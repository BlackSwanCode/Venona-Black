"""
collectors/search_engines/dork_collector.py
Collecteur automatique de Dorks, vérificateur de fuites de secrets,
parser S3 Bucket XML et mapper MITRE ATT&CK.

NE HÉRITE PAS de BaseCollector : son interface (fetch(domain) -> liste de
findings enrichis MITRE) est volontairement différente de celle d'un
collecteur de recherche classique (collect(query, session) ->
List[SearchResult]), car il retourne des données bien plus riches (secrets
détectés, contenu de buckets S3, mapping MITRE ATT&CK) qui ne rentreraient
pas dans un simple SearchResult. Auparavant, la classe héritait quand même
de BaseCollector sans respecter son contrat (pas de collect(), __init__
incompatible), ce qui la rendait impossible à instancier — d'où son statut
de collecteur "orphelin" (absent de collectors_registry.json et inutilisable
si on essayait de l'appeler).

Utilisation (voir ui/watchlist_monitor.py, scan de dorks/secrets à la
demande) :

    collector_mgr = CollectorManager()
    dc = DorkSecretCollector(case_id="MON_CAS")
    async with aiohttp.ClientSession() as session:
        findings = await dc.fetch("exemple.com", collector_manager=collector_mgr, session=session)

Si collector_manager/session ne sont pas fournis, fetch() se rabat sur une
recherche vide (aucune URL candidate) plutôt que de planter.
"""

import asyncio
import os
import random
import re
import xml.etree.ElementTree as ET
import httpx
from typing import List, Dict, Any, Optional
from core.dork_templates import generate_dorks
from core.mitre_mapper import MitreMapper
from core.ioc_extractor import IOCExtractor
from utils.logger import get_investigation_logger

SECRET_REGEXES = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Generic API Key": r"(?i)(api[_-]?key|secret[_-]?key|token)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,64})['\"]",
    "Private Key": r"-----BEGIN (RSA|EC|PGP|OPENSSH) PRIVATE KEY-----",
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    "Database Connection String": r"(mongodb|postgres|mysql):\/\/[^\s<\"']+",
    "Env File Indicator": r"(?m)^(DB_HOST|DB_PASSWORD|SECRET_KEY|REDIS_URL)="
}

SENSITIVE_FILE_PATTERNS = re.compile(
    r"(\.env|\.pem|\.key|\.crt|\.pfx|\.p12|\.sql|\.db|\.bak|\.dump|\.log|"
    r"config\.json|credentials|shadow|passwd|backup|dump)", re.IGNORECASE
)


def extract_iocs(text: str) -> Dict[str, List[str]]:
    """
    Regroupe les IOC détectés dans `text` par type, ex. {"EMAIL": [...], "IPV4": [...]}.
    Remplace l'ancien fallback (import qui échouait silencieusement et
    retournait toujours {}) par un branchement réel sur core.ioc_extractor.
    """
    try:
        iocs, _stats = IOCExtractor.extract_from_text(text)
    except Exception:
        return {}

    grouped: Dict[str, List[str]] = {}
    for ioc in iocs:
        grouped.setdefault(ioc.type, []).append(ioc.value)
    return grouped


class DorkSecretCollector:
    def __init__(self, case_id: str = "GENERAL", search_engine_ids: Optional[List[str]] = None):
        self.log = get_investigation_logger(case_id)
        self.mitre_mapper = MitreMapper(case_id=case_id)
        # IDs de collectors_registry.json utilisés pour découvrir des URLs
        # candidates à partir des dorks générés.
        self.search_engine_ids = search_engine_ids or ["duckduckgo", "brave"]
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"

    async def fetch(self, domain: str, collector_manager=None, session=None) -> List[Dict[str, Any]]:
        self.log.info(f"[DorkCollector] Démarrage de la recherche de secrets pour : {domain}")
        dorks = generate_dorks(domain)
        discovered_urls: List[Dict[str, str]] = []

        # Pause aléatoire entre deux dorks pour limiter le risque de
        # déclencher le "soft rate limit" (statut 202) de DuckDuckGo, qui
        # survient facilement quand plusieurs requêtes partent en rafale.
        delay_min = float(os.getenv("DDG_INTER_QUERY_DELAY_MIN", "2"))
        delay_max = float(os.getenv("DDG_INTER_QUERY_DELAY_MAX", "5"))

        for idx, dork_info in enumerate(dorks):
            query = dork_info["query"]
            self.log.debug(f"[DorkCollector] Exécution du dork ({dork_info['category']}): {query}")

            try:
                urls = await self._discover_urls(query, collector_manager, session)
                for url in urls:
                    discovered_urls.append({
                        "url": url,
                        "category": dork_info["category"],
                        "dork": query
                    })
            except Exception as e:
                self.log.error(f"[DorkCollector] Erreur lors du dork '{query}': {str(e)}")

            if idx < len(dorks) - 1:
                delay = random.uniform(delay_min, delay_max)
                self.log.debug(f"[DorkCollector] Pause de {delay:.1f}s avant le prochain dork (anti rate-limit DDG).")
                await asyncio.sleep(delay)

        self.log.info(f"[DorkCollector] {len(discovered_urls)} URLs candidates trouvées. Début du scan de vérification.")
        verified_results = await self._verify_and_scan_urls(discovered_urls)

        self.log.info("[DorkCollector] Enrichissement des découvertes avec le référentiel MITRE ATT&CK.")
        return self.mitre_mapper.map_findings(verified_results)

    async def _discover_urls(self, query: str, collector_manager, session) -> List[str]:
        """
        Découvre les URLs candidates pour un dork donné en réutilisant les
        collecteurs de recherche déjà enregistrés dans CollectorManager
        (au lieu de dépendre d'un `search_engine_collector.search()` qui
        n'était implémenté nulle part ailleurs dans le projet).
        """
        if collector_manager is None or session is None:
            return await self._fallback_search(query)

        urls: List[str] = []
        for engine_id in self.search_engine_ids:
            try:
                results = await collector_manager.run_single_collector(engine_id, query, session)
                urls.extend([r.url for r in results if getattr(r, "url", None)])
            except Exception as e:
                self.log.debug(f"[DorkCollector] Moteur '{engine_id}' indisponible pour ce dork : {e}")

        return urls

    async def _verify_and_scan_urls(self, url_entries: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        results = []
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True, headers={"User-Agent": self.user_agent}) as client:
            tasks = [self._analyze_single_url(client, entry) for entry in url_entries]
            analyses = await asyncio.gather(*tasks, return_exceptions=True)

            for res in analyses:
                if isinstance(res, dict) and res.get("exposed"):
                    results.append(res)

        return results

    async def _analyze_single_url(self, client: httpx.AsyncClient, entry: Dict[str, str]) -> Dict[str, Any]:
        url = entry["url"]
        self.log.debug(f"[DorkCollector] Analyse HTTP de l'URL : {url}")

        result_payload = {
            "url": url,
            "category": entry["category"],
            "dork_origin": entry["dork"],
            "exposed": False,
            "status_code": None,
            "is_s3_bucket": False,
            "s3_objects_total": 0,
            "s3_sensitive_files": [],
            "secrets_found": [],
            "extracted_iocs": {},
            "content_snippet": ""
        }

        try:
            response = await client.get(url)
            result_payload["status_code"] = response.status_code

            if response.status_code == 200:
                content = response.text
                result_payload["exposed"] = True
                result_payload["content_snippet"] = content[:300]

                if "<ListBucketResult" in content:
                    self.log.warning(f"[DorkCollector] Bucket S3 ouvert détecté sur : {url}")
                    s3_data = self._parse_s3_bucket_xml(content, url)
                    result_payload["is_s3_bucket"] = True
                    result_payload["s3_objects_total"] = s3_data["total_objects"]
                    result_payload["s3_sensitive_files"] = s3_data["sensitive_files"]

                for secret_type, regex in SECRET_REGEXES.items():
                    matches = re.findall(regex, content)
                    if matches:
                        self.log.warning(f"[DorkCollector] SECRETS DÉTECTÉS ({secret_type}) sur {url}")
                        result_payload["secrets_found"].append({
                            "type": secret_type,
                            "count": len(matches)
                        })

                result_payload["extracted_iocs"] = extract_iocs(content)

        except httpx.RequestError as exc:
            self.log.debug(f"[DorkCollector] Échec d'accès à {url} : {str(exc)}")

        return result_payload

    def _parse_s3_bucket_xml(self, xml_content: str, base_url: str) -> Dict[str, Any]:
        sensitive_files = []
        total_objects = 0

        try:
            clean_xml = re.sub(r'xmlns="[^"]+"', '', xml_content, count=1)
            root = ET.fromstring(clean_xml)

            for contents_node in root.findall("Contents"):
                total_objects += 1
                key_node = contents_node.find("Key")
                size_node = contents_node.find("Size")

                if key_node is not None and key_node.text:
                    file_key = key_node.text
                    file_size = int(size_node.text) if (size_node is not None and size_node.text) else 0

                    if SENSITIVE_FILE_PATTERNS.search(file_key):
                        file_url = base_url.rstrip("/") + "/" + file_key.lstrip("/")
                        sensitive_files.append({
                            "key": file_key,
                            "size_bytes": file_size,
                            "direct_url": file_url
                        })

            self.log.info(f"[DorkCollector] Bucket S3 parsé : {total_objects} objets au total, {len(sensitive_files)} fichiers critiques.")

        except ET.ParseError as e:
            self.log.error(f"[DorkCollector] Erreur parsing XML S3 pour {base_url}: {str(e)}")

        return {
            "total_objects": total_objects,
            "sensitive_files": sensitive_files
        }

    async def _fallback_search(self, query: str) -> List[str]:
        """Utilisé uniquement si aucun CollectorManager/session n'est fourni."""
        await asyncio.sleep(0.1)
        return []
