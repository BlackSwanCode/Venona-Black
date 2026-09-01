"""
collectors/search_engines/dork_collector.py
Collecteur automatique de Dorks, vérificateur de fuites de secrets, 
parser S3 Bucket XML et mapper MITRE ATT&CK.
"""

import asyncio
import re
import xml.etree.ElementTree as ET
import httpx
from typing import List, Dict, Any
from collectors.base import BaseCollector
from core.dork_templates import generate_dorks
from core.mitre_mapper import MitreMapper
from utils.logger import get_investigation_logger

try:
    from core.ioc_extractor import extract_iocs
except ImportError:
    def extract_iocs(text): return {}

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

class DorkSecretCollector(BaseCollector):
    def __init__(self, search_engine_collector=None, case_id: str = "GENERAL"):
        super().__init__()
        self.log = get_investigation_logger(case_id)
        self.search_engine = search_engine_collector
        self.mitre_mapper = MitreMapper(case_id=case_id)
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"

    async def fetch(self, domain: str) -> List[Dict[str, Any]]:
        self.log.info(f"[DorkCollector] Démarrage de la recherche de secrets pour : {domain}")
        dorks = generate_dorks(domain)
        discovered_urls: List[Dict[str, str]] = []

        for dork_info in dorks:
            query = dork_info["query"]
            self.log.debug(f"[DorkCollector] Exécution du dork ({dork_info['category']}): {query}")
            
            try:
                if self.search_engine:
                    results = await self.search_engine.search(query)
                else:
                    results = await self._fallback_search(query)
                
                for url in results:
                    discovered_urls.append({
                        "url": url,
                        "category": dork_info["category"],
                        "dork": query
                    })
            except Exception as e:
                self.log.error(f"[DorkCollector] Erreur lors du dork '{query}': {str(e)}")

        self.log.info(f"[DorkCollector] {len(discovered_urls)} URLs candidates trouvées. Début du scan de vérification.")
        verified_results = await self._verify_and_scan_urls(discovered_urls)
        
        self.log.info("[DorkCollector] Enrichissement des découvertes avec le référentiel MITRE ATT&CK.")
        return self.mitre_mapper.map_findings(verified_results)

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
        await asyncio.sleep(0.1)
        return []
