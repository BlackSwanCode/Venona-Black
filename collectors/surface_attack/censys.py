"""
Censys Collector — Recherche d'hosts/certificats via la Censys Platform API (v3).

Censys a déprécié l'authentification "API ID + Secret" (Basic Auth) sur
search.censys.io/api/v2 au profit d'un Personal Access Token (PAT) sur la
nouvelle Platform API :

    Base URL : https://api.platform.censys.io/v3/
    Auth     : Authorization: Bearer <PAT>
    Org ID   : header X-Organization-ID (ou paramètre ?organization_id=...),
               requis pour la plupart des comptes payants, facultatif en Free.
    Endpoint : POST /v3/global/search/query   body: {"query": "...", "page_size": N}

Variables d'environnement :
    CENSYS_PAT          (obligatoire) — Personal Access Token (platform.censys.io
                         > icône utilisateur > API Access).
    CENSYS_ORG_ID        (optionnel)  — nécessaire pour la plupart des comptes payants.
    DEBUG_API_CALLS=1    (optionnel)  — journalise chaque requête/réponse
                         (voir utils/api_debug.py) pour diagnostiquer un 401/403/429.

⚠️ Le schéma de réponse exact de /v3/global/search/query est peu documenté
publiquement. Le parsing ci-dessous gère plusieurs formes plausibles ("hit"
à plat ou imbriqué sous "resource") ; en cas de doute, activez le mode debug
pour voir la réponse brute et ajuster les chemins de champs si besoin.
"""

import os
import re
import json
import aiohttp
from typing import List
from collectors.base import BaseCollector
from core.models import SearchResult
from utils.api_debug import log_api_call
import logging

logger = logging.getLogger("dorker.censys")

IPV4_RE = re.compile(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
)


class CensysCollector(BaseCollector):
    """
    Collecteur Censys (Platform API v3).

    Nécessite CENSYS_PAT (Personal Access Token). CENSYS_ORG_ID est optionnel
    mais souvent requis en dehors du tier Free.
    """

    BASE_URL = "https://api.platform.censys.io/v3"

    async def collect(self, query: str, session: aiohttp.ClientSession) -> List[SearchResult]:
        """Recherche dans Censys via la Platform API."""
        pat = os.getenv("CENSYS_PAT")
        if not pat:
            logger.info("Censys désactivé (CENSYS_PAT manquant — voir .env.example)")
            return []

        org_id = os.getenv("CENSYS_ORG_ID")

        # CenQL : si la requête est une IP nue, on la précise en "host.ip:" pour
        # un résultat plus pertinent. Sinon on transmet la requête telle quelle.
        cenql_query = f'host.ip: "{query}"' if IPV4_RE.match(query.strip()) else query

        url = f"{self.BASE_URL}/global/search/query"
        headers = {
            "Authorization": f"Bearer {pat}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if org_id:
            headers["X-Organization-ID"] = org_id

        payload = {"query": cenql_query, "page_size": 20}

        try:
            async with session.post(url, headers=headers, json=payload, timeout=15) as response:
                status = response.status
                body_text = None

                if status != 200:
                    # On ne lit le corps que dans le cas d'erreur, pour le
                    # mode debug (évite de gaspiller de la bande passante
                    # inutilement quand tout va bien).
                    try:
                        body_text = await response.text()
                    except Exception:
                        body_text = None

                log_api_call(
                    "Censys", "POST", url,
                    headers=headers, payload=payload,
                    status=status, response_body=body_text,
                )

                if status == 401:
                    logger.error("CENSYS_PAT invalide ou expiré")
                    return []

                if status == 403:
                    logger.error(
                        "Censys a renvoyé 403 (Forbidden) — vérifiez le rôle 'API Access' "
                        "du compte et, si le compte est payant, que CENSYS_ORG_ID est bien "
                        "défini. Activez DEBUG_API_CALLS=1 pour voir la réponse brute."
                    )
                    return []

                if status == 429:
                    logger.warning("Quota/crédits Censys dépassés")
                    return []

                if status != 200:
                    logger.warning(f"Censys a renvoyé {status}")
                    return []

                data = await response.json()
                hits = (
                    data.get("result", {}).get("hits")
                    or data.get("hits")
                    or []
                )

                if not hits:
                    logger.debug(f"Censys: aucune hit exploitable. Réponse brute: {json.dumps(data)[:500]}")
                    return []

                results = []
                for raw_hit in hits[:20]:
                    hit = raw_hit.get("resource", raw_hit) if isinstance(raw_hit, dict) else {}

                    ip = hit.get("ip", "")
                    services = hit.get("services") or raw_hit.get("matched_services") or []

                    service_info = []
                    for svc in services[:5]:
                        name = svc.get("service_name") or svc.get("extended_service_name") or "unknown"
                        port = svc.get("port", "N/A")
                        service_info.append(f"{name}/{port}")

                    location = hit.get("location", {}) or {}
                    country = location.get("country", "N/A")
                    city = location.get("city", "N/A")

                    if not ip:
                        continue

                    snippet = f"IP: {ip} | Services: {', '.join(service_info) or 'N/A'} | Location: {city}, {country}"

                    results.append(SearchResult(
                        title=f"Censys: {ip}",
                        url=f"https://platform.censys.io/hosts/{ip}",
                        snippet=snippet,
                        source="Censys"
                    ))

                return results

        except Exception as e:
            log_api_call("Censys", "POST", url, headers=headers, payload=payload, error=str(e))
            logger.error(f"Erreur Censys: {e}")
            return []
