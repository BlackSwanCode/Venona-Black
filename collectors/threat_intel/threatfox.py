"""
ThreatFox Collector — Recherche d'IOCs communautaires via l'API abuse.ch.

ThreatFox (projet abuse.ch / Spamhaus) agrège des indicateurs de compromission
(IPs, domaines, URLs, hashes) vérifiés et associés à des familles de malware
identifiées, avec un niveau de confiance et un contexte (tags, reporter).

API: https://threatfox-api.abuse.ch/api/v1/
Depuis 2025, un Auth-Key abuse.ch est requis (gratuit via https://auth.abuse.ch/).
La même clé peut être réutilisée pour URLhaus/MalwareBazaar (compte unique).
"""

import os
import re
import aiohttp
from typing import List
from collectors.base import BaseCollector
from core.models import SearchResult
import logging

logger = logging.getLogger("dorker.threatfox")


class ThreatFoxCollector(BaseCollector):
    """
    Collecteur ThreatFox (abuse.ch).

    Recherche des IOCs par valeur (IP, domaine, URL, hash) ou par mot-clé
    associé à une famille de malware.
    """

    API_URL = "https://threatfox-api.abuse.ch/api/v1/"

    async def collect(self, query: str, session: aiohttp.ClientSession) -> List[SearchResult]:
        api_key = os.getenv("THREATFOX_API_KEY")
        if not api_key:
            logger.info("ThreatFox désactivé (clé API manquante)")
            return []

        query = query.strip()
        headers = {"Auth-Key": api_key}

        # Recherche par hash -> endpoint search_hash, sinon search_ioc (IP/domaine/URL/mot-clé)
        is_hash = bool(
            re.match(r'^[a-fA-F0-9]{32}$', query)
            or re.match(r'^[a-fA-F0-9]{40}$', query)
            or re.match(r'^[a-fA-F0-9]{64}$', query)
        )
        payload = {
            "query": "search_hash" if is_hash else "search_ioc",
            "search_term" if not is_hash else "hash": query
        }

        try:
            async with session.post(self.API_URL, headers=headers, json=payload, timeout=15) as response:
                if response.status == 401:
                    logger.error("Auth-Key ThreatFox invalide")
                    return []

                if response.status != 200:
                    logger.warning(f"ThreatFox returned {response.status}")
                    return []

                data = await response.json()

                if data.get("query_status") != "ok":
                    logger.debug(f"ThreatFox: {data.get('query_status')} pour '{query}'")
                    return []

                results = []
                for entry in data.get("data", [])[:30]:
                    ioc_value = entry.get("ioc", "N/A")
                    malware = entry.get("malware_printable", entry.get("malware", "Unknown"))
                    tags = ", ".join(entry.get("tags") or [])

                    results.append(SearchResult(
                        title=f"ThreatFox: {malware} — {entry.get('ioc_type', 'IOC')}",
                        url=f"https://threatfox.abuse.ch/ioc/{entry.get('id', '')}/",
                        snippet=(
                            f"IOC: {ioc_value} | Type: {entry.get('threat_type_desc', 'N/A')} | "
                            f"Confiance: {entry.get('confidence_level', 'N/A')}% | "
                            f"Vu: {entry.get('first_seen', 'N/A')} | Tags: {tags or 'N/A'} | "
                            f"Reporter: {entry.get('reporter', 'N/A')}"
                        ),
                        source="ThreatFox"
                    ))

                return results

        except aiohttp.ClientError as e:
            logger.error(f"Erreur réseau ThreatFox: {e}")
            return []
        except Exception as e:
            logger.error(f"Erreur ThreatFox: {e}")
            return []
