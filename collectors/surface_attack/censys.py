"""
Censys Collector — Recherche d'hosts et certificats.

Censys scanne Internet pour indexer les hosts, certificats, et services.
API v2: https://search.censys.io/api/
Clé API requise (CENSYS_API_ID et CENSYS_API_SECRET dans .env)
"""

import aiohttp
import os
from typing import List
from collectors.base import BaseCollector
from core.models import SearchResult
import logging

logger = logging.getLogger("dorker.censys")

class CensysCollector(BaseCollector):
    """
    Collecteur Censys.

    Recherche des hosts et certificats.
    Nécessite CENSYS_API_ID et CENSYS_API_SECRET.
    """

    BASE_URL = "https://search.censys.io/api/v2"

    async def collect(self, query: str, session: aiohttp.ClientSession) -> List[SearchResult]:
        """Recherche dans Censys."""
        api_id = os.getenv("CENSYS_API_ID")
        api_secret = os.getenv("CENSYS_API_SECRET")

        if not api_id or not api_secret:
            logger.info("Censys désactivé (clés API manquantes)")
            return []

        # Déterminer si c'est une recherche de host ou de certificat
        import re
        if re.match(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', query):
            index = "hosts"
        else:
            index = "hosts"  # Par défaut hosts

        url = f"{self.BASE_URL}/{index}/search"
        params = {"q": query, "per_page": 20}

        try:
            async with session.get(url, params=params, auth=aiohttp.BasicAuth(api_id, api_secret), timeout=15) as response:
                if response.status == 401:
                    logger.error("Clés API Censys invalides")
                    return []

                if response.status == 429:
                    logger.warning("Quota Censys dépassé")
                    return []

                if response.status != 200:
                    logger.warning(f"Censys returned {response.status}")
                    return []

                data = await response.json()
                results = []

                for hit in data.get("result", {}).get("hits", [])[:20]:
                    ip = hit.get("ip", "")
                    services = hit.get("services", [])

                    service_info = []
                    for svc in services[:5]:
                        service_info.append(f"{svc.get('service_name', 'unknown')}/{svc.get('port', 'N/A')}")

                    location = hit.get("location", {})
                    country = location.get("country", "N/A")
                    city = location.get("city", "N/A")

                    snippet = f"IP: {ip} | Services: {', '.join(service_info)} | Location: {city}, {country}"

                    results.append(SearchResult(
                        title=f"Censys: {ip}",
                        url=f"https://search.censys.io/hosts/{ip}",
                        snippet=snippet,
                        source="Censys"
                    ))

                return results

        except Exception as e:
            logger.error(f"Erreur Censys: {e}")
            return []
