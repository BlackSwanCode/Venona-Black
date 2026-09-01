"""
URLScan.io Collector — Analyse et recherche d'URLs suspectes.

URLScan permet de rechercher des scans existants ou de soumettre
une URL pour analyse. Ici on utilise la recherche publique.

API: https://urlscan.io/api/v1/
Clé API optionnelle (recommandée pour plus de résultats)
"""

import aiohttp
import os
from typing import List
from collectors.base import BaseCollector
from core.models import SearchResult
import logging

logger = logging.getLogger("dorker.urlscan")

class URLScanCollector(BaseCollector):
    """
    Collecteur URLScan.io.

    Recherche des scans existants pour un domaine, IP, ou hash de page.
    """

    BASE_URL = "https://urlscan.io/api/v1"

    async def collect(self, query: str, session: aiohttp.ClientSession) -> List[SearchResult]:
        """Recherche des scans URLScan."""
        api_key = os.getenv("URLSCAN_API_KEY")

        headers = {}
        if api_key:
            headers["API-Key"] = api_key

        # Nettoyer la requête
        query = query.strip()

        # Si c'est une URL complète, extraire le domaine
        if query.startswith("http://") or query.startswith("https://"):
            from urllib.parse import urlparse
            domain = urlparse(query).netloc
            query = domain

        # Recherche par domaine ou IP
        search_url = f"{self.BASE_URL}/search/"
        params = {"q": f"domain:{query}", "size": 20}

        try:
            async with session.get(search_url, headers=headers, params=params, timeout=15) as response:
                if response.status == 429:
                    logger.warning("Quota URLScan dépassé")
                    return []

                if response.status != 200:
                    logger.warning(f"URLScan returned {response.status}")
                    return []

                data = await response.json()
                results = []

                scans = data.get("results", [])
                for scan in scans[:20]:
                    page = scan.get("page", {})
                    task = scan.get("task", {})

                    url = page.get("url", "")
                    domain = page.get("domain", "")
                    ip = page.get("ip", "")
                    country = page.get("country", "")

                    title = task.get("domURL", "").split("/")[-1] if task.get("domURL") else domain

                    snippet_parts = [
                        f"URL: {url}",
                        f"IP: {ip}",
                        f"Country: {country}",
                        f"Time: {task.get('time', 'N/A')}",
                    ]

                    if scan.get("verdicts", {}).get("overall", {}).get("malicious"):
                        snippet_parts.append("VERDICT: MALICIOUS")

                    results.append(SearchResult(
                        title=f"URLScan: {domain}",
                        url=f"https://urlscan.io/result/{scan.get('_id', '')}/",
                        snippet=" | ".join(snippet_parts),
                        source="URLScan.io"
                    ))

                return results

        except Exception as e:
            logger.error(f"Erreur URLScan: {e}")
            return []
