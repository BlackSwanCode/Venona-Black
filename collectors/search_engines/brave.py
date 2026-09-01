"""
Brave Search Collector — Requêtes via l'API officielle Brave Search.

Brave dispose de son propre index web (indépendant de Bing/Google), ce qui
en fait une source de dorking précieuse pour diversifier les résultats et
limiter les biais de ranking d'un moteur unique.

API: https://api.search.brave.com/res/v1/web/search
Clé API requise (BRAVE_API_KEY) — un tier gratuit existe (2000 req/mois).
Doc: https://api-dashboard.search.brave.com/app/documentation
"""

import os
import aiohttp
from typing import List
from collectors.base import BaseCollector
from core.models import SearchResult
import logging

logger = logging.getLogger("dorker.brave")


class BraveSearchCollector(BaseCollector):
    """
    Collecteur Brave Search API.

    Utilise l'index web indépendant de Brave. Authentification via le
    header X-Subscription-Token.
    """

    API_URL = "https://api.search.brave.com/res/v1/web/search"

    async def collect(self, query: str, session: aiohttp.ClientSession) -> List[SearchResult]:
        api_key = os.getenv("BRAVE_API_KEY")
        if not api_key:
            logger.info("Brave Search désactivé (clé API manquante)")
            return []

        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
            "X-Subscription-Token": api_key,
        }
        params = {
            "q": query,
            "count": 20,
            "safesearch": "off",
        }

        try:
            async with session.get(self.API_URL, headers=headers, params=params, timeout=15) as response:
                if response.status == 401:
                    logger.error("Clé API Brave invalide")
                    return []

                if response.status == 429:
                    logger.warning("Quota Brave Search dépassé (rate limit)")
                    return []

                if response.status != 200:
                    logger.warning(f"Brave Search returned {response.status}")
                    return []

                data = await response.json()
                results = []

                web_results = data.get("web", {}).get("results", [])
                for item in web_results:
                    results.append(SearchResult(
                        title=item.get("title", "No Title"),
                        url=item.get("url", ""),
                        snippet=item.get("description", ""),
                        source="Brave Search"
                    ))

                return results

        except aiohttp.ClientError as e:
            logger.error(f"Erreur réseau Brave Search: {e}")
            return []
        except Exception as e:
            logger.error(f"Erreur Brave Search: {e}")
            return []
