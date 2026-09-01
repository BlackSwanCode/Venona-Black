"""
Mojeek Collector — Requêtes via l'API officielle Mojeek Search.

Mojeek possède son propre crawler et son propre index (contrairement à
beaucoup de métamoteurs qui republient Bing/Google), ce qui en fait une
source utile pour croiser des résultats de dorking indépendants et
retrouver du contenu absent des index dominants.

API: https://www.mojeek.com/support/api/search/
Clé API requise (MOJEEK_API_KEY) — tier gratuit disponible sur demande.
"""

import os
import aiohttp
from typing import List
from collectors.base import BaseCollector
from core.models import SearchResult
import logging

logger = logging.getLogger("dorker.mojeek")


class MojeekCollector(BaseCollector):
    """
    Collecteur Mojeek Search API.

    Index web indépendant. Authentification via le paramètre api_key.
    """

    API_URL = "https://api.mojeek.com/search"

    async def collect(self, query: str, session: aiohttp.ClientSession) -> List[SearchResult]:
        api_key = os.getenv("MOJEEK_API_KEY")
        if not api_key:
            logger.info("Mojeek désactivé (clé API manquante)")
            return []

        params = {
            "q": query,
            "api_key": api_key,
            "fmt": "json",
            "t": 20,
        }

        try:
            async with session.get(self.API_URL, params=params, timeout=15) as response:
                if response.status == 401 or response.status == 403:
                    logger.error("Clé API Mojeek invalide")
                    return []

                if response.status != 200:
                    logger.warning(f"Mojeek returned {response.status}")
                    return []

                data = await response.json()
                results = []

                for item in data.get("response", {}).get("results", []):
                    results.append(SearchResult(
                        title=item.get("title", "No Title"),
                        url=item.get("url", ""),
                        snippet=item.get("desc", ""),
                        source="Mojeek"
                    ))

                return results

        except aiohttp.ClientError as e:
            logger.error(f"Erreur réseau Mojeek: {e}")
            return []
        except Exception as e:
            logger.error(f"Erreur Mojeek: {e}")
            return []
