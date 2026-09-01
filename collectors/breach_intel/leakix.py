"""
LeakIX Collector — Recherche de fuites et de services exposés via l'API LeakIX.

LeakIX indexe en continu des services mal configurés et des fuites de données
exposées publiquement (bases ouvertes, buckets, panels d'admin, dumps
".git"/".env", etc.), avec la syntaxe de requête de type "+plugin:X +country:Y".

API: https://leakix.net/search (scope=leak pour les fuites, scope=service par défaut)
Doc: https://docs.leakix.net/docs/api/
Clé API requise (LEAKIX_API_KEY) — augmente fortement la profondeur des résultats.
"""

import os
import aiohttp
from typing import List
from collectors.base import BaseCollector
from core.models import SearchResult
import logging

logger = logging.getLogger("dorker.leakix")


class LeakIXCollector(BaseCollector):
    """
    Collecteur LeakIX.

    Interroge l'index LeakIX sur le scope "leak" (fuites de données), qui est
    le plus pertinent pour de la breach intelligence. La requête brute de
    l'utilisateur est utilisée telle quelle, ce qui permet d'exploiter la
    syntaxe avancée LeakIX (+plugin:, +country:, +ip:, etc.) si l'utilisateur
    la fournit, ou une simple recherche par mot-clé/domaine sinon.
    """

    SEARCH_URL = "https://leakix.net/search"

    async def collect(self, query: str, session: aiohttp.ClientSession) -> List[SearchResult]:
        api_key = os.getenv("LEAKIX_API_KEY")
        if not api_key:
            logger.info("LeakIX désactivé (clé API manquante)")
            return []

        headers = {
            "api-key": api_key,
            "Accept": "application/json",
        }
        params = {
            "q": query,
            "scope": "leak",
        }

        try:
            async with session.get(self.SEARCH_URL, headers=headers, params=params, timeout=15) as response:
                if response.status == 401:
                    logger.error("Clé API LeakIX invalide")
                    return []

                if response.status == 404:
                    # LeakIX renvoie 404 quand aucun résultat ne correspond
                    return []

                if response.status == 429:
                    logger.warning("Quota LeakIX dépassé (rate limit)")
                    return []

                if response.status != 200:
                    logger.warning(f"LeakIX returned {response.status}")
                    return []

                data = await response.json()
                if not isinstance(data, list):
                    return []

                results = []
                for event in data[:30]:
                    leak = event.get("leak") or {}
                    host = event.get("host", event.get("ip", "N/A"))
                    plugin = event.get("event_source", event.get("plugin", "N/A"))
                    geoip = event.get("geoip") or {}
                    dataset = leak.get("dataset") or {}

                    results.append(SearchResult(
                        title=f"LeakIX: {leak.get('type', plugin)} — {host}",
                        url=f"https://leakix.net/host/{event.get('ip', host)}",
                        snippet=(
                            f"Host: {host} | Port: {event.get('port', 'N/A')} | "
                            f"Sévérité: {leak.get('severity', 'N/A')} | "
                            f"Dataset: {dataset.get('rows', 'N/A')} lignes / {dataset.get('size', 'N/A')} | "
                            f"Pays: {geoip.get('country_name', 'N/A')} | "
                            f"Détecté: {event.get('time', 'N/A')}"
                        ),
                        source="LeakIX"
                    ))

                return results

        except aiohttp.ClientError as e:
            logger.error(f"Erreur réseau LeakIX: {e}")
            return []
        except Exception as e:
            logger.error(f"Erreur LeakIX: {e}")
            return []
