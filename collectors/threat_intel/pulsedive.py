"""
Pulsedive Collector — Réputation et contexte de menace pour un indicateur.

Pulsedive agrège de nombreux flux de threat intelligence publics et calcule
un score de risque (none/low/medium/high/critical) pour un indicateur
(IP, domaine, URL ou hash), avec les menaces/flux associés.

API: https://pulsedive.com/api/
Clé API requise pour un quota confortable (PULSEDIVE_API_KEY dans .env) —
un tier gratuit existe mais avec un rate limit très bas sans clé.
Doc: https://pulsedive.com/api/
"""

import os
import aiohttp
from typing import List
from collectors.base import BaseCollector
from core.models import SearchResult
import logging

logger = logging.getLogger("dorker.pulsedive")


class PulsediveCollector(BaseCollector):
    """
    Collecteur Pulsedive.

    Recherche un indicateur (IP, domaine, URL, hash) via l'endpoint
    `info.php` et restitue son score de risque ainsi que les menaces/flux
    associés.

    Nécessite une clé API (PULSEDIVE_API_KEY dans .env).
    """

    BASE_URL = "https://pulsedive.com/api"

    async def collect(self, query: str, session: aiohttp.ClientSession) -> List[SearchResult]:
        api_key = os.getenv("PULSEDIVE_API_KEY")
        if not api_key:
            logger.info("Pulsedive désactivé (clé API manquante)")
            return []

        indicator = query.strip()
        if not indicator:
            return []

        url = f"{self.BASE_URL}/info.php"
        params = {"indicator": indicator, "key": api_key}

        try:
            async with session.get(url, params=params, timeout=15) as response:
                if response.status == 429:
                    logger.warning("Quota Pulsedive dépassé")
                    return []

                if response.status != 200:
                    logger.warning(f"Pulsedive a retourné {response.status}")
                    return []

                data = await response.json()

                # Pulsedive renvoie un objet contenant "error" (ex: indicateur
                # inconnu ou format invalide) plutôt qu'un statut HTTP non-200.
                if isinstance(data, dict) and data.get("error"):
                    logger.debug(f"Pulsedive: {data.get('error')} pour '{indicator}'")
                    return []

                risk = data.get("risk", "unknown")
                ind_type = data.get("type", "N/A")
                iid = data.get("iid")

                threats = [t.get("name") for t in data.get("threats", []) if t.get("name")]
                feeds = [f.get("name") for f in data.get("feeds", []) if f.get("name")]
                riskfactors = [
                    rf.get("description") if isinstance(rf, dict) else str(rf)
                    for rf in data.get("riskfactors", [])
                ]

                snippet_parts = [f"Type: {ind_type}", f"Risque: {risk}"]
                if threats:
                    snippet_parts.append(f"Menaces: {', '.join(threats[:5])}")
                if feeds:
                    snippet_parts.append(f"Flux: {', '.join(feeds[:5])}")
                if riskfactors:
                    snippet_parts.append(f"Facteurs de risque: {', '.join(riskfactors[:3])}")

                detail_url = (
                    f"https://pulsedive.com/indicator/?iid={iid}"
                    if iid else "https://pulsedive.com/"
                )

                return [SearchResult(
                    title=f"Pulsedive: {indicator} — Risque {risk.upper() if isinstance(risk, str) else risk}",
                    url=detail_url,
                    snippet=" | ".join(snippet_parts),
                    source="Pulsedive",
                )]

        except Exception as e:
            logger.error(f"Erreur Pulsedive: {e}")
            return []
