"""
GreyNoise Collector — Vérification des IPs de scan/bruteforce.

GreyNoise identifie les IPs qui scannent Internet (bruteforce, scanners,
bots connus) et distingue les menaces des bruits de fond.

API: https://api.greynoise.io/v3/
Clé API requise pour les requêtes avancées (gratuit tier disponible)
"""

import aiohttp
import os
from typing import List
from collectors.base import BaseCollector
from core.models import SearchResult
import logging

logger = logging.getLogger("dorker.greynoise")

class GreyNoiseCollector(BaseCollector):
    """
    Collecteur GreyNoise.

    Recherche des informations sur une IP ou un CIDR.
    Nécessite une clé API (GRY_API_KEY dans .env).
    """

    BASE_URL = "https://api.greynoise.io/v3/community"

    async def collect(self, query: str, session: aiohttp.ClientSession) -> List[SearchResult]:
        """Recherche une IP dans GreyNoise."""
        api_key = os.getenv("GRY_API_KEY")
        if not api_key:
            logger.info("GreyNoise désactivé (clé API manquante)")
            return []

        # Extraire l'IP de la requête
        import re
        ip_match = re.search(r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)', query)
        if not ip_match:
            logger.debug(f"GreyNoise: aucune IP trouvée dans '{query}'")
            return []

        ip = ip_match.group(0)

        # Vérifier les IPs privées
        if self._is_private_ip(ip):
            return []

        url = f"{self.BASE_URL}/{ip}"
        headers = {"key": api_key}

        try:
            async with session.get(url, headers=headers, timeout=10) as response:
                if response.status == 404:
                    # IP non vue par GreyNoise
                    return [SearchResult(
                        title=f"GreyNoise: {ip} — Non observée",
                        url=f"https://viz.greynoise.io/ip/{ip}",
                        snippet="Cette IP n'a pas été observée dans le trafic de scan/bruteforce par GreyNoise.",
                        source="GreyNoise"
                    )]

                if response.status == 429:
                    logger.warning("Quota GreyNoise dépassé")
                    return []

                if response.status != 200:
                    logger.warning(f"GreyNoise returned {response.status}")
                    return []

                data = await response.json()
                results = []

                noise = data.get("noise", False)
                riot = data.get("riot", False)
                classification = data.get("classification", "unknown")
                name = data.get("name", "Unknown")

                snippet_parts = [
                    f"Classification: {classification}",
                    f"Noise: {'Oui' if noise else 'Non'}",
                    f"RIOT: {'Oui' if riot else 'Non'}",
                    f"Name: {name}",
                ]

                if data.get("metadata"):
                    meta = data["metadata"]
                    snippet_parts.append(f"OS: {meta.get('os', 'N/A')}")
                    snippet_parts.append(f"Org: {meta.get('organization', 'N/A')}")
                    snippet_parts.append(f"Country: {meta.get('country', 'N/A')}")

                results.append(SearchResult(
                    title=f"GreyNoise: {ip} — {classification.upper()}",
                    url=f"https://viz.greynoise.io/ip/{ip}",
                    snippet=" | ".join(snippet_parts),
                    source="GreyNoise"
                ))

                return results

        except Exception as e:
            logger.error(f"Erreur GreyNoise: {e}")
            return []

    def _is_private_ip(self, ip: str) -> bool:
        """Vérifie si une IP est privée."""
        parts = ip.split(".")
        if len(parts) != 4:
            return True

        first = int(parts[0])
        second = int(parts[1])

        if first == 10:
            return True
        if first == 172 and 16 <= second <= 31:
            return True
        if first == 192 and second == 168:
            return True
        if first == 127:
            return True

        return False
