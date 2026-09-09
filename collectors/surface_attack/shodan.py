"""
Shodan Collector — Recherche d'hosts exposés sur Internet.

Shodan est le moteur de recherche pour les appareils connectés.
API: https://api.shodan.io/
Clé API requise (SHODAN_API_KEY dans .env)

⚠️ L'endpoint /shodan/host/search est réservé aux comptes payants — un
compte Free renverra un 403 même avec une clé valide et un code correct.
Vérifiez le plan de votre clé sur https://account.shodan.io/billing.
Activez DEBUG_API_CALLS=1 (voir utils/api_debug.py) pour voir la réponse
brute renvoyée par Shodan en cas d'erreur.
"""

import aiohttp
import os
from typing import List
from collectors.base import BaseCollector
from core.models import SearchResult
from utils.api_debug import log_api_call
import logging

logger = logging.getLogger("dorker.shodan")

class ShodanCollector(BaseCollector):
    """
    Collecteur Shodan.

    Recherche des hosts, services, et vulnérabilités.
    Nécessite une clé API (SHODAN_API_KEY).
    """

    BASE_URL = "https://api.shodan.io"

    async def collect(self, query: str, session: aiohttp.ClientSession) -> List[SearchResult]:
        """Recherche dans Shodan."""
        api_key = os.getenv("SHODAN_API_KEY")
        if not api_key:
            logger.info("Shodan désactivé (clé API manquante)")
            return []

        url = f"{self.BASE_URL}/shodan/host/search"
        params = {
            "key": api_key,
            "query": query,
            "limit": 20
        }

        try:
            async with session.get(url, params=params, timeout=15) as response:
                status = response.status
                body_text = None

                if status != 200:
                    try:
                        body_text = await response.text()
                    except Exception:
                        body_text = None

                log_api_call(
                    "Shodan", "GET", url,
                    params=params, status=status, response_body=body_text,
                )

                if status == 401:
                    logger.error("Clé API Shodan invalide")
                    return []

                if status == 403:
                    logger.error(
                        "Shodan a renvoyé 403 (Forbidden) — l'endpoint de recherche complète "
                        "(/shodan/host/search) nécessite un compte payant ; un compte Free "
                        "n'y a pas accès même avec une clé valide. Vérifiez votre plan sur "
                        "account.shodan.io/billing. Activez DEBUG_API_CALLS=1 pour le détail "
                        "du message renvoyé par Shodan."
                    )
                    return []

                if status == 429:
                    logger.warning("Quota Shodan dépassé")
                    return []

                if status != 200:
                    logger.warning(f"Shodan returned {status}")
                    return []

                data = await response.json()
                results = []

                for match in data.get("matches", [])[:20]:
                    ip = match.get("ip_str", "")
                    port = match.get("port", "")
                    org = match.get("org", "N/A")
                    country = match.get("location", {}).get("country_name", "N/A")
                    city = match.get("location", {}).get("city", "N/A")

                    banners = []
                    if match.get("http"):
                        banners.append(f"HTTP: {match['http'].get('server', 'N/A')}")
                    if match.get("ssl"):
                        banners.append("SSL: Oui")
                    if match.get("vulns"):
                        vulns = list(match["vulns"].keys())[:5]
                        banners.append(f"Vulns: {', '.join(vulns)}")

                    snippet = f"IP: {ip}:{port} | Org: {org} | Location: {city}, {country} | {' | '.join(banners)}"

                    results.append(SearchResult(
                        title=f"Shodan: {ip}:{port}",
                        url=f"https://www.shodan.io/host/{ip}",
                        snippet=snippet,
                        source="Shodan"
                    ))

                return results

        except Exception as e:
            log_api_call("Shodan", "GET", url, params=params, error=str(e))
            logger.error(f"Erreur Shodan: {e}")
            return []
