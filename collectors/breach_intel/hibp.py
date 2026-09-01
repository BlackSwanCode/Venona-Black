"""
Have I Been Pwned Collector — Vérification des fuites de données pour emails.

HIBP est un service de Troy Hunt qui indexe les breaches publiques.
API v3: https://haveibeenpwned.com/API/v3
Clé API requise (HIBP_API_KEY dans .env) — coût ~3$/mois
"""

import aiohttp
import os
from typing import List
from collectors.base import BaseCollector
from core.models import SearchResult
import logging

logger = logging.getLogger("dorker.hibp")

class HIBPCollector(BaseCollector):
    """
    Collecteur Have I Been Pwned.

    Vérifie si un email a été compromis dans des fuites de données connues.
    Nécessite une clé API (HIBP_API_KEY).
    """

    BASE_URL = "https://haveibeenpwned.com/api/v3"

    async def collect(self, query: str, session: aiohttp.ClientSession) -> List[SearchResult]:
        """Vérifie les breaches pour un email."""
        api_key = os.getenv("HIBP_API_KEY")
        if not api_key:
            logger.info("HIBP désactivé (clé API manquante)")
            return []

        # Extraire l'email de la requête
        import re
        email_match = re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', query)
        if not email_match:
            logger.debug(f"HIBP: aucun email trouvé dans '{query}'")
            return []

        email = email_match.group(0)

        headers = {
            "hibp-api-key": api_key,
            "user-agent": "Venona-OSINT-Tool"
        }

        url = f"{self.BASE_URL}/breachedaccount/{email}"
        params = {"truncateResponse": "false"}

        try:
            async with session.get(url, headers=headers, params=params, timeout=10) as response:
                if response.status == 404:
                    # Email non trouvé dans les breaches
                    return [SearchResult(
                        title=f"HIBP: {email} — Aucune fuite",
                        url=f"https://haveibeenpwned.com/account/{email}",
                        snippet="Cet email n'a pas été trouvé dans les bases de fuites de données connues.",
                        source="Have I Been Pwned"
                    )]

                if response.status == 429:
                    logger.warning("Quota HIBP dépassé")
                    return []

                if response.status == 401:
                    logger.error("Clé API HIBP invalide")
                    return []

                if response.status != 200:
                    logger.warning(f"HIBP returned {response.status}")
                    return []

                data = await response.json()
                results = []

                for breach in data[:10]:
                    results.append(SearchResult(
                        title=f"HIBP Breach: {breach.get('Name', 'Unknown')}",
                        url=breach.get("Domain", f"https://haveibeenpwned.com/account/{email}"),
                        snippet=(
                            f"Date: {breach.get('BreachDate', 'N/A')} | "
                            f"Compromised: {breach.get('DataClasses', [])} | "
                            f"Accounts: {breach.get('PwnCount', 'N/A')} | "
                            f"Verified: {breach.get('IsVerified', False)} | "
                            f"Description: {breach.get('Description', 'N/A')[:150]}"
                        ),
                        source="Have I Been Pwned"
                    ))

                return results

        except Exception as e:
            logger.error(f"Erreur HIBP: {e}")
            return []
