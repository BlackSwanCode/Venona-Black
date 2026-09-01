"""
Qwant Collector — Requêtes via l'API non officielle de Qwant.

Qwant est un moteur de recherche européen (FR) intéressant en OSINT pour
son indexation distincte et son absence de personnalisation par profil
utilisateur. L'API n'est pas documentée officiellement et est protégée par
DataDome sur une partie du trafic : ce collecteur détecte ce blocage et
échoue proprement plutôt que de retourner du HTML de challenge anti-bot.

API (non officielle): https://api.qwant.com/v3/search/web
Pas de clé requise, mais accès non garanti dans la durée (WAF DataDome).
"""

import aiohttp
import json
from fake_useragent import UserAgent
from collectors.base import BaseCollector
from core.models import SearchResult
import logging

logger = logging.getLogger("dorker.qwant")


class QwantCollector(BaseCollector):
    """
    Collecteur Qwant (API non officielle v3).

    Recherche web classique. Se dégrade silencieusement (liste vide) si
    Qwant renvoie un challenge DataDome plutôt qu'une réponse JSON.
    """

    API_URL = "https://api.qwant.com/v3/search/web"

    async def collect(self, query: str, session: aiohttp.ClientSession) -> list[SearchResult]:
        ua = UserAgent().random
        headers = {
            "User-Agent": ua,
            "Accept": "application/json",
            "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8",
            "Referer": "https://www.qwant.com/",
        }
        params = {
            "q": query,
            "count": 20,
            "locale": "fr_FR",
            "offset": 0,
            "device": "desktop",
            "safesearch": 1,
        }

        try:
            async with session.get(self.API_URL, headers=headers, params=params, timeout=15) as response:
                content_type = response.headers.get("Content-Type", "")

                if "application/json" not in content_type:
                    text_preview = await response.text()
                    if "datadome" in text_preview.lower() or "captcha" in text_preview.lower():
                        logger.warning("Qwant protégé par DataDome/CAPTCHA — collecte impossible pour le moment.")
                    else:
                        logger.warning(f"Qwant a renvoyé '{content_type}' au lieu de JSON.")
                    return []

                try:
                    data = await response.json()
                except json.JSONDecodeError:
                    logger.error("Échec du décodage JSON depuis Qwant.")
                    return []

                if data.get("status") != "success":
                    logger.warning(f"Qwant status={data.get('status')} — {data.get('error', {})}")
                    return []

                results = []
                items = (
                    data.get("data", {})
                    .get("result", {})
                    .get("items", {})
                    .get("mainline", [])
                )

                for block in items:
                    if block.get("type") != "web":
                        continue
                    for item in block.get("items", []):
                        results.append(SearchResult(
                            title=item.get("title", "No Title"),
                            url=item.get("url", ""),
                            snippet=item.get("desc", ""),
                            source="Qwant"
                        ))

                return results

        except aiohttp.ClientError as e:
            logger.error(f"Erreur réseau Qwant: {e}")
            return []
        except Exception as e:
            logger.error(f"Erreur inattendue Qwant: {e}")
            return []
