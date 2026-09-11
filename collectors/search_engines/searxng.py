import aiohttp
import json
from fake_useragent import UserAgent
from collectors.base import BaseCollector
from core.models import SearchResult
import logging

logger = logging.getLogger("dorker.searxng")

# Instances publiques connues pour exposer format=json (à revalider
# périodiquement sur https://searx.space, la disponibilité de l'API JSON
# change au gré des admins). Configurable via collectors_registry.json
# (clé "instance_urls", liste) ou "instance_url" (une seule, gardée pour
# compatibilité ascendante).
DEFAULT_INSTANCES = [
    "https://searx.tiekoetter.com",
    "https://searx.be",
    "https://priv.au",
    "https://search.inetol.net",
]


class SearXNGCollector(BaseCollector):
    async def collect(self, query: str, session: aiohttp.ClientSession) -> list[SearchResult]:
        instances = self.config.get("instance_urls")
        if not instances:
            single = self.config.get("instance_url")
            instances = [single] if single else DEFAULT_INSTANCES

        last_error = None
        for base_url in instances:
            results, error = await self._try_instance(base_url, query, session)
            if error is None:
                return results
            last_error = error
            logger.info(f"Repli sur l'instance SearXNG suivante après échec de {base_url}: {error}")

        logger.error(f"Toutes les instances SearXNG ont échoué. Dernière erreur : {last_error}")
        return []

    async def _try_instance(self, base_url: str, query: str, session: aiohttp.ClientSession):
        """Tente une instance donnée. Retourne (results, None) en cas de
        succès, ou ([], message_erreur) en cas d'échec — pour permettre au
        repli d'essayer l'instance suivante plutôt que d'abandonner."""
        url = f"{base_url}/search"

        # Rotation du User-Agent pour éviter le blocage par les WAF (Cloudflare, etc.)
        ua = UserAgent().random
        headers = {
            "User-Agent": ua,
            "Accept": "application/json, text/html, */*",
            "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8",
            "Referer": base_url,
            "DNT": "1"
        }

        params = {
            "q": query,
            "format": "json",
            "language": "fr-FR"
        }

        try:
            async with session.get(url, headers=headers, params=params, timeout=15) as response:
                content_type = response.headers.get('Content-Type', '')

                # Vérification cruciale : est-ce vraiment du JSON ?
                if 'application/json' not in content_type:
                    text_preview = await response.text()
                    if "cloudflare" in text_preview.lower() or "captcha" in text_preview.lower() or "attention required" in text_preview.lower():
                        return [], f"WAF/CAPTCHA détecté sur {base_url}"
                    return [], f"'{content_type}' au lieu de JSON sur {base_url} (format=json probablement désactivé par l'admin)"

                try:
                    data = await response.json()
                except json.JSONDecodeError:
                    return [], f"JSON corrompu depuis {base_url}"

                results = []
                for item in data.get("results", []):
                    results.append(SearchResult(
                        title=item.get("title", "No Title"),
                        url=item.get("url", ""),
                        snippet=item.get("content", ""),
                        source="SearXNG"
                    ))
                return results, None

        except aiohttp.ClientError as e:
            return [], f"Erreur réseau ({base_url}): {e}"
        except Exception as e:
            return [], f"Erreur inattendue ({base_url}): {e}"
