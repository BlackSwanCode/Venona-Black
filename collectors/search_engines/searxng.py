import aiohttp
import json
from fake_useragent import UserAgent
from collectors.base import BaseCollector
from core.models import SearchResult
import logging

logger = logging.getLogger("dorker.searxng")

class SearXNGCollector(BaseCollector):
    async def collect(self, query: str, session: aiohttp.ClientSession) -> list[SearchResult]:
        # Utilisation d'une instance souvent plus permissive que searx.be
        base_url = self.config.get("instance_url", "https://searx.tiekoetter.com")
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
                    logger.warning(f"L'instance {base_url} a renvoyé '{content_type}' au lieu de JSON. Blocage WAF probable.")
                    
                    # Lecture du contenu pour vérifier s'il s'agit d'une page de blocage connue
                    text_preview = await response.text()
                    if "cloudflare" in text_preview.lower() or "captcha" in text_preview.lower() or "attention required" in text_preview.lower():
                        logger.error(f"L'instance {base_url} est protégée par un WAF/CAPTCHA. Essayez une autre instance.")
                    return []

                # Parsing JSON sécurisé
                try:
                    data = await response.json()
                except json.JSONDecodeError:
                    logger.error(f"Échec du décodage JSON depuis {base_url} (réponse corrompue ou HTML masqué).")
                    return []
                
                results = []
                for item in data.get("results", []):
                    results.append(SearchResult(
                        title=item.get("title", "No Title"),
                        url=item.get("url", ""),
                        snippet=item.get("content", ""),
                        source="SearXNG"
                    ))
                return results
                
        except aiohttp.ClientError as e:
            logger.error(f"Erreur réseau SearXNG ({base_url}) : {e}")
            return []
        except Exception as e:
            logger.error(f"Erreur inattendue SearXNG : {e}")
            return []
