import aiohttp
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
from collectors.base import BaseCollector
from core.models import SearchResult
import logging

logger = logging.getLogger("dorker.ddg")

class DuckDuckGoCollector(BaseCollector):
    async def collect(self, query: str, session: aiohttp.ClientSession) -> list[SearchResult]:
        url = "https://html.duckduckgo.com/html/"
        # Rotation User-Agent pour éviter les bans simples
        ua = UserAgent().random 
        headers = {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Referer": "https://duckduckgo.com/"
        }
        data = {"q": query}
        
        try:
            async with session.post(url, headers=headers, data=data, timeout=15) as response:
                if response.status != 200:
                    logger.warning(f"DDG returned status {response.status}")
                    return []
                
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')
                
                results = []
                # Parsing spécifique au HTML de DDG
                for result in soup.find_all("div", class_="result"):
                    title_tag = result.find("a", class_="result__a")
                    snippet_tag = result.find("a", class_="result__snippet")
                    
                    if title_tag:
                        title = title_tag.get_text(strip=True)
                        link = title_tag.get("href", "")
                        # DDG utilise des redirections, on garde l'URL brute ou on tente de l'extraire
                        if "uddg=" in link:
                            import urllib.parse
                            parsed = urllib.parse.parse_qs(urllib.parse.urlparse(link).query)
                            link = parsed.get("uddg", [link])[0]
                            
                        snippet = snippet_tag.get_text(strip=True) if snippet_tag else ""
                        
                        results.append(SearchResult(
                            title=title,
                            url=link,
                            snippet=snippet,
                            source="DuckDuckGo"
                        ))
                return results
        except Exception as e:
            logger.error(f"Erreur DDG: {e}")
            return []
