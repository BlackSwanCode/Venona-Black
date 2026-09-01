import aiohttp
import os
from collectors.base import BaseCollector
from core.models import SearchResult
import logging

logger = logging.getLogger("dorker.github")

class GitHubCollector(BaseCollector):
    async def collect(self, query: str, session: aiohttp.ClientSession) -> list[SearchResult]:
        """Recherche de code via l'API GitHub."""
        token = os.getenv("GITHUB_TOKEN")
        headers = {"Accept": "application/vnd.github.v3+json"}
        if token:
            headers["Authorization"] = f"token {token}"
        
        url = "https://api.github.com/search/code"
        params = {"q": query, "per_page": 10}
        
        try:
            async with session.get(url, headers=headers, params=params, timeout=10) as response:
                if response.status == 403:
                    logger.warning("Quota API GitHub dépassé ou token manquant")
                    return []
                if response.status != 200:
                    return []
                
                data = await response.json()
                results = []
                
                for item in data.get("items", []):
                    repo = item.get("repository", {})
                    results.append(SearchResult(
                        title=item.get("name", "No Title"),
                        url=item.get("html_url", ""),
                        snippet=f"Repo: {repo.get('full_name', 'N/A')} | Path: {item.get('path', 'N/A')}",
                        source="GitHub"
                    ))
                
                return results
        except Exception as e:
            logger.error(f"Erreur GitHub: {e}")
            return []
