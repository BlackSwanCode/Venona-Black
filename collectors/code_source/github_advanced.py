import os
import aiohttp
from collectors.base import BaseCollector
from core.models import SearchResult

class GitHubAdvancedCollector(BaseCollector):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.api_key = os.getenv("GITHUB_TOKEN")

    async def collect(self, query: str, session: aiohttp.ClientSession) -> list:
        if not self.api_key:
            return []
        
        search_query = f"{query} extension:env OR extension:json OR extension:yaml OR extension:py OR extension:sh"
        url = "https://api.github.com/search/code"
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "Authorization": f"token {self.api_key}"
        }
        params = {"q": search_query, "per_page": 15}
        
        try:
            async with session.get(url, headers=headers, params=params, timeout=15) as response:
                if response.status == 200:
                    data = await response.json()
                    results = []
                    for item in data.get("items", []):
                        results.append(SearchResult(
                            title=f"GitHub Code: {item['name']} in {item['repository']['full_name']}",
                            url=item['html_url'],
                            snippet=f"Chemin: {item['path']}",
                            source="github_advanced",
                            metadata={"leak_category": "GITHUB", "raw_context": f"Repo: {item['repository']['full_name']} | Path: {item['path']}"}
                        ))
                    return results
        except Exception as e:
            print(f"[!] Erreur GitHub Advanced: {e}")
        return []
