import os
import base64
import aiohttp
from collectors.base import BaseCollector
from core.models import SearchResult

class DeHashedCollector(BaseCollector):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.api_key = os.getenv("DEHASHED_API_KEY")
        self.email = os.getenv("DEHASHED_EMAIL")

    async def collect(self, query: str, session: aiohttp.ClientSession) -> list:
        if not self.api_key or not self.email:
            return []
        
        url = "https://api.dehashed.com/search"
        auth_str = f"{self.email}:{self.api_key}"
        headers = {
            "Accept": "application/json",
            "Authorization": f"Basic {base64.b64encode(auth_str.encode()).decode()}"
        }
        params = {"query": f"email:{query} OR username:{query} OR domain:{query} OR password:{query}", "size": 20}
        
        try:
            async with session.get(url, headers=headers, params=params, timeout=15) as response:
                if response.status == 200:
                    data = await response.json()
                    results = []
                    for entry in data.get("entries", []):
                        snippet = f"DB: {entry.get('database_name')} | Email: {entry.get('email', 'N/A')} | User: {entry.get('username', 'N/A')}"
                        results.append(SearchResult(
                            title=f"Data Breach: {entry.get('database_name')}",
                            url="https://dehashed.com",
                            snippet=snippet,
                            source="dehashed",
                            metadata={"leak_category": "DB_DUMP", "raw_context": str(entry)}
                        ))
                    return results
        except Exception as e:
            print(f"[!] Erreur DeHashed: {e}")
        return []
