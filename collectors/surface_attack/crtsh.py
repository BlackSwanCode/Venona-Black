import aiohttp
from collectors.base import BaseCollector
from core.models import SearchResult
import logging

logger = logging.getLogger("dorker.crtsh")

class CrtShCollector(BaseCollector):
    async def collect(self, query: str, session: aiohttp.ClientSession) -> list[SearchResult]:
        """Recherche de certificats via crt.sh (Certificate Transparency)."""
        url = f"https://crt.sh/?q=%25.{query}&output=json"
        
        try:
            async with session.get(url, timeout=15) as response:
                if response.status != 200:
                    return []
                
                data = await response.json()
                results = []
                
                seen_domains = set()
                for cert in data[:50]:  # Limite à 50 résultats
                    domain = cert.get("name_value", "")
                    if domain and domain not in seen_domains:
                        seen_domains.add(domain)
                        results.append(SearchResult(
                            title=f"Certificat: {domain}",
                            url=f"https://crt.sh/?id={cert.get('id', '')}",
                            snippet=f"Émetteur: {cert.get('issuer_name', 'N/A')} | Not Before: {cert.get('not_before', 'N/A')}",
                            source="crt.sh"
                        ))
                
                return results
        except Exception as e:
            logger.error(f"Erreur crt.sh: {e}")
            return []
