"""
DuckDuckGo Collector — Recherche via html.duckduckgo.com/html/ (scraping, sans clé API).

⚠️ DuckDuckGo applique un "soft rate limit" documenté sur cet endpoint : au
lieu de bloquer franchement (403), il peut répondre 202 (Accepted) tout en
ne renvoyant aucun résultat exploitable, ou 429 en rate-limit classique.
Dans les deux cas, on retente avec un backoff exponentiel + jitter plutôt
que d'abandonner immédiatement — voir DDG_MAX_RETRIES / DDG_BACKOFF_BASE_SECONDS.
"""

import aiohttp
import asyncio
import os
import random
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
from collectors.base import BaseCollector
from core.models import SearchResult
import logging

logger = logging.getLogger("dorker.ddg")

# Statuts considérés comme un rate-limit temporaire (on retente) plutôt
# qu'un échec définitif (on abandonne).
RETRYABLE_STATUSES = {202, 429}


class DuckDuckGoCollector(BaseCollector):
    async def collect(self, query: str, session: aiohttp.ClientSession) -> list[SearchResult]:
        max_retries = max(1, int(os.getenv("DDG_MAX_RETRIES", "3")))
        base_backoff = float(os.getenv("DDG_BACKOFF_BASE_SECONDS", "3"))

        url = "https://html.duckduckgo.com/html/"
        data = {"q": query}

        for attempt in range(1, max_retries + 1):
            # Nouvelle rotation de User-Agent à chaque tentative.
            ua = UserAgent().random
            headers = {
                "User-Agent": ua,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Referer": "https://duckduckgo.com/"
            }

            try:
                async with session.post(url, headers=headers, data=data, timeout=15) as response:
                    if response.status != 200:
                        if response.status in RETRYABLE_STATUSES and attempt < max_retries:
                            backoff = base_backoff * (2 ** (attempt - 1)) + random.uniform(0, 1.5)
                            logger.warning(
                                f"DDG a renvoyé {response.status} (soft rate-limit) — "
                                f"nouvel essai {attempt}/{max_retries - 1} dans {backoff:.1f}s"
                            )
                            await asyncio.sleep(backoff)
                            continue

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

        return []
