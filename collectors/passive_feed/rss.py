"""
RSS/Atom Feeds Collector — Agrégation de flux OSINT.

Agrège les flux RSS de sources de threat intelligence pour
détecter les mentions d'une cible.

Sources: BleepingComputer, TheHackerNews, ThreatPost, etc.
"""

import aiohttp
import feedparser
from typing import List
from collectors.base import BaseCollector
from core.models import SearchResult
import logging

logger = logging.getLogger("dorker.rss")

class RSSCollector(BaseCollector):
    """
    Collecteur de flux RSS OSINT.

    Recherche dans les flux RSS de sources de sécurité.
    """

    FEEDS = [
        "https://www.bleepingcomputer.com/feed/",
        "https://feeds.feedburner.com/TheHackersNews",
        "https://www.darkreading.com/rss.xml",
        "https://threatpost.com/feed/",
        "https://www.securityweek.com/feed/",
        "https://krebsonsecurity.com/feed/",
        "https://therecord.media/feed/",
    ]

    async def collect(self, query: str, session: aiohttp.ClientSession) -> List[SearchResult]:
        """Recherche des mentions dans les flux RSS."""
        results = []
        query_lower = query.lower()

        for feed_url in self.FEEDS:
            try:
                async with session.get(feed_url, timeout=15) as response:
                    if response.status != 200:
                        continue

                    content = await response.text()
                    feed = feedparser.parse(content)

                    for entry in feed.entries[:10]:
                        title = entry.get("title", "")
                        summary = entry.get("summary", "")
                        link = entry.get("link", "")

                        # Vérifier si la requête est mentionnée
                        if query_lower in title.lower() or query_lower in summary.lower():
                            results.append(SearchResult(
                                title=f"RSS: {title}",
                                url=link,
                                snippet=summary[:300] + "..." if len(summary) > 300 else summary,
                                source=f"RSS/{feed.feed.get('title', 'Unknown')}"
                            ))

            except Exception as e:
                logger.debug(f"Erreur RSS {feed_url}: {e}")
                continue

        return results
