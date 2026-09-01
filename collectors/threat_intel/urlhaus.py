"""
URLhaus Collector — Recherche d'URLs malveillantes via l'API abuse.ch.

URLhaus (projet abuse.ch) référence les URLs utilisées pour la distribution
de malware. Utile pour vérifier si un domaine/host est ou a été impliqué
dans une campagne de diffusion, avec les payloads associés (hash, type).

API: https://urlhaus-api.abuse.ch/v1/
Depuis 2025, un Auth-Key abuse.ch est requis (gratuit via https://auth.abuse.ch/).
La même clé peut être réutilisée pour ThreatFox/MalwareBazaar (compte unique).
"""

import os
import re
import aiohttp
from typing import List
from collectors.base import BaseCollector
from core.models import SearchResult
import logging

logger = logging.getLogger("dorker.urlhaus")


class URLhausCollector(BaseCollector):
    """
    Collecteur URLhaus (abuse.ch).

    Recherche par host/domaine, par URL complète, ou par hash de payload.
    """

    BASE_URL = "https://urlhaus-api.abuse.ch/v1"

    async def collect(self, query: str, session: aiohttp.ClientSession) -> List[SearchResult]:
        api_key = os.getenv("URLHAUS_API_KEY")
        if not api_key:
            logger.info("URLhaus désactivé (clé API manquante)")
            return []

        query = query.strip()
        headers = {"Auth-Key": api_key}

        try:
            if query.startswith("http://") or query.startswith("https://"):
                return await self._search_url(query, session, headers)
            if re.match(r'^[a-fA-F0-9]{32}$', query) or re.match(r'^[a-fA-F0-9]{64}$', query):
                return await self._search_hash(query, session, headers)
            return await self._search_host(query, session, headers)

        except aiohttp.ClientError as e:
            logger.error(f"Erreur réseau URLhaus: {e}")
            return []
        except Exception as e:
            logger.error(f"Erreur URLhaus: {e}")
            return []

    async def _search_host(self, host: str, session: aiohttp.ClientSession, headers: dict) -> List[SearchResult]:
        """Recherche les URLs malveillantes hébergées sur un host/domaine."""
        data = {"host": host}
        async with session.post(f"{self.BASE_URL}/host/", headers=headers, data=data, timeout=15) as response:
            if response.status == 401:
                logger.error("Auth-Key URLhaus invalide")
                return []
            if response.status != 200:
                return []

            result = await response.json()
            if result.get("query_status") != "ok":
                return []

            results = []
            for url_entry in (result.get("urls") or [])[:30]:
                tags = ", ".join(url_entry.get("tags") or [])
                results.append(SearchResult(
                    title=f"URLhaus: {url_entry.get('url_status', 'N/A')} — {host}",
                    url=url_entry.get("urlhaus_reference", url_entry.get("url", "")),
                    snippet=(
                        f"URL: {url_entry.get('url', 'N/A')} | Menace: {url_entry.get('threat', 'N/A')} | "
                        f"Ajouté: {url_entry.get('date_added', 'N/A')} | Tags: {tags or 'N/A'}"
                    ),
                    source="URLhaus"
                ))
            return results

    async def _search_url(self, url_value: str, session: aiohttp.ClientSession, headers: dict) -> List[SearchResult]:
        """Recherche des informations sur une URL précise."""
        data = {"url": url_value}
        async with session.post(f"{self.BASE_URL}/url/", headers=headers, data=data, timeout=15) as response:
            if response.status == 401:
                logger.error("Auth-Key URLhaus invalide")
                return []
            if response.status != 200:
                return []

            result = await response.json()
            if result.get("query_status") != "ok":
                return []

            tags = ", ".join(result.get("tags") or [])
            blacklists = result.get("blacklists") or {}
            bl_str = ", ".join(f"{k}={v}" for k, v in blacklists.items())

            return [SearchResult(
                title=f"URLhaus: {result.get('url_status', 'N/A')} — {result.get('host', 'N/A')}",
                url=result.get("urlhaus_reference", url_value),
                snippet=(
                    f"Menace: {result.get('threat', 'N/A')} | Ajouté: {result.get('date_added', 'N/A')} | "
                    f"Tags: {tags or 'N/A'} | Blacklists: {bl_str or 'N/A'} | "
                    f"Payloads: {len(result.get('payloads') or [])}"
                ),
                source="URLhaus"
            )]

    async def _search_hash(self, file_hash: str, session: aiohttp.ClientSession, headers: dict) -> List[SearchResult]:
        """Recherche des informations sur un payload par son hash MD5/SHA256."""
        data = {"md5_hash" if len(file_hash) == 32 else "sha256_hash": file_hash}
        async with session.post(f"{self.BASE_URL}/payload/", headers=headers, data=data, timeout=15) as response:
            if response.status == 401:
                logger.error("Auth-Key URLhaus invalide")
                return []
            if response.status != 200:
                return []

            result = await response.json()
            if result.get("query_status") != "ok":
                return []

            urls = result.get("urls") or []
            return [SearchResult(
                title=f"URLhaus Payload: {result.get('file_type', 'N/A')} — {file_hash[:16]}...",
                url=urls[0].get("urlhaus_reference", "") if urls else "https://urlhaus.abuse.ch/",
                snippet=(
                    f"Taille: {result.get('file_size', 'N/A')} | Signature: {result.get('signature', 'N/A')} | "
                    f"Premier vu: {result.get('firstseen', 'N/A')} | URLs de diffusion: {len(urls)}"
                ),
                source="URLhaus"
            )]
