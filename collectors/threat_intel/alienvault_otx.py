"""
AlienVault OTX Collector — Recherche passive d'IOCs via l'API OTX.

OTX est une plateforme de threat intelligence communautaire qui agrège
des IOCs (IPs, domaines, hashes, URLs) depuis des rapports de sécurité.

API: https://otx.alienvault.com/api/
Rate limit: ~1 req/sec (gratuit, pas de clé requise pour la recherche basique)
"""

import aiohttp
from typing import List, Dict, Any
from collectors.base import BaseCollector
from core.models import SearchResult
import logging

logger = logging.getLogger("dorker.alienvault")

class AlienVaultOTXCollector(BaseCollector):
    """
    Collecteur AlienVault OTX.

    Recherche des pulses (rapports) et IOCs associés à une requête.
    Supporte les recherches par domaine, IP, hash ou mot-clé.
    """

    BASE_URL = "https://otx.alienvault.com/api/v1"

    async def collect(self, query: str, session: aiohttp.ClientSession) -> List[SearchResult]:
        """
        Recherche des pulses OTX contenant la requête.

        Args:
            query: Domaine, IP, hash ou mot-clé à rechercher
            session: Session aiohttp

        Returns:
            Liste de SearchResult avec les IOCs trouvés
        """
        results = []

        # Déterminer le type de recherche
        search_type = self._detect_search_type(query)

        try:
            if search_type == "ipv4":
                results = await self._search_ipv4(query, session)
            elif search_type == "domain":
                results = await self._search_domain(query, session)
            elif search_type == "hash":
                results = await self._search_hash(query, session)
            else:
                # Recherche générale par mot-clé dans les pulses
                results = await self._search_pulses(query, session)

        except aiohttp.ClientError as e:
            logger.error(f"Erreur réseau OTX: {e}")
        except Exception as e:
            logger.error(f"Erreur OTX: {e}")

        return results

    def _detect_search_type(self, query: str) -> str:
        """Détecte si la requête est une IP, un domaine, un hash ou un mot-clé."""
        import re

        # IPv4
        if re.match(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', query):
            return "ipv4"

        # Hash MD5/SHA1/SHA256
        if re.match(r'^[a-fA-F0-9]{32}$', query) or re.match(r'^[a-fA-F0-9]{40}$', query) or re.match(r'^[a-fA-F0-9]{64}$', query):
            return "hash"

        # Domaine (simple heuristique)
        if '.' in query and ' ' not in query and not query.startswith('http'):
            return "domain"

        return "keyword"

    async def _search_ipv4(self, ip: str, session: aiohttp.ClientSession) -> List[SearchResult]:
        """Recherche des informations sur une IP via OTX."""
        url = f"{self.BASE_URL}/indicators/IPv4/{ip}/general"

        async with session.get(url, timeout=15) as response:
            if response.status == 404:
                return []
            if response.status != 200:
                logger.warning(f"OTX IPv4 returned {response.status}")
                return []

            data = await response.json()
            results = []

            # Extraire les pulses associés
            pulses = data.get("pulse_info", {}).get("pulses", [])
            for pulse in pulses[:20]:
                results.append(SearchResult(
                    title=f"OTX Pulse: {pulse.get('name', 'Unknown')}",
                    url=pulse.get("references", [""])[0] if pulse.get("references") else f"https://otx.alienvault.com/pulse/{pulse.get('id', '')}",
                    snippet=f"{pulse.get('description', '')[:200]}... | Tags: {', '.join(pulse.get('tags', [])[:5])}",
                    source="AlienVault OTX"
                ))

            # Ajouter les indicateurs associés
            indicators = data.get("pulse_info", {}).get("indicators", [])
            for indicator in indicators[:30]:
                ioc_type = indicator.get("type", "")
                ioc_value = indicator.get("indicator", "")
                if ioc_value and ioc_value != ip:
                    results.append(SearchResult(
                        title=f"OTX IOC: {ioc_type} — {ioc_value}",
                        url=f"https://otx.alienvault.com/indicator/{ioc_type}/{ioc_value}",
                        snippet=f"Type: {ioc_type} | Créé: {indicator.get('created', 'N/A')} | Pulse: {indicator.get('pulse_key', 'N/A')}",
                        source="AlienVault OTX"
                    ))

            return results

    async def _search_domain(self, domain: str, session: aiohttp.ClientSession) -> List[SearchResult]:
        """Recherche des informations sur un domaine via OTX."""
        url = f"{self.BASE_URL}/indicators/domain/{domain}/general"

        async with session.get(url, timeout=15) as response:
            if response.status == 404:
                return []
            if response.status != 200:
                logger.warning(f"OTX Domain returned {response.status}")
                return []

            data = await response.json()
            results = []

            pulses = data.get("pulse_info", {}).get("pulses", [])
            for pulse in pulses[:20]:
                results.append(SearchResult(
                    title=f"OTX Pulse: {pulse.get('name', 'Unknown')}",
                    url=pulse.get("references", [""])[0] if pulse.get("references") else f"https://otx.alienvault.com/pulse/{pulse.get('id', '')}",
                    snippet=f"{pulse.get('description', '')[:200]}... | Tags: {', '.join(pulse.get('tags', [])[:5])}",
                    source="AlienVault OTX"
                ))

            # WHOIS info
            whois = data.get("whois", "")
            if whois:
                results.append(SearchResult(
                    title=f"OTX WHOIS: {domain}",
                    url=f"https://otx.alienvault.com/indicator/domain/{domain}",
                    snippet=f"WHOIS: {whois[:300]}",
                    source="AlienVault OTX"
                ))

            return results

    async def _search_hash(self, file_hash: str, session: aiohttp.ClientSession) -> List[SearchResult]:
        """Recherche des informations sur un hash via OTX."""
        url = f"{self.BASE_URL}/indicators/file/{file_hash}/general"

        async with session.get(url, timeout=15) as response:
            if response.status == 404:
                return []
            if response.status != 200:
                logger.warning(f"OTX Hash returned {response.status}")
                return []

            data = await response.json()
            results = []

            pulses = data.get("pulse_info", {}).get("pulses", [])
            for pulse in pulses[:20]:
                results.append(SearchResult(
                    title=f"OTX Pulse: {pulse.get('name', 'Unknown')}",
                    url=pulse.get("references", [""])[0] if pulse.get("references") else f"https://otx.alienvault.com/pulse/{pulse.get('id', '')}",
                    snippet=f"{pulse.get('description', '')[:200]}... | Tags: {', '.join(pulse.get('tags', [])[:5])}",
                    source="AlienVault OTX"
                ))

            # Analysis info
            analysis = data.get("analysis", {})
            if analysis:
                info = analysis.get("info", {})
                results.append(SearchResult(
                    title=f"OTX Analysis: {file_hash}",
                    url=f"https://otx.alienvault.com/indicator/file/{file_hash}",
                    snippet=f"File type: {info.get('file_type', 'N/A')} | File size: {info.get('file_size', 'N/A')} | Pulse count: {data.get('pulse_info', {}).get('count', 0)}",
                    source="AlienVault OTX"
                ))

            return results

    async def _search_pulses(self, keyword: str, session: aiohttp.ClientSession) -> List[SearchResult]:
        """Recherche des pulses par mot-clé."""
        url = f"{self.BASE_URL}/search/pulses"
        params = {"q": keyword, "limit": 20}

        async with session.get(url, params=params, timeout=15) as response:
            if response.status != 200:
                logger.warning(f"OTX Pulse search returned {response.status}")
                return []

            data = await response.json()
            results = []

            pulses = data.get("results", [])
            for pulse in pulses[:20]:
                results.append(SearchResult(
                    title=f"OTX Pulse: {pulse.get('name', 'Unknown')}",
                    url=pulse.get("references", [""])[0] if pulse.get("references") else f"https://otx.alienvault.com/pulse/{pulse.get('id', '')}",
                    snippet=f"{pulse.get('description', '')[:200]}... | Tags: {', '.join(pulse.get('tags', [])[:5])} | IOCs: {pulse.get('indicator_count', 0)}",
                    source="AlienVault OTX"
                ))

            return results
