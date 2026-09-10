"""
SecurityTrails Collector — Reconnaissance DNS passive et énumération de sous-domaines.

SecurityTrails fournit un historique DNS et une base de sous-domaines très
large, utile en reconnaissance d'infrastructure (surface d'attaque passive).

API: https://api.securitytrails.com/v1/
Clé API requise (SECURITYTRAILS_API_KEY dans .env).
Doc: https://docs.securitytrails.com/
"""

import os
import aiohttp
from typing import List
from collectors.base import BaseCollector
from core.models import SearchResult
import logging

logger = logging.getLogger("dorker.securitytrails")


class SecurityTrailsCollector(BaseCollector):
    """
    Collecteur SecurityTrails.

    Attend un nom de domaine (ex: "example.com") en entrée.
    Interroge successivement :
      - GET /v1/domain/{hostname}          -> enregistrements DNS courants
      - GET /v1/domain/{hostname}/subdomains -> sous-domaines connus

    Nécessite une clé API (SECURITYTRAILS_API_KEY dans .env).
    """

    BASE_URL = "https://api.securitytrails.com/v1"
    MAX_SUBDOMAINS = 50

    async def collect(self, query: str, session: aiohttp.ClientSession) -> List[SearchResult]:
        api_key = os.getenv("SECURITYTRAILS_API_KEY")
        if not api_key:
            logger.info("SecurityTrails désactivé (clé API manquante)")
            return []

        domain = query.strip().lower()
        if not domain or " " in domain or "." not in domain:
            logger.debug(f"SecurityTrails: '{query}' ne ressemble pas à un domaine, ignoré")
            return []

        headers = {"apikey": api_key, "Accept": "application/json"}
        results: List[SearchResult] = []

        # --- 1. Enregistrements DNS courants ---
        try:
            url = f"{self.BASE_URL}/domain/{domain}"
            async with session.get(url, headers=headers, timeout=15) as response:
                if response.status == 429:
                    logger.warning("Quota SecurityTrails dépassé")
                    return results
                if response.status == 200:
                    data = await response.json()
                    current_dns = data.get("current_dns", {})
                    snippet_parts = []

                    a_values = [
                        rec.get("ip")
                        for rec in current_dns.get("a", {}).get("values", [])
                        if rec.get("ip")
                    ]
                    if a_values:
                        snippet_parts.append(f"A: {', '.join(a_values[:10])}")

                    mx_values = [
                        rec.get("hostname")
                        for rec in current_dns.get("mx", {}).get("values", [])
                        if rec.get("hostname")
                    ]
                    if mx_values:
                        snippet_parts.append(f"MX: {', '.join(mx_values[:5])}")

                    ns_values = [
                        rec.get("nameserver")
                        for rec in current_dns.get("ns", {}).get("values", [])
                        if rec.get("nameserver")
                    ]
                    if ns_values:
                        snippet_parts.append(f"NS: {', '.join(ns_values[:5])}")

                    hostname = data.get("hostname", domain)
                    alexa_rank = data.get("alexa_rank")
                    if alexa_rank:
                        snippet_parts.append(f"Alexa rank: {alexa_rank}")

                    if snippet_parts:
                        results.append(SearchResult(
                            title=f"SecurityTrails: {hostname} — DNS",
                            url=f"https://securitytrails.com/domain/{domain}/dns",
                            snippet=" | ".join(snippet_parts),
                            source="SecurityTrails",
                        ))
                elif response.status != 404:
                    logger.warning(f"SecurityTrails (domain) a retourné {response.status}")
        except Exception as e:
            logger.error(f"Erreur SecurityTrails (domain): {e}")

        # --- 2. Sous-domaines connus ---
        try:
            url = f"{self.BASE_URL}/domain/{domain}/subdomains"
            async with session.get(url, headers=headers, timeout=15) as response:
                if response.status == 429:
                    logger.warning("Quota SecurityTrails dépassé")
                    return results
                if response.status == 200:
                    data = await response.json()
                    subdomains = data.get("subdomains", [])[: self.MAX_SUBDOMAINS]

                    for sub in subdomains:
                        fqdn = f"{sub}.{domain}" if sub else domain
                        results.append(SearchResult(
                            title=f"SecurityTrails: sous-domaine {fqdn}",
                            url=f"https://securitytrails.com/domain/{fqdn}/dns",
                            snippet=f"Sous-domaine découvert via SecurityTrails pour {domain}.",
                            source="SecurityTrails",
                        ))
                elif response.status != 404:
                    logger.warning(f"SecurityTrails (subdomains) a retourné {response.status}")
        except Exception as e:
            logger.error(f"Erreur SecurityTrails (subdomains): {e}")

        return results
