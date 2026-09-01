import aiosqlite
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from enrichment.virustotal import enrich_with_vt
from enrichment.abuseipdb import enrich_with_abuseipdb
from enrichment.whois_dns import enrich_with_whois

class EnrichmentOrchestrator:
    def __init__(self, db_path: str = "osint_searches.db"):
        self.db_path = db_path

    async def _get_cached_enrichment(self, ioc_value: str) -> Optional[Dict[str, Any]]:
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                "SELECT enrichment_data, last_seen FROM iocs WHERE value = ?", 
                (ioc_value,)
            )
            row = await cursor.fetchone()
            if row:
                data, last_seen_str = row
                if data:
                    last_seen = datetime.fromisoformat(last_seen_str)
                    if datetime.utcnow() - last_seen < timedelta(days=7):
                        return json.loads(data)
        return None

    async def _cache_enrichment(self, ioc_value: str, ioc_type: str, data: Dict[str, Any]):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT INTO iocs (id, value, type, first_seen, last_seen, enrichment_data)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?)
                ON CONFLICT(value) DO UPDATE SET 
                last_seen = CURRENT_TIMESTAMP,
                enrichment_data = excluded.enrichment_data
            """, (hashlib.sha256(ioc_value.encode()).hexdigest(), ioc_value, ioc_type, json.dumps(data)))
            await db.commit()

    async def enrich(self, ioc_value: str, ioc_type: str, api_keys: Dict[str, str]) -> Dict[str, Any]:
        cached = await self._get_cached_enrichment(ioc_value)
        if cached:
            return {"source": "cache", "data": cached}

        enriched_data = {}
        
        try:
            if ioc_type == "IPV4":
                if api_keys.get("ABUSEIPDB"):
                    enriched_data["abuseipdb"] = await enrich_with_abuseipdb(ioc_value, api_keys["ABUSEIPDB"])
                if api_keys.get("VIRUSTOTAL"):
                    enriched_data["virustotal"] = await enrich_with_vt(ioc_value, "ip", api_keys["VIRUSTOTAL"])
            
            elif ioc_type == "DOMAIN":
                enriched_data["whois"] = await enrich_with_whois(ioc_value)
                if api_keys.get("VIRUSTOTAL"):
                    enriched_data["virustotal"] = await enrich_with_vt(ioc_value, "domain", api_keys["VIRUSTOTAL"])
            
            elif ioc_type == "EMAIL":
                enriched_data["mx_record"] = await self._check_mx(ioc_value)

            await self._cache_enrichment(ioc_value, ioc_type, enriched_data)
            return {"source": "live", "data": enriched_data}
            
        except Exception as e:
            return {"source": "error", "error": str(e)}

    async def _check_mx(self, email: str) -> bool:
        import dns.resolver
        domain = email.split("@")[-1]
        try:
            await dns.resolver.resolve(domain, 'MX')
            return True
        except Exception:
            return False
