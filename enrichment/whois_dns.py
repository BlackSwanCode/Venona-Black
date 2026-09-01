import whois
import dns.resolver
from typing import Dict, Any
import asyncio

async def enrich_with_whois(domain: str) -> Dict[str, Any]:
    """Enrichit un domaine via WHOIS et DNS."""
    result = {}
    
    # WHOIS (exécuté dans un thread pour ne pas bloquer l'async)
    try:
        loop = asyncio.get_running_loop()
        w = await loop.run_in_executor(None, whois.whois, domain)
        
        result["whois"] = {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date) if w.creation_date else "Unknown",
            "expiration_date": str(w.expiration_date) if w.expiration_date else "Unknown",
            "name_servers": w.name_servers if w.name_servers else [],
            "org": w.org,
            "country": w.country
        }
    except Exception as e:
        result["whois"] = {"error": str(e)}
    
    # DNS Records
    try:
        dns_records = {}
        
        # A records
        try:
            answers = await dns.resolver.resolve(domain, 'A')
            dns_records["A"] = [str(rdata) for rdata in answers]
        except Exception:
            pass
        
        # MX records
        try:
            answers = await dns.resolver.resolve(domain, 'MX')
            dns_records["MX"] = [str(rdata.exchange) for rdata in answers]
        except Exception:
            pass
        
        # TXT records
        try:
            answers = await dns.resolver.resolve(domain, 'TXT')
            dns_records["TXT"] = [str(rdata) for rdata in answers]
        except Exception:
            pass
        
        result["dns"] = dns_records
    except Exception as e:
        result["dns"] = {"error": str(e)}
    
    return result
