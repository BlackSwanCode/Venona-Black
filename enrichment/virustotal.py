import aiohttp
import os
from typing import Dict, Any

async def enrich_with_vt(value: str, vt_type: str, api_key: str) -> Dict[str, Any]:
    """Enrichit un IOC via l'API VirusTotal."""
    base_url = "https://www.virustotal.com/api/v3"
    
    if vt_type == "ip":
        url = f"{base_url}/ip_addresses/{value}"
    elif vt_type == "domain":
        url = f"{base_url}/domains/{value}"
    else:
        return {"error": "Type non supporté"}
    
    headers = {"x-apikey": api_key}
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, timeout=10) as response:
                if response.status == 404:
                    return {"found": False}
                if response.status == 429:
                    return {"error": "Quota API dépassé"}
                if response.status != 200:
                    return {"error": f"HTTP {response.status}"}
                
                data = await response.json()
                attributes = data.get("data", {}).get("attributes", {})
                
                result = {"found": True}
                
                if vt_type == "ip":
                    result["malicious_count"] = attributes.get("last_analysis_stats", {}).get("malicious", 0)
                    result["country"] = attributes.get("country", "Unknown")
                    result["owner"] = attributes.get("as_owner", "Unknown")
                
                elif vt_type == "domain":
                    result["malicious_count"] = attributes.get("last_analysis_stats", {}).get("malicious", 0)
                    result["registrar"] = attributes.get("registrar", "Unknown")
                    result["creation_date"] = attributes.get("creation_date", "Unknown")
                
                return result
    except Exception as e:
        return {"error": str(e)}
