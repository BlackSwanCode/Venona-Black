import aiohttp
from typing import Dict, Any

async def enrich_with_abuseipdb(ip: str, api_key: str) -> Dict[str, Any]:
    """Enrichit une IP via l'API AbuseIPDB."""
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, params=params, timeout=10) as response:
                if response.status == 429:
                    return {"error": "Quota API dépassé"}
                if response.status != 200:
                    return {"error": f"HTTP {response.status}"}
                
                data = await response.json()
                ip_data = data.get("data", {})
                
                return {
                    "abuse_confidence_score": ip_data.get("abuseConfidenceScore", 0),
                    "country_code": ip_data.get("countryCode", "Unknown"),
                    "isp": ip_data.get("isp", "Unknown"),
                    "domain": ip_data.get("domain", "Unknown"),
                    "total_reports": ip_data.get("totalReports", 0),
                    "last_reported_at": ip_data.get("lastReportedAt", None)
                }
    except Exception as e:
        return {"error": str(e)}
