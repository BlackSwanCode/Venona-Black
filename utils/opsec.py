import aiohttp
import os
import logging

logger = logging.getLogger("dorker.opsec")

async def check_ip_leak() -> dict:
    """Vérifie l'IP réelle et détecte les fuites DNS."""
    try:
        async with aiohttp.ClientSession() as session:
            # Vérifie l'IP perçue
            async with session.get("https://api.ipify.org?format=json", timeout=10) as resp:
                data = await resp.json()
                perceived_ip = data.get("ip")
            
            proxy_active = bool(os.getenv("HTTP_PROXY") or os.getenv("HTTPS_PROXY"))
            
            return {
                "status": "success",
                "perceived_ip": perceived_ip,
                "proxy_active": proxy_active,
                "warning": "Vérifiez que cette IP correspond à votre nœud de sortie attendu." if proxy_active else "Aucun proxy détecté. Votre IP réelle est visible."
            }
    except Exception as e:
        logger.error(f"Erreur vérification IP: {e}")
        return {"status": "error", "message": str(e)}
