import abc
import asyncio
import logging
from typing import List, Dict, Any
from core.models import SearchResult

logger = logging.getLogger("dorker.collector")

class BaseCollector(abc.ABC):
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.name = config.get("name", "Unknown")
        self.rate_limit_cfg = config.get("rate_limit", {})
        self._last_call_time = 0.0

    @abc.abstractmethod
    async def collect(self, query: str, session: Any) -> List[SearchResult]:
        pass

    async def _respect_rate_limit(self):
        """Simple rate limiter basé sur le temps écoulé."""
        rpm = self.rate_limit_cfg.get("requests_per_minute", 60)
        if rpm <= 0: return
        
        interval = 60.0 / rpm
        # Utilisation de get_running_loop() pour Python 3.10+ (remplace get_event_loop)
        now = asyncio.get_running_loop().time()
        elapsed = now - self._last_call_time
        
        if elapsed < interval:
            wait_time = interval - elapsed
            logger.debug(f"[{self.name}] Rate limit: attente de {wait_time:.2f}s")
            await asyncio.sleep(wait_time)
        
        self._last_call_time = asyncio.get_running_loop().time()
