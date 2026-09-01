import importlib
import json
import os
import logging
import asyncio
from typing import List, Dict, Any
from collectors.base import BaseCollector
from core.models import SearchResult
from core.dork_translator import DorkTranslator, TranslationResult

logger = logging.getLogger("dorker.manager")

class CollectorManager:
    def __init__(self, registry_path: str = "collectors_registry.json"):
        self.registry_path = registry_path
        self.collectors: Dict[str, BaseCollector] = {}
        self._load_collectors()

    def _load_collectors(self):
        if not os.path.exists(self.registry_path):
            logger.warning(f"Registry file {self.registry_path} not found.")
            return

        with open(self.registry_path, 'r', encoding='utf-8') as f:
            registry = json.load(f)
        
        for col_config in registry.get("collectors", []):
            if not col_config.get("enabled", True):
                continue
            
            if col_config.get("requires_api_key"):
                env_var = col_config.get("env_var")
                if not os.getenv(env_var):
                    logger.info(f"Collecteur {col_config['name']} désactivé (clé {env_var} manquante).")
                    continue

            try:
                module_path = col_config["module"]
                class_name = col_config["class"]
                module = importlib.import_module(module_path)
                collector_class = getattr(module, class_name)
                self.collectors[col_config["id"]] = collector_class(col_config)
                logger.info(f"Collecteur chargé : {col_config['name']}")
            except Exception as e:
                logger.error(f"Erreur chargement {col_config['id']}: {e}")

    def translate_query_for_engines(self, query: str, engine_ids: List[str]) -> Dict[str, TranslationResult]:
        """Traduit une requête pour chaque moteur sélectionné."""
        return DorkTranslator.translate_for_multiple_engines(query, engine_ids)

    async def run_all(
        self, 
        query: str, 
        session: Any, 
        selected_ids: List[str] = None,
        use_translated_queries: Dict[str, str] = None
    ) -> List[SearchResult]:
        """
        Lance la collecte sur tous les moteurs sélectionnés.
        
        Args:
            query: Requête originale
            session: Session aiohttp
            selected_ids: Liste des IDs de collecteurs à utiliser
            use_translated_queries: Dict {engine_id: translated_query} pour utiliser des requêtes traduites
        """
        tasks = []
        targets = self.collectors
        if selected_ids:
            targets = {k: v for k, v in self.collectors.items() if k in selected_ids}

        for col_id, collector in targets.items():
            # Utilise la requête traduite si fournie, sinon la requête originale
            effective_query = query
            if use_translated_queries and col_id in use_translated_queries:
                effective_query = use_translated_queries[col_id]
            
            tasks.append(self._safe_collect(collector, effective_query, session))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        final_results = []
        for res in results:
            if isinstance(res, list):
                final_results.extend(res)
            elif isinstance(res, Exception):
                logger.error(f"Erreur collecteur: {res}")
        return final_results

    async def _safe_collect(self, collector: BaseCollector, query: str, session: Any) -> List[SearchResult]:
        await collector._respect_rate_limit()
        return await collector.collect(query, session)
