"""
Traducteur de Google Dorks vers la syntaxe de chaque moteur de recherche.

Intègre maintenant le QuerySanitizer pour nettoyer les requêtes problématiques.
"""

import re
from typing import Dict, List, Tuple
from dataclasses import dataclass
from core.query_sanitizer import QuerySanitizer, SanitizedQuery

@dataclass
class TranslationResult:
    """Résultat de la traduction d'une requête."""
    original: str
    translated: str
    engine: str
    lost_operators: List[str]
    warnings: List[str]
    was_sanitized: bool = False

class DorkTranslator:
    """Traduit les Google Dorks vers la syntaxe native de chaque moteur."""
    
    ENGINE_CAPABILITIES = {
        "duckduckgo_html": {
            "exact_match": True,
            "exclusion": True,
            "site": False,
            "or_and": False,
            "filetype": False,
            "intitle": False,
            "inurl": False,
            "parentheses": False,
        },
        "searxng_public": {
            "exact_match": True,
            "exclusion": True,
            "site": True,
            "or_and": True,
            "filetype": True,
            "intitle": True,
            "inurl": True,
            "parentheses": True,
        },
        "brave_search": {
            "exact_match": True,
            "exclusion": True,
            "site": True,
            "or_and": False,
            "filetype": False,
            "intitle": False,
            "inurl": False,
            "parentheses": False,
        },
        "qwant": {
            "exact_match": True,
            "exclusion": True,
            "site": True,
            "or_and": False,
            "filetype": False,
            "intitle": False,
            "inurl": False,
            "parentheses": False,
        },
        "mojeek": {
            "exact_match": True,
            "exclusion": True,
            "site": True,
            "or_and": False,
            "filetype": False,
            "intitle": False,
            "inurl": False,
            "parentheses": False,
        },
        "crtsh_passive": {
            "exact_match": False,
            "exclusion": False,
            "site": False,
            "or_and": False,
            "filetype": False,
            "intitle": False,
            "inurl": False,
            "parentheses": False,
        },
        "github_code": {
            "exact_match": True,
            "exclusion": True,
            "site": False,
            "or_and": True,
            "filetype": True,
            "intitle": False,
            "inurl": False,
            "parentheses": False,
        },
    }
    
    @staticmethod
    def translate(query: str, engine_id: str) -> TranslationResult:
        """Traduit une requête Google Dork pour un moteur spécifique."""
        capabilities = DorkTranslator.ENGINE_CAPABILITIES.get(
            engine_id, 
            DorkTranslator.ENGINE_CAPABILITIES["duckduckgo_html"]
        )
        
        # Étape 1 : Nettoyage de la requête
        sanitized = QuerySanitizer.sanitize(query, engine_id)
        translated = sanitized.sanitized
        lost_operators = sanitized.removed_elements.copy()
        warnings = sanitized.warnings.copy()
        
        # Étape 2 : Traduction supplémentaire si nécessaire
        # (Le QuerySanitizer gère déjà la plupart des cas, mais on garde cette logique pour compatibilité)
        
        # Vérifier si des opérateurs non supportés restent
        if not capabilities.get("site") and 'site:' in translated.lower():
            lost_operators.append("site:")
            translated = re.sub(r'site:[^\s]+', '', translated, flags=re.IGNORECASE)
        
        if not capabilities.get("filetype") and 'filetype:' in translated.lower():
            lost_operators.append("filetype:")
            translated = re.sub(r'filetype:[^\s]+', '', translated, flags=re.IGNORECASE)
        
        # Nettoyage final
        translated = re.sub(r'\s+', ' ', translated).strip()
        
        return TranslationResult(
            original=query,
            translated=translated,
            engine=engine_id,
            lost_operators=lost_operators,
            warnings=warnings,
            was_sanitized=(translated != query)
        )
    
    @staticmethod
    def translate_for_multiple_engines(query: str, engine_ids: List[str]) -> Dict[str, TranslationResult]:
        """Traduit une requête pour plusieurs moteurs."""
        return {
            engine_id: DorkTranslator.translate(query, engine_id)
            for engine_id in engine_ids
        }
    
    @staticmethod
    def suggest_syntax(engine_id: str) -> str:
        """Retourne un exemple de syntaxe supportée pour un moteur."""
        capabilities = DorkTranslator.ENGINE_CAPABILITIES.get(engine_id, {})
        
        examples = []
        if capabilities.get("exact_match"):
            examples.append('"exact match"')
        if capabilities.get("exclusion"):
            examples.append('-excluded_word')
        if capabilities.get("site"):
            examples.append('site:example.com')
        if capabilities.get("or_and"):
            examples.append('word1 OR word2')
        if capabilities.get("filetype"):
            examples.append('filetype:pdf')
        if capabilities.get("intitle"):
            examples.append('intitle:"keyword"')
        if capabilities.get("parentheses"):
            examples.append('(word1 OR word2)')
        
        return " ".join(examples) if examples else "Recherche simple uniquement"
    
    @staticmethod
    def recommend_engines_for_query(query: str) -> List[str]:
        """Recommande les meilleurs moteurs pour une requête donnée."""
        is_complex = QuerySanitizer.is_complex_query(query)
        
        if is_complex:
            # Requêtes complexes : privilégier SearXNG
            return ["searxng_public"]
        else:
            # Requêtes simples : tous les moteurs conviennent
            return ["duckduckgo_html", "searxng_public"]
