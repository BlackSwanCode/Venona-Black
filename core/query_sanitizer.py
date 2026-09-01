"""
Nettoyeur de requêtes pour adapter la syntaxe à chaque moteur de recherche.

Correction appliquée : Suppression systématique des doubles quotes pour DuckDuckGo,
car elles provoquent systématiquement des échecs de parsing ou 0 résultat en scraping HTML.
"""

import re
from typing import List
from dataclasses import dataclass

@dataclass
class SanitizedQuery:
    """Résultat du nettoyage d'une requête."""
    original: str
    sanitized: str
    engine: str
    removed_elements: List[str]
    warnings: List[str]

class QuerySanitizer:
    """Nettoie les requêtes pour les adapter aux limitations de chaque moteur."""
    
    @staticmethod
    def sanitize_for_duckduckgo(query: str) -> SanitizedQuery:
        """
        Nettoie une requête pour DuckDuckGo HTML.
        """
        sanitized = query
        removed = []
        warnings = []
        
        # 1. SUPPRESSION SYSTÉMATIQUE DES DOUBLES QUOTES (Correction critique)
        if '"' in sanitized:
            sanitized = sanitized.replace('"', '')
            removed.append("doubles quotes")
            warnings.append("⚠️ Doubles quotes supprimées : DuckDuckGo HTML gère très mal les guillemets lors du scraping.")
        
        # 2. Supprimer les parenthèses et leur contenu complexe
        paren_pattern = r'\(([^)]+)\)'
        matches = re.findall(paren_pattern, sanitized)
        for match in matches:
            if re.search(r'\bOR\b|\bAND\b', match, re.IGNORECASE):
                terms = re.split(r'\bOR\b|\bAND\b', match, flags=re.IGNORECASE)
                terms = [t.strip() for t in terms if t.strip()]
                replacement = ' '.join(terms)
                sanitized = re.sub(r'\([^)]+\)', replacement, sanitized, count=1)
                removed.append(f"parenthèses: ({match})")
        
        # 3. Supprimer les OR / AND (DDG les cherche littéralement)
        if re.search(r'\bOR\b', sanitized, re.IGNORECASE):
            sanitized = re.sub(r'\bOR\b', '', sanitized, flags=re.IGNORECASE)
            removed.append("OR")
            warnings.append("⚠️ Opérateur 'OR' supprimé (recherché littéralement par DDG).")
        
        if re.search(r'\bAND\b', sanitized, re.IGNORECASE):
            sanitized = re.sub(r'\bAND\b', '', sanitized, flags=re.IGNORECASE)
            removed.append("AND")
            warnings.append("⚠️ Opérateur 'AND' supprimé (recherché littéralement par DDG).")
        
        # 4. Supprimer les opérateurs spéciaux non supportés
        for op in ['site:', 'filetype:', 'intitle:', 'inurl:']:
            if op in sanitized.lower():
                sanitized = re.sub(rf'{op}[^\s]+', '', sanitized, flags=re.IGNORECASE)
                removed.append(op)
                warnings.append(f"⚠️ Opérateur '{op}' supprimé (non supporté).")
        
        # 5. Nettoyage final des espaces et parenthèses orphelines
        sanitized = re.sub(r'\s+', ' ', sanitized).strip()
        sanitized = re.sub(r'[()]', '', sanitized)
        
        # 6. Vérification de sécurité
        if not sanitized or len(sanitized.split()) < 2:
            warnings.append("❌ Requête trop simplifiée, résultats potentiellement limités.")
        
        return SanitizedQuery(
            original=query,
            sanitized=sanitized,
            engine="duckduckgo_html",
            removed_elements=removed,
            warnings=warnings
        )
    
    @staticmethod
    def sanitize_for_searxng(query: str) -> SanitizedQuery:
        """Nettoie une requête pour SearXNG (garde la syntaxe avancée)."""
        sanitized = query
        removed = []
        warnings = []
        
        open_parens = sanitized.count('(')
        close_parens = sanitized.count(')')
        if open_parens != close_parens:
            sanitized = sanitized.replace('(', '').replace(')', '')
            removed.append("parenthèses mal formées")
            warnings.append("⚠️ Parenthèses mal formées détectées et supprimées.")
        
        quote_count = sanitized.count('"')
        if quote_count % 2 != 0:
            sanitized = sanitized.replace('"', '')
            removed.append("doubles quotes mal formées")
            warnings.append("⚠️ Doubles quotes mal formées détectées et supprimées.")
        
        sanitized = re.sub(r'\s+', ' ', sanitized).strip()
        
        return SanitizedQuery(
            original=query,
            sanitized=sanitized,
            engine="searxng_public",
            removed_elements=removed,
            warnings=warnings
        )
    
    @staticmethod
    def sanitize(query: str, engine_id: str) -> SanitizedQuery:
        """Nettoie une requête pour un moteur spécifique."""
        if engine_id == "duckduckgo_html":
            return QuerySanitizer.sanitize_for_duckduckgo(query)
        elif engine_id == "searxng_public":
            return QuerySanitizer.sanitize_for_searxng(query)
        else:
            return SanitizedQuery(
                original=query,
                sanitized=query,
                engine=engine_id,
                removed_elements=[],
                warnings=[]
            )
    
    @staticmethod
    def is_complex_query(query: str) -> bool:
        """Détermine si une requête est trop complexe pour DuckDuckGo."""
        indicators = [
            r'\(.*\bOR\b.*\)', r'\(.*\bAND\b.*\)', r'\bOR\b', r'\bAND\b',
            r'site:', r'filetype:', r'intitle:', r'inurl:', r'"'
        ]
        for pattern in indicators:
            if re.search(pattern, query, re.IGNORECASE):
                return True
        return False
