"""
Scraper de contenu de pages web pour extraction d'IOC contextuels.

Ce module récupère le texte brut des pages trouvées par les moteurs de recherche,
permettant d'extraire les IOC mentionnés dans le contenu (hashes, IPs, domaines C2, etc.)
et non seulement les URLs des sources.
"""

import aiohttp
import asyncio
from bs4 import BeautifulSoup
import re
from typing import List, Dict, Optional
from fake_useragent import UserAgent
from core.models import SearchResult
import logging

logger = logging.getLogger("dorker.scraper")

class ContentScraper:
    """Récupère le contenu textuel des pages web pour analyse OSINT."""
    
    # Taille max à télécharger (en octets) pour éviter les fichiers trop volumineux
    MAX_CONTENT_SIZE = 5 * 1024 * 1024  # 5 MB
    
    # Timeout pour chaque requête
    TIMEOUT = 15
    
    # Tags HTML à supprimer (menus, pubs, navigation, etc.)
    REMOVE_TAGS = ['script', 'style', 'nav', 'header', 'footer', 'aside', 'iframe', 'noscript']
    
    # Domaines à ne pas scraper (légitimes, trop volumineux, ou risqués)
    SKIP_DOMAINS = {
        'youtube.com', 'youtu.be',  # Vidéos, pas de contenu textuel utile
        'twitter.com', 'x.com',  # Nécessite authentification
        'facebook.com', 'instagram.com',
        'linkedin.com',
        'archive.org',  # Trop volumineux
    }
    
    def __init__(self, max_concurrent: int = 5):
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.ua = UserAgent()
    
    def _should_skip(self, url: str) -> bool:
        """Vérifie si une URL doit être ignorée."""
        from urllib.parse import urlparse
        try:
            domain = urlparse(url).netloc.lower()
            for skip_domain in self.SKIP_DOMAINS:
                if domain.endswith(skip_domain):
                    return True
            return False
        except Exception:
            return True
    
    async def scrape_page(self, session: aiohttp.ClientSession, url: str) -> Optional[Dict]:
        """
        Récupère le contenu textuel d'une page web.
        
        Returns:
            Dict avec 'url', 'text', 'title' ou None en cas d'erreur
        """
        if self._should_skip(url):
            return None
        
        async with self.semaphore:
            try:
                headers = {
                    "User-Agent": self.ua.random,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9,fr;q=0.8",
                }
                
                async with session.get(url, headers=headers, timeout=self.TIMEOUT) as response:
                    # Vérifier le type de contenu
                    content_type = response.headers.get('Content-Type', '').lower()
                    if 'html' not in content_type and 'text' not in content_type:
                        logger.debug(f"Skipping {url}: not HTML ({content_type})")
                        return None
                    
                    # Vérifier la taille
                    content_length = int(response.headers.get('Content-Length', 0))
                    if content_length > self.MAX_CONTENT_SIZE:
                        logger.debug(f"Skipping {url}: too large ({content_length} bytes)")
                        return None
                    
                    html = await response.text()
                    
                    # Parser et nettoyer le HTML
                    soup = BeautifulSoup(html, 'html.parser')
                    
                    # Titre de la page
                    title = ""
                    title_tag = soup.find('title')
                    if title_tag:
                        title = title_tag.get_text(strip=True)
                    
                    # Supprimer les tags non pertinents
                    for tag in self.REMOVE_TAGS:
                        for element in soup.find_all(tag):
                            element.decompose()
                    
                    # Extraire le texte
                    text = soup.get_text(separator=' ', strip=True)
                    
                    # Nettoyage des espaces multiples
                    text = re.sub(r'\s+', ' ', text)
                    
                    # Vérifier qu'on a assez de contenu
                    if len(text) < 100:
                        return None
                    
                    return {
                        'url': url,
                        'title': title,
                        'text': text,
                        'length': len(text)
                    }
                    
            except asyncio.TimeoutError:
                logger.debug(f"Timeout scraping {url}")
                return None
            except Exception as e:
                logger.debug(f"Error scraping {url}: {e}")
                return None
    
    async def scrape_multiple(
        self, 
        session: aiohttp.ClientSession, 
        urls: List[str],
        max_pages: int = 10
    ) -> List[Dict]:
        """
        Scrape plusieurs pages en parallèle avec limite de concurrence.
        
        Args:
            session: Session aiohttp
            urls: Liste d'URLs à scraper
            max_pages: Nombre max de pages à scraper (pour limiter le temps)
        
        Returns:
            Liste de dicts avec le contenu des pages
        """
        urls_to_scrape = urls[:max_pages]
        
        tasks = [self.scrape_page(session, url) for url in urls_to_scrape]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filtrer les erreurs et les None
        valid_results = []
        for result in results:
            if isinstance(result, dict) and result is not None:
                valid_results.append(result)
        
        return valid_results
