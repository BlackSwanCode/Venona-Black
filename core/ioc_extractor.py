import re
import math
from urllib.parse import urlparse
from typing import List, Dict, Any, Tuple
from core.models import IOC
from core.domain_whitelist import DomainWhitelist


class IOCExtractor:
    # Patterns de détection (IOC classiques + Secrets type TruffleHog/gitleaks)
    PATTERNS = {
        "EMAIL": re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
        "IPV4": re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
        "DOMAIN": re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'),
        "URL": re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*'),
        "HASH_MD5": re.compile(r'\b[a-fA-F0-9]{32}\b'),
        "HASH_SHA1": re.compile(r'\b[a-fA-F0-9]{40}\b'),
        "HASH_SHA256": re.compile(r'\b[a-fA-F0-9]{64}\b'),
        "AWS_SECRET_KEY": re.compile(r'(?i)aws(.{0,20})?[0-9a-zA-Z/+]{40}'),
        "GITHUB_FINE_GRAINED": re.compile(r'github_pat_[0-9a-zA-Z_]{82}'),
        "GITHUB_CLASSIC": re.compile(r'ghp_[0-9a-zA-Z]{36}'),
        "PRIVATE_KEY": re.compile(r'-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----'),
        "DATABASE_CONN_STRING": re.compile(r'(?i)(?:mongodb|postgresql|mysql|redis|jdbc):\/\/[^:\s]+:[^@\s]+@[^\s]+'),
        "GENERIC_API_KEY": re.compile(r'(?i)(?:api[_-]?key|secret[_-]?key|password|passwd)\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{16,}["\']?')
    }

    SUSPICIOUS_TLDS = {'.tk', '.ml', '.xyz', '.top', '.click', '.pw'}

    @staticmethod
    def _calculate_entropy(data: str) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        for x in range(256):
            p_x = float(data.count(chr(x))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        return entropy

    @classmethod
    def _domain_for_whitelist_check(cls, ioc_type: str, value: str) -> str:
        """Extrait le nom de domaine pertinent pour la vérification whitelist."""
        if ioc_type == "DOMAIN":
            return value
        if ioc_type == "URL":
            try:
                return urlparse(value).netloc.split(":")[0]
            except Exception:
                return ""
        return ""

    @classmethod
    def extract_from_text(cls, text: str, source_url: str = "") -> Tuple[List[IOC], Dict[str, int]]:
        """
        Extrait les IOC d'un texte donné.

        Retourne un tuple (liste_d_iocs, stats_locales) où stats_locales contient
        le nombre d'éléments filtrés (domaines whitelistés / faux positifs) pour
        que l'appelant puisse les agréger.
        """
        local_stats = {"filtered_legitimate": 0, "filtered_false_positive": 0}

        if not text:
            return [], local_stats

        found_iocs = []
        seen_values = set()

        for ioc_type, pattern in cls.PATTERNS.items():
            for match in pattern.finditer(text):
                value = match.group(0)

                if value in seen_values:
                    continue

                # Filtre anti-faux positifs basiques
                if value.lower() in ["password", "your_api_key", "example.com", "your_password"]:
                    local_stats["filtered_false_positive"] += 1
                    continue

                confidence = 0.8
                # Validation par entropie pour les secrets
                if ioc_type in ["AWS_SECRET_KEY", "GITHUB_FINE_GRAINED", "GITHUB_CLASSIC", "GENERIC_API_KEY"]:
                    if cls._calculate_entropy(value) < 3.5:
                        local_stats["filtered_false_positive"] += 1
                        continue
                    confidence = 0.95

                # Filtre whitelist (vendors sécurité, CERT, médias tech, plateformes légitimes)
                if ioc_type in ("DOMAIN", "URL"):
                    domain = cls._domain_for_whitelist_check(ioc_type, value)
                    if domain and DomainWhitelist.is_legitimate(domain):
                        local_stats["filtered_legitimate"] += 1
                        seen_values.add(value)
                        continue

                ioc = IOC(value=value, type=ioc_type, confidence=confidence, source_url=source_url)

                found_iocs.append(ioc)
                seen_values.add(value)

        return found_iocs, local_stats

    @classmethod
    def extract_from_results(cls, search_results: List[Any], scraped_contents: List[Any] = None) -> Tuple[List[IOC], Dict]:
        """
        Extrait les IOC depuis les résultats de recherche et le contenu scrapé.
        Retourne un tuple (liste_d_iocs, dictionnaire_de_stats) pour correspondre à l'appel UI.
        """
        all_iocs: List[IOC] = []
        stats = {
            "from_snippets": 0,
            "from_scraped_content": 0,
            "filtered_legitimate": 0,
            "filtered_false_positive": 0,
            "total_iocs": 0,
        }

        if scraped_contents is None:
            scraped_contents = []

        # 1. Extraction depuis les snippets des résultats
        for res in search_results:
            snippet = getattr(res, 'snippet', '') or ''
            url = getattr(res, 'url', '') or ''
            iocs, local_stats = cls.extract_from_text(snippet, url)
            all_iocs.extend(iocs)
            stats["from_snippets"] += len(iocs)
            stats["filtered_legitimate"] += local_stats["filtered_legitimate"]
            stats["filtered_false_positive"] += local_stats["filtered_false_positive"]

        # 2. Extraction depuis le contenu brut scrapé
        for content in scraped_contents:
            if isinstance(content, dict):
                text = content.get('text', '')
                url = content.get('url', '')
            else:
                text = getattr(content, 'text', '') or str(content)
                url = getattr(content, 'url', '')

            iocs, local_stats = cls.extract_from_text(text, url)
            all_iocs.extend(iocs)
            stats["from_scraped_content"] += len(iocs)
            stats["filtered_legitimate"] += local_stats["filtered_legitimate"]
            stats["filtered_false_positive"] += local_stats["filtered_false_positive"]

        # 3. Déduplication finale par valeur
        unique_iocs = list({ioc.value: ioc for ioc in all_iocs}.values())
        stats["total_iocs"] = len(unique_iocs)

        return unique_iocs, stats
