"""
Whitelist de domaines légitimes à exclure de la liste des IOC.

Ces domaines sont des sources OSINT légitimes (vendors de sécurité, CERT, médias tech,
ONG d'investigation). Les extraire comme IOC serait un faux positif systématique.
"""

class DomainWhitelist:
    """Gère la liste des domaines légitimes à exclure des IOC."""
    
    # Vendors de cybersécurité (publient des analyses, rapports, IOCs)
    SECURITY_VENDORS = {
        # Kaspersky / Securelist
        "kaspersky.com", "securelist.com", "kas.pr",
        # ESET
        "eset.com", "welivesecurity.com", "eset.sk",
        # Palo Alto / Unit 42
        "paloaltonetworks.com", "unit42.paloaltonetworks.com", "unit42.com",
        # CrowdStrike
        "crowdstrike.com",
        # Microsoft
        "microsoft.com", "msrc.microsoft.com", "microsoft.com/security",
        # Cisco / Talos
        "cisco.com", "talosintelligence.com",
        # SentinelOne
        "sentinelone.com",
        # Mandiant / Google
        "mandiant.com", "google.com/threatintelligence",
        # Check Point
        "checkpoint.com", "research.checkpoint.com",
        # Trend Micro
        "trendmicro.com", "trendmicro.co.jp",
        # Zscaler
        "zscaler.com",
        # Recorded Future
        "recordedfuture.com",
        # VirusTotal
        "virustotal.com",
        # Sophos
        "sophos.com", "news.sophos.com",
        # Fortinet
        "fortinet.com", "fortiguard.com",
        # BlackBerry / Cylance
        "blackberry.com",
        # Proofpoint
        "proofpoint.com",
    }
    
    # CERT et agences gouvernementales
    CERT_ORGS = {
        # France
        "ssi.gouv.fr", "cert.ssi.gouv.fr", "anssi.gouv.fr",
        # USA
        "cisa.gov", "us-cert.gov", "nsa.gov", "fbi.gov",
        # UK
        "ncsc.gov.uk",
        # EU
        "enisa.europa.eu", "cert.europa.eu",
        # International
        "mitre.org", "first.org",
        # Ukraine
        "cert.gov.ua",
        # Israel
        "cert.gov.il", "gov.il",
    }
    
    # Médias tech et blogs de sécurité
    TECH_MEDIA = {
        "bleepingcomputer.com",
        "thehackernews.com",
        "threatpost.com",
        "securityaffairs.com",
        "darkreading.com",
        "zdnet.com",
        "techcrunch.com",
        "arstechnica.com",
        "wired.com",
        "therecord.media",
        "securityweek.com",
        "cyberscoop.com",
        "krebsonsecurity.com",
        "motherboard.vice.com",
        "theregister.com",
    }
    
    # Organisations OSINT et d'investigation
    OSINT_ORGS = {
        "bellingcat.com",
        "dfrlab.org",  # Digital Forensic Research Lab
        "atlanticcouncil.org",
        "disinfo.eu",  # EU DisinfoLab
        "occrp.org",  # Organized Crime and Corruption Reporting Project
        "icij.org",  # International Consortium of Investigative Journalists
    }
    
    # Plateformes d'hébergement légitimes (à filtrer avec précaution)
    LEGIT_PLATFORMS = {
        "github.com", "gitlab.com", "bitbucket.org",
        "medium.com", "substack.com",
        "linkedin.com", "twitter.com", "x.com",
        "youtube.com",
        "wikipedia.org",
    }
    
    @classmethod
    def get_all_whitelisted(cls) -> set:
        """Retourne l'ensemble complet des domaines whitelistés."""
        return (
            cls.SECURITY_VENDORS | 
            cls.CERT_ORGS | 
            cls.TECH_MEDIA | 
            cls.OSINT_ORGS | 
            cls.LEGIT_PLATFORMS
        )
    
    @classmethod
    def is_legitimate(cls, domain: str) -> bool:
        """Vérifie si un domaine appartient à la whitelist."""
        domain = domain.lower().strip()
        
        # Retirer les sous-domaines pour vérifier le domaine racine
        # Ex: "research.checkpoint.com" → "checkpoint.com"
        parts = domain.split('.')
        if len(parts) >= 2:
            root_domain = '.'.join(parts[-2:])
        else:
            root_domain = domain
        
        whitelist = cls.get_all_whitelisted()
        
        # Vérification directe
        if domain in whitelist or root_domain in whitelist:
            return True
        
        # Vérification des sous-domaines (ex: blog.kaspersky.com)
        for whitelisted in whitelist:
            if domain.endswith(f".{whitelisted}") or domain == whitelisted:
                return True
        
        return False
    
    @classmethod
    def get_category(cls, domain: str) -> str:
        """Retourne la catégorie d'un domaine whitelisté."""
        domain = domain.lower().strip()
        
        for cat_name, cat_domains in [
            ("Security Vendor", cls.SECURITY_VENDORS),
            ("CERT/Gov", cls.CERT_ORGS),
            ("Tech Media", cls.TECH_MEDIA),
            ("OSINT Org", cls.OSINT_ORGS),
            ("Platform", cls.LEGIT_PLATFORMS),
        ]:
            for whitelisted in cat_domains:
                if domain.endswith(f".{whitelisted}") or domain == whitelisted:
                    return cat_name
        
        return "Unknown"
