from typing import List


def calculate_osint_score(iocs: list, leaks_count: int = 0, source_reliability: float = 1.0) -> float:
    """
    Scoring v2 : Sévérité × Confiance × Fiabilité source

    Le score est plafonné à 100 pour éviter les valeurs aberrantes.
    """
    score = 0.0

    # Pondération par type d'IOC (basée sur la criticité)
    weights = {
        "HASH_SHA256": 5.0,
        "HASH_SHA1": 4.5,
        "HASH_MD5": 4.0,
        "IPV4": 2.5,
        "DOMAIN": 2.0,
        "URL": 1.5,
        "EMAIL": 1.2,
        "CVE": 3.0,
        "C2_CONFIG": 4.0,
        "PRIVATE_KEY": 5.0,
        "AWS_KEY": 4.5,
        "GITHUB_TOKEN": 4.0,
        "JWT": 3.0,
        "YARA_RULE": 3.5,
        "TLP_MARKER": 2.0,
        "PHONE": 0.8,
        "IBAN": 1.0,
    }

    # TLD souvent associés aux infrastructures malveillantes
    suspicious_tlds = {'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'click', 'link',
                       'work', 'date', 'party', 'racing', 'win', 'download', 'men'}

    for ioc in iocs:
        base = weights.get(ioc.type, 0.5)

        # Bonus si le domaine utilise un TLD suspect
        if ioc.type == "DOMAIN":
            tld = ioc.value.split('.')[-1].lower()
            if tld in suspicious_tlds:
                base *= 1.5

        # Bonus si l'IOC a été enrichi (indique une validation externe)
        if getattr(ioc, 'enrichment', None):
            base *= 1.3

        score += base * ioc.confidence * source_reliability

    # Bonus fuites (très lourd car indique compromission confirmée)
    score += leaks_count * 8.0

    return round(min(score, 100.0), 2)
