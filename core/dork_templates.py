"""
core/dork_templates.py
Générateur de dorks ciblés pour l'exposition de secrets et d'infrastructures.
"""

from typing import List, Dict

DORK_PATTERNS: Dict[str, List[str]] = {
    "sensitive_files": [
        'site:{domain} ext:env OR ext:yml OR ext:yaml OR ext:config OR ext:log',
        'site:{domain} filename:.env OR filename:config.json OR filename:credentials.xml',
        'site:{domain} ext:sql OR ext:db OR ext:backup OR ext:dump',
        'site:{domain} ext:pem OR ext:crt OR ext:key OR ext:pfx OR ext:ppk',
    ],
    "cloud_storage": [
        'site:s3.amazonaws.com "{domain}"',
        'site:blob.core.windows.net "{domain}"',
        'site:storage.googleapis.com "{domain}"',
        'site:digitaloceanspaces.com "{domain}"',
    ],
    "exposed_dashboards_api": [
        'site:{domain} inurl:admin OR inurl:dashboard OR inurl:kibana OR inurl:grafana',
        'site:{domain} inurl:api/v1 OR inurl:swagger OR inurl:api-docs OR inurl:graphql',
        'site:{domain} intitle:"Index of /" OR intitle:"phpMyAdmin"',
    ],
    "hardcoded_credentials": [
        'site:{domain} "DB_PASSWORD=" OR "AWS_SECRET_ACCESS_KEY=" OR "API_KEY="',
        'site:{domain} "BEGIN PRIVATE KEY" OR "Authorization: Bearer"',
    ]
}

def generate_dorks(domain: str) -> List[Dict[str, str]]:
    generated_dorks = []
    clean_domain = domain.strip().lower()

    for category, patterns in DORK_PATTERNS.items():
        for pattern in patterns:
            query = pattern.format(domain=clean_domain)
            generated_dorks.append({
                "category": category,
                "query": query,
                "target_domain": clean_domain
            })
            
    return generated_dorks
