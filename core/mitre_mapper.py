"""
core/mitre_mapper.py
Module d'enrichissement associant les découvertes OSINT et fuites de secrets 
aux techniques et tactiques du framework MITRE ATT&CK.
"""

from typing import List, Dict, Any
from utils.logger import get_investigation_logger

MITRE_ATTACK_RULES: Dict[str, Dict[str, Any]] = {
    "s3_bucket_exposure": {
        "technique_id": "T1530",
        "technique_name": "Data from Cloud Storage Object",
        "tactic": "Collection",
        "url": "https://attack.mitre.org/techniques/T1530/",
        "description": "Les données sensibles stockées dans des buckets cloud (AWS S3, Azure Blob) sont directement accessibles sans authentification."
    },
    "env_file_leak": {
        "technique_id": "T1552.001",
        "technique_name": "Unsecured Credentials: Credentials In Files",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1552/001/",
        "description": "Exposition d'identifiants, tokens API ou mots de passe stockés en clair dans des fichiers (.env, config.json, etc.)."
    },
    "private_key_leak": {
        "technique_id": "T1552.004",
        "technique_name": "Unsecured Credentials: Private Keys",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1552/004/",
        "description": "Présence de clés privées (RSA, SSH, PGP) exposées publiquement permettant d'usurper des identités ou d'accéder à des serveurs."
    },
    "api_key_leak": {
        "technique_id": "T1552.001",
        "technique_name": "Unsecured Credentials: Credentials In Files",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1552/001/",
        "description": "Jetons d'API (Slack, AWS, SaaS) découverts dans des fuites ou du code source."
    },
    "exposed_dashboard": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1190/",
        "description": "Interfaces d'administration ou panneaux d'infrastructures (Kibana, Grafana, Admin) exposés sur Internet."
    },
    "database_dump": {
        "technique_id": "T1212",
        "technique_name": "Exfiltration Over Web Service",
        "tactic": "Exfiltration",
        "url": "https://attack.mitre.org/techniques/T1212/",
        "description": "Fichiers de sauvegarde de base de données (.sql, .db, .dump) accessibles publiquement."
    }
}

class MitreMapper:
    def __init__(self, case_id: str = "GENERAL"):
        self.log = get_investigation_logger(case_id)

    def map_findings(self, raw_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        enriched_findings = []

        for finding in raw_findings:
            mitre_matches = self._detect_mitre_techniques(finding)
            enriched_finding = finding.copy()
            enriched_finding["mitre_attack"] = mitre_matches
            
            if mitre_matches:
                self.log.debug(
                    f"[MitreMapper] URL '{finding.get('url')}' associée à "
                    f"{len(mitre_matches)} technique(s) MITRE ATT&CK."
                )

            enriched_findings.append(enriched_finding)

        return enriched_findings

    def _detect_mitre_techniques(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        matched_techniques = []
        rules_to_apply = set()

        if finding.get("is_s3_bucket") or "s3.amazonaws.com" in finding.get("url", ""):
            rules_to_apply.add("s3_bucket_exposure")

        secrets = finding.get("secrets_found", [])
        for secret in secrets:
            sec_type = secret.get("type")
            if sec_type == "Private Key":
                rules_to_apply.add("private_key_leak")
            elif sec_type in ["AWS Access Key", "Generic API Key", "Slack Token"]:
                rules_to_apply.add("api_key_leak")
            elif sec_type == "Env File Indicator":
                rules_to_apply.add("env_file_leak")

        category = finding.get("category", "")
        if category == "exposed_dashboards_api":
            rules_to_apply.add("exposed_dashboard")
        
        for sensitive_file in finding.get("s3_sensitive_files", []):
            key_name = sensitive_file.get("key", "").lower()
            if ".env" in key_name or "credentials" in key_name:
                rules_to_apply.add("env_file_leak")
            elif ".pem" in key_name or ".key" in key_name:
                rules_to_apply.add("private_key_leak")
            elif ".sql" in key_name or ".dump" in key_name or ".bak" in key_name:
                rules_to_apply.add("database_dump")

        for rule_key in rules_to_apply:
            if rule_key in MITRE_ATTACK_RULES:
                matched_techniques.append(MITRE_ATTACK_RULES[rule_key])

        return matched_techniques
