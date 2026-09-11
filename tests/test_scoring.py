"""
Tests unitaires pour core.scoring.calculate_osint_score.
"""

from core.scoring import calculate_osint_score


class FakeIOC:
    """Stub léger : calculate_osint_score n'a besoin que de .type et .confidence
    (et .enrichment si présent), pas d'un vrai modèle Pydantic core.models.IOC."""
    def __init__(self, type_, confidence=0.8, value="", enrichment=None):
        self.type = type_
        self.confidence = confidence
        self.value = value
        self.enrichment = enrichment


def test_empty_iocs_gives_zero_score():
    assert calculate_osint_score([]) == 0.0


def test_score_increases_with_more_iocs():
    one = calculate_osint_score([FakeIOC("IPV4")])
    two = calculate_osint_score([FakeIOC("IPV4"), FakeIOC("DOMAIN")])
    assert two > one


def test_score_is_capped_at_100():
    many_critical = [FakeIOC("PRIVATE_KEY", confidence=1.0) for _ in range(50)]
    score = calculate_osint_score(many_critical, leaks_count=20)
    assert score == 100.0


def test_unknown_ioc_type_uses_low_default_weight():
    known = calculate_osint_score([FakeIOC("HASH_SHA256", confidence=1.0)])
    unknown = calculate_osint_score([FakeIOC("SOME_UNKNOWN_TYPE", confidence=1.0)])
    assert unknown < known


def test_suspicious_tld_domain_scores_higher_than_normal_tld():
    normal = calculate_osint_score([FakeIOC("DOMAIN", confidence=1.0, value="example.com")])
    suspicious = calculate_osint_score([FakeIOC("DOMAIN", confidence=1.0, value="phishing.tk")])
    assert suspicious > normal


def test_enriched_ioc_scores_higher_than_non_enriched():
    plain = calculate_osint_score([FakeIOC("IPV4", confidence=1.0)])
    enriched = calculate_osint_score([FakeIOC("IPV4", confidence=1.0, enrichment={"abuseipdb": {}})])
    assert enriched > plain


def test_leaks_count_adds_to_score():
    without_leak = calculate_osint_score([FakeIOC("EMAIL")])
    with_leak = calculate_osint_score([FakeIOC("EMAIL")], leaks_count=1)
    assert with_leak > without_leak
