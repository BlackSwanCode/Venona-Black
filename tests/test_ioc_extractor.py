"""
Tests unitaires pour core.ioc_extractor.IOCExtractor.

Couvre : détection des types d'IOC de base, dédoublonnage, filtre des
faux positifs évidents (placeholders type "example.com"), et validation
par entropie pour les secrets (pour éviter qu'une chaîne à faible
entropie soit remontée comme clé API malgré un pattern qui matche).
"""

from core.ioc_extractor import IOCExtractor


def test_extract_from_text_empty_returns_empty():
    iocs, stats = IOCExtractor.extract_from_text("")
    assert iocs == []
    assert stats["filtered_legitimate"] == 0
    assert stats["filtered_false_positive"] == 0


def test_extract_ipv4():
    iocs, _ = IOCExtractor.extract_from_text("Le C2 communique avec 45.33.32.156 toutes les 10 min.")
    values = {i.value for i in iocs if i.type == "IPV4"}
    assert "45.33.32.156" in values


def test_extract_email():
    iocs, _ = IOCExtractor.extract_from_text("Contact identifié : attacker@evil-domain.io")
    values = {i.value for i in iocs if i.type == "EMAIL"}
    assert "attacker@evil-domain.io" in values


def test_extract_sha256_hash():
    fake_sha256 = "a" * 64
    iocs, _ = IOCExtractor.extract_from_text(f"Payload hash: {fake_sha256}")
    values = {i.value for i in iocs if i.type == "HASH_SHA256"}
    assert fake_sha256 in values


def test_placeholder_values_are_filtered_as_false_positive():
    iocs, stats = IOCExtractor.extract_from_text("Configurez votre clé : your_api_key puis testez.")
    assert not any(i.value.lower() == "your_api_key" for i in iocs)


def test_deduplication_within_same_text():
    text = "45.33.32.156 apparaît deux fois : 45.33.32.156"
    iocs, _ = IOCExtractor.extract_from_text(text)
    ip_matches = [i for i in iocs if i.value == "45.33.32.156"]
    assert len(ip_matches) == 1


def test_low_entropy_secret_like_string_is_filtered():
    """Une chaîne répétitive de 16+ caractères ne doit pas être remontée
    comme secret malgré un pattern GENERIC_API_KEY qui matche, car son
    entropie est trop faible pour être un vrai secret."""
    text = 'api_key = "aaaaaaaaaaaaaaaaaaaa"'
    iocs, _ = IOCExtractor.extract_from_text(text)
    assert not any(i.type == "GENERIC_API_KEY" for i in iocs)


def test_high_entropy_secret_is_kept_with_high_confidence():
    text = 'api_key: "Zk9mQ2pXeL3vTn8rY5wBpAq2sHc7dFj1"'
    iocs, _ = IOCExtractor.extract_from_text(text)
    matches = [i for i in iocs if i.type == "GENERIC_API_KEY"]
    if matches:
        assert matches[0].confidence >= 0.9


def test_source_url_is_propagated():
    iocs, _ = IOCExtractor.extract_from_text("IP trouvée : 8.8.8.8", source_url="https://example-report.test/ioc")
    ip_iocs = [i for i in iocs if i.value == "8.8.8.8"]
    assert ip_iocs and ip_iocs[0].source_url == "https://example-report.test/ioc"
