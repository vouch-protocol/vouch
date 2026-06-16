"""Tests for the lethal-trifecta capability linter."""

from vouch import Signer, generate_identity
from vouch import trifecta as tri


def test_two_legs_is_safe():
    # Private data + untrusted input, but no exfiltration: not lethal.
    result = tri.analyze(["read_database", "fetch_url"])
    assert result.lethal is False
    assert tri.PRIVATE_DATA in result.present
    assert tri.UNTRUSTED_INPUT in result.present
    assert tri.EXFILTRATION not in result.present


def test_all_three_is_lethal():
    result = tri.analyze(["read_database", "browse_web", "send_email"])
    assert result.lethal is True
    assert result.present.issuperset(tri.CATEGORIES)
    assert result.missing == set()


def test_single_capability_multiple_categories():
    # read_email is both private data and untrusted input.
    cats = tri.classify_capability("read_email")
    assert tri.PRIVATE_DATA in cats
    assert tri.UNTRUSTED_INPUT in cats


def test_unclassified_capabilities_listed():
    result = tri.analyze(["frobnicate_widget"])
    assert result.lethal is False
    assert "frobnicate_widget" in result.unclassified


def test_contributing_maps_capabilities():
    result = tri.analyze(["query_db", "scrape_site", "http_post"])
    assert "query_db" in result.contributing[tri.PRIVATE_DATA]
    assert "scrape_site" in result.contributing[tri.UNTRUSTED_INPUT]
    assert "http_post" in result.contributing[tri.EXFILTRATION]


def test_custom_rules_extend_classification():
    rules = {
        tri.PRIVATE_DATA: {"ledger"},
        tri.UNTRUSTED_INPUT: {"feed"},
        tri.EXFILTRATION: {"broadcast"},
    }
    result = tri.analyze(["ledger", "feed", "broadcast"], rules=rules)
    assert result.lethal is True


def test_analyze_credential_extracts_capabilities():
    ident = generate_identity(domain="agent.example.com")
    signer = Signer(private_key=ident.private_key_jwk, did=ident.did)
    # A credential whose intent reads private data; add scopes for the other legs.
    cred = signer.sign_credential(
        intent={
            "action": "read_database",
            "target": "users",
            "resource": "https://api.example.com/users",
        }
    )
    cred["credentialSubject"]["scope"] = ["browse_web", "send_email"]
    result = tri.analyze_credential(cred)
    assert result.lethal is True


def test_credential_without_trifecta_is_safe():
    ident = generate_identity(domain="agent.example.com")
    signer = Signer(private_key=ident.private_key_jwk, did=ident.did)
    cred = signer.sign_credential(
        intent={
            "action": "read_file",
            "target": "config",
            "resource": "https://api.example.com/config",
        }
    )
    result = tri.analyze_credential(cred)
    assert result.lethal is False
