"""Tests for the vouch.scan leak detector (PAD-058 detection stage)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vouch.scan import scan_path, scan_text, Finding, Severity, Kind
from vouch.scan.detector import (
    findings_to_json,
    findings_to_text,
    has_severity_at_or_above,
)


# --------------------------------------------------------------------
# Content-based patterns
# --------------------------------------------------------------------


def test_detects_ed25519_private_jwk():
    text = """
    const config = {
        signingKey: {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "BzZB8aBNxJyZ1aaa-replace_me-publicPublicPublicPub",
            "d": "AAABBBCCCDDDEEEFFFGGGHHHIIIJJJKKKLLLMMMNNN1"
        }
    };
    """
    findings = scan_text(text, file_label="config.js")
    assert any(f.kind == Kind.ED25519_PRIVATE_JWK for f in findings)
    crit = [f for f in findings if f.severity == Severity.CRITICAL]
    assert crit, "expected at least one CRITICAL finding"


def test_detects_seed_env_var():
    text = "export VOUCH_ED25519_SEED=" + "ab" * 32
    findings = scan_text(text, file_label=".env")
    assert any(f.kind == Kind.SEED_ENV_VAR for f in findings)
    assert findings[0].severity == Severity.CRITICAL


def test_detects_did_doc_with_private_key():
    text = """
    {
        "id": "did:web:agent.example.com",
        "verificationMethod": [
            {
                "id": "did:web:agent.example.com#key-1",
                "type": "JsonWebKey2020",
                "controller": "did:web:agent.example.com",
                "privateKeyJwk": { "kty": "OKP", "crv": "Ed25519", "d": "..." }
            }
        ]
    }
    """
    findings = scan_text(text, file_label="did.json")
    assert any(f.kind == Kind.DID_DOC_WITH_PRIVATE_KEY for f in findings)


def test_no_finding_on_public_only_did_doc():
    text = """
    {
        "id": "did:web:agent.example.com",
        "verificationMethod": [
            {
                "id": "did:web:agent.example.com#key-1",
                "type": "JsonWebKey2020",
                "controller": "did:web:agent.example.com",
                "publicKeyMultibase": "z6Mkj1AaB..."
            }
        ]
    }
    """
    findings = scan_text(text, file_label="did.json")
    assert findings == [], f"expected no findings on public-only DID Doc, got {findings}"


def test_detects_multibase_private_key():
    text = '{"privateKeyMultibase":"z' + "A" * 48 + '"}'
    findings = scan_text(text, file_label="key.json")
    assert any(f.kind == Kind.ED25519_PRIVATE_MULTIBASE for f in findings)


def test_no_false_positive_on_public_key_jwk():
    """A JWK without the 'd' field (public-only) MUST NOT match."""
    text = """
    {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "publicComponentOnlyPublicComponentOnlyPubOnlyP"
    }
    """
    findings = scan_text(text, file_label="pub.json")
    assert not any(f.kind == Kind.ED25519_PRIVATE_JWK for f in findings)


# --------------------------------------------------------------------
# Filename-based patterns
# --------------------------------------------------------------------


def test_detects_vouch_config_filename(tmp_path: Path):
    target = tmp_path / "vouch.json"
    target.write_text("{}", encoding="utf-8")
    findings = scan_path(target)
    assert any(f.kind == Kind.VOUCH_CONFIG_FILENAME for f in findings)
    # Filename match is MEDIUM (verify file contents).
    fn_findings = [f for f in findings if f.kind == Kind.VOUCH_CONFIG_FILENAME]
    assert fn_findings[0].severity == Severity.MEDIUM


def test_detects_agent_jwk_filename(tmp_path: Path):
    target = tmp_path / "agent.jwk"
    target.write_text("{}", encoding="utf-8")
    findings = scan_path(target)
    assert any(f.kind == Kind.VOUCH_CONFIG_FILENAME for f in findings)


# --------------------------------------------------------------------
# Directory walk
# --------------------------------------------------------------------


def test_scan_directory_finds_in_multiple_files(tmp_path: Path):
    # Two files, each with one critical match.
    (tmp_path / "config.js").write_text(
        'const k = {"kty":"OKP","crv":"Ed25519","d":"' + "x" * 43 + '"};',
        encoding="utf-8",
    )
    (tmp_path / ".env").write_text(
        "VOUCH_ED25519_SEED=" + "00" * 32,
        encoding="utf-8",
    )
    # A benign file that should NOT match.
    (tmp_path / "README.md").write_text("# Project\n\nNothing sensitive here.\n", encoding="utf-8")

    findings = scan_path(tmp_path)
    # Two real critical findings, possibly plus filename findings if any vouch-named.
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical) == 2
    files = {f.file for f in critical}
    assert "config.js" in files
    assert ".env" in files


def test_scan_skips_node_modules(tmp_path: Path):
    """The directory walker MUST NOT descend into node_modules."""
    nm = tmp_path / "node_modules" / "evil-pkg"
    nm.mkdir(parents=True)
    (nm / "index.js").write_text(
        'const k = {"kty":"OKP","crv":"Ed25519","d":"' + "y" * 43 + '"};',
        encoding="utf-8",
    )
    # A real file at the top level.
    (tmp_path / "real.js").write_text("// just a comment\n", encoding="utf-8")

    findings = scan_path(tmp_path)
    # Should find nothing — node_modules was skipped.
    assert findings == [], f"unexpected findings: {findings}"


def test_scan_skips_dot_directories(tmp_path: Path):
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text(
        '{"kty":"OKP","crv":"Ed25519","d":"' + "z" * 43 + '"}',
        encoding="utf-8",
    )
    findings = scan_path(tmp_path)
    assert findings == []


# --------------------------------------------------------------------
# Output formatters
# --------------------------------------------------------------------


def test_findings_to_json_roundtrip():
    text = '{"kty":"OKP","crv":"Ed25519","d":"' + "k" * 43 + '"}'
    findings = scan_text(text, file_label="f.json")
    blob = findings_to_json(findings)
    parsed = json.loads(blob)
    assert isinstance(parsed, list)
    assert parsed[0]["kind"] == "vouch_ed25519_private_jwk"
    assert parsed[0]["severity"] == "critical"
    # Hash is present but the raw secret is NOT in the snippet.
    assert "matched_hash" in parsed[0]
    assert parsed[0]["matched_hash"].startswith("sha256:")


def test_findings_to_text_includes_severity_headers():
    text = '{"kty":"OKP","crv":"Ed25519","d":"' + "k" * 43 + '"}'
    findings = scan_text(text, file_label="f.json")
    report = findings_to_text(findings)
    assert "CRITICAL" in report
    assert "vouch_ed25519_private_jwk" in report


def test_findings_to_text_empty():
    assert "no Vouch-shaped key material detected" in findings_to_text([])


# --------------------------------------------------------------------
# Severity threshold
# --------------------------------------------------------------------


def test_has_severity_at_or_above():
    critical_f = Finding(
        kind=Kind.SEED_ENV_VAR,
        severity=Severity.CRITICAL,
        file="x",
        line=1,
        column=1,
        snippet="x",
        matched_hash="sha256:x",
        description="x",
        remediation="x",
    )
    medium_f = Finding(
        kind=Kind.VOUCH_CONFIG_FILENAME,
        severity=Severity.MEDIUM,
        file="y",
        line=1,
        column=1,
        snippet="y",
        matched_hash="sha256:y",
        description="y",
        remediation="y",
    )
    assert has_severity_at_or_above([critical_f], Severity.HIGH) is True
    assert has_severity_at_or_above([medium_f], Severity.CRITICAL) is False
    assert has_severity_at_or_above([medium_f], Severity.MEDIUM) is True
    assert has_severity_at_or_above([], Severity.LOW) is False


# --------------------------------------------------------------------
# Snippet redaction
# --------------------------------------------------------------------


def test_snippet_redacts_long_matches():
    # The full private key is ~80+ chars; snippet should truncate.
    text = '{"kty":"OKP","crv":"Ed25519","d":"' + "P" * 43 + '"}'
    findings = scan_text(text, file_label="f.json")
    assert findings, "expected at least one finding"
    snippet = findings[0].snippet
    # Either short and unredacted, or truncated with ellipsis.
    assert len(snippet) <= 80 or "..." in snippet


# --------------------------------------------------------------------
# Missing path
# --------------------------------------------------------------------


def test_scan_missing_path_raises():
    with pytest.raises(FileNotFoundError):
        scan_path("/nonexistent/path/should/not/exist/anywhere")
