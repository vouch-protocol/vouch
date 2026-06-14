"""
Focused tests for the cherry-picked security hardening: the SSRF guard used by
did:web resolution, and the path-traversal-safe key filename derivation.

The proof-binding and bounded-cache additions in the verifier are exercised
indirectly by the full existing suite (which still passes); these tests pin the
two guards that are cleanly unit-testable.
"""

import os

import pytest

from vouch.ssrf import validate_url, SSRFError
from vouch.keys import KeyManager


# --- SSRF guard -------------------------------------------------------------


def test_ssrf_rejects_non_https():
    with pytest.raises(SSRFError):
        validate_url("http://8.8.8.8")


def test_ssrf_rejects_loopback():
    with pytest.raises(SSRFError):
        validate_url("https://127.0.0.1")


def test_ssrf_rejects_cloud_metadata():
    # 169.254.169.254 is the link-local cloud-metadata endpoint.
    with pytest.raises(SSRFError):
        validate_url("https://169.254.169.254")


def test_ssrf_rejects_private_range():
    with pytest.raises(SSRFError):
        validate_url("https://10.0.0.1")


def test_ssrf_allows_public_https():
    # 8.8.8.8 is a public address literal (no DNS lookup needed); must not raise.
    validate_url("https://8.8.8.8")


# --- Key filename path traversal -------------------------------------------


def test_keys_path_traversal_is_contained():
    km = KeyManager()
    path = km._get_filename("did:web:../../etc/passwd")
    # The crafted DID must not escape the key directory. Path separators are
    # stripped, so any residual dots are literal filename characters, not
    # traversal; the real guarantee is that the resolved file stays in key_dir.
    assert os.path.dirname(os.path.realpath(path)) == os.path.realpath(km.key_dir)
    assert "/" not in os.path.basename(path)
    assert os.sep not in os.path.basename(path)


def test_keys_normal_did_filename_preserved():
    km = KeyManager()
    path = km._get_filename("did:web:example.com")
    # Historic scheme preserved for ordinary DIDs (':' becomes '-').
    assert os.path.basename(path) == "did-web-example.com.json"
