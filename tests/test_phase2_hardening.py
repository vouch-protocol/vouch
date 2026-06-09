"""
Security regression tests for Phase 2 network hardening:
  - SSRF guard blocks non-https and non-public hosts (metadata, loopback,
    private, link-local) while allowing public https.
  - Status list decoding rejects a gzip decompression bomb but still decodes a
    normal list.
"""
import gzip

import pytest

from vouch import ssrf
from vouch.status_list import (
    StatusList,
    StatusListError,
    MAX_STATUS_LIST_BYTES,
    _gunzip_bounded,
)


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/x",                       # not https
        "https://169.254.169.254/latest/meta-data/",  # cloud metadata
        "https://127.0.0.1/x",                        # loopback
        "https://10.0.0.5/x",                         # RFC1918 private
        "https://192.168.1.10/x",                     # RFC1918 private
        "https://[::1]/x",                            # IPv6 loopback
    ],
)
def test_ssrf_blocks_unsafe_urls(url):
    with pytest.raises(ssrf.SSRFError):
        ssrf.validate_url(url)


def test_ssrf_allows_public_https():
    # Resolves to a public address; should not raise.
    ssrf.validate_url("https://example.com/.well-known/did.json")


def test_gzip_bomb_is_rejected():
    bomb = gzip.compress(b"\x00" * (40 * 1024 * 1024))  # ~40 MiB -> tiny
    with pytest.raises(StatusListError):
        _gunzip_bounded(bomb, MAX_STATUS_LIST_BYTES)


def test_normal_status_list_roundtrips():
    sl = StatusList(status_list_id="https://issuer.example/status/1",
                    status_purpose="revocation")
    decoded = StatusList.decode(sl.encode(), "https://issuer.example/status/1",
                                "revocation")
    assert decoded.length >= 131_072
