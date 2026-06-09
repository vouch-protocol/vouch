"""
Security regression tests for Phase 3 robustness:
  - multikey.decode rejects private-key prefixes and wrong-length keys.
  - KeyManager resists path traversal and writes key files as 0o600.
"""
import os
import stat

import pytest

from vouch import multikey
from vouch.multikey import (
    ED25519_PRIV_PREFIX,
    ED25519_PUB_PREFIX,
    _b58encode,
)
from vouch.keys import KeyManager, generate_identity


def _multikey(prefix: bytes, body: bytes) -> str:
    return "z" + _b58encode(prefix + body)


def test_decode_rejects_private_prefix():
    mk = _multikey(ED25519_PRIV_PREFIX, b"\x01" * 32)
    with pytest.raises(ValueError, match="private-key prefix"):
        multikey.decode(mk)


def test_decode_rejects_wrong_length():
    mk = _multikey(ED25519_PUB_PREFIX, b"\x01" * 31)  # one byte short
    with pytest.raises(ValueError, match="32 bytes"):
        multikey.decode(mk)


def test_decode_accepts_valid_public_key():
    mk = _multikey(ED25519_PUB_PREFIX, b"\x02" * 32)
    alg, raw = multikey.decode(mk)
    assert alg == "Ed25519"
    assert len(raw) == 32


def test_keyfile_rejects_path_traversal(tmp_path):
    km = KeyManager(key_dir=str(tmp_path))
    # A DID that sanitizes to nothing usable (all dots) is rejected outright.
    with pytest.raises(ValueError):
        km._get_filename("...")
    # A separator-only DID is collapsed to a safe in-directory name (not an escape).
    assert os.path.dirname(os.path.realpath(km._get_filename("../../"))) == \
        os.path.realpath(str(tmp_path))
    # A traversal-shaped DID still resolves to a file INSIDE key_dir, with no
    # path separators in the name (separators were replaced during sanitizing).
    ident = generate_identity()
    ident.did = "did:web:../../etc/evil"
    km.save_identity(ident)
    key_dir_real = os.path.realpath(str(tmp_path))
    for name in os.listdir(tmp_path):
        assert "/" not in name and "\\" not in name
        assert os.path.dirname(os.path.realpath(tmp_path / name)) == key_dir_real


def test_keyfile_written_with_0600(tmp_path):
    km = KeyManager(key_dir=str(tmp_path))
    ident = generate_identity("example.com")
    km.save_identity(ident)
    files = list(tmp_path.glob("*.json"))
    assert files, "no key file written"
    mode = stat.S_IMODE(os.stat(files[0]).st_mode)
    assert mode == 0o600, f"expected 0o600, got {oct(mode)}"
