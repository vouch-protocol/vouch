"""
Python side of the shared Authority Freshness interop vector.

Loads test-vectors/authority-state/vector.json and asserts that Python:
  1. reproduces `proofValue` byte-for-byte from the seed + unsigned credential,
  2. verifies `signed_credential`, and rejects a stale-epoch tamper,
  3. reaches the same allow/reason on every freshness case.

The Rust, TypeScript, and Go runners load the same file and must agree.
"""

import base64
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from vouch import data_integrity
from vouch.authority_state import (
    evaluate_authority_freshness,
    read_authority_epoch,
    verify_authority_state,
)
from vouch.multikey import encode_ed25519_public

VECTOR = Path(__file__).resolve().parent.parent / "test-vectors" / "authority-state" / "vector.json"


def _load():
    return json.loads(VECTOR.read_text(encoding="utf-8"))


def test_reproduce_proof_value():
    v = _load()
    seed = base64.b64decode(v["ed25519"]["seed_b64"])
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    created = datetime.fromisoformat(v["created"].replace("Z", "+00:00")).astimezone(timezone.utc)
    proof = data_integrity.build_proof(
        v["unsigned_credential"], priv, v["verificationMethod"], created=created
    )
    assert proof["proofValue"] == v["proofValue"]


def test_verify_signed_and_reject_tamper():
    v = _load()
    pub_raw = base64.b64decode(v["ed25519"]["public_key_b64"])
    mk = encode_ed25519_public(pub_raw)

    ok, passport = verify_authority_state(
        v["signed_credential"], mk, at_time=datetime(2026, 7, 26, 10, 2, tzinfo=timezone.utc)
    )
    assert ok is True
    assert passport.authority_epoch == read_authority_epoch(v["unsigned_credential"])

    tampered = json.loads(json.dumps(v["signed_credential"]))
    tampered["credentialSubject"]["authorityEpoch"] = 999
    ok2, _ = verify_authority_state(
        tampered, mk, at_time=datetime(2026, 7, 26, 10, 2, tzinfo=timezone.utc)
    )
    assert ok2 is False


def test_freshness_cases_match():
    v = _load()
    for case in v["freshness"]["cases"]:
        verdict = evaluate_authority_freshness(
            tier=case["tier"],
            voucher_epoch=case["voucher_epoch"],
            last_seen_epoch=case["last_seen_epoch"],
            current_status=case["current_status"],
            live_cosign_ok=case["live_cosign_ok"],
        )
        assert verdict.allow is case["expected_allow"], case["name"]
        if "expected_reason" in case:
            assert verdict.reason == case["expected_reason"], case["name"]
