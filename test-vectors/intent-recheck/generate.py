#!/usr/bin/env python3
"""
Generate the shared intent-recheck interop vector from the Python reference.

The vector pins a deterministic Ed25519 key, a set of signed
`ReasonedActionCredential`s, and the expected intent-freshness verdict for each,
so every SDK can prove three things against the SAME bytes:

  1. A seal built here (the credential's `eddsa-jcs-2022` proof) verifies in the
     other language (cross-language signature agreement).
  2. `justification_digest` recomputes to the pinned value (byte-exact JCS).
  3. `verify_intent_freshness` returns the SAME reason string, so a fresh seal is
     accepted and a stale seal is rejected identically everywhere.

Run: `python3 test-vectors/intent-recheck/generate.py`
"""

import base64
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vouch import Signer
from vouch.intent_recheck import (
    TIER_HIGH,
    TIER_ROUTINE,
    default_requirement,
    verify_intent_freshness,
)
from vouch.reasoning import (
    artifact_digest,
    build_justification,
    evidence_anchor,
    justification_digest,
    sign_reasoned_action,
)

SEED = bytes([7] * 32)
DID = "did:web:agent.example"
VM = "did:web:agent.example#key-1"

INTENT = {
    "action": "transfer_funds",
    "target": "account:9911",
    "resource": "https://bank.example/v1/xfer",
}
USER_MSG = {"text": "please move $500 to savings"}
INTERVAL = 60
LAST_PULSE = "2026-08-02T10:00:00Z"


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _signer() -> Signer:
    priv = Ed25519PrivateKey.from_private_bytes(SEED)
    from cryptography.hazmat.primitives import serialization

    raw_pub = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    jwk = json.dumps({"kty": "OKP", "crv": "Ed25519", "d": _b64u(SEED), "x": _b64u(raw_pub)})
    return Signer(private_key=jwk, did=DID), raw_pub


def _dt(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _anchor():
    return evidence_anchor(
        "user asked", ref="urn:msg:42", evidence=USER_MSG, anchor_type="user_message"
    )


def _case(signer, name, tier, sealed_at, exec_at, cred_id):
    just = build_justification(INTENT, [_anchor()], commitment_level=tier)
    cred = sign_reasoned_action(
        signer,
        intent=INTENT,
        justification=just,
        valid_from=_dt(exec_at),
        sealed_at=_dt(sealed_at) if sealed_at else None,
        credential_id=cred_id,
    )
    reason = verify_intent_freshness(cred, tier, LAST_PULSE, default_requirement(tier))
    return {
        "name": name,
        "tier": tier,
        "last_pulse": LAST_PULSE,
        "interval_seconds": INTERVAL,
        "credential": cred,
        "expected_reason": reason,  # null means accepted
    }


def main():
    signer, raw_pub = _signer()
    ref_just = build_justification(INTENT, [_anchor()], commitment_level=TIER_HIGH)
    vector = {
        "description": (
            "Event-triggered intent recheck. A ReasonedActionCredential carries a "
            "sealedAt timestamp; verify_intent_freshness binds seal freshness to the "
            "action for sensitive tiers. Every SDK must verify the signature, "
            "recompute justification_digest to expected_justification_digest, and "
            "return expected_reason for each case (null == accepted)."
        ),
        "module": "vouch.intent_recheck",
        "spec_reference": "Specification 11.6",
        "version": "1.0",
        "public_key_hex": raw_pub.hex(),
        "did": DID,
        "verification_method": VM,
        "reference_justification": ref_just,
        "expected_justification_digest": justification_digest(ref_just),
        "expected_artifact_digest": artifact_digest(USER_MSG),
        "cases": [
            _case(
                signer,
                "accept_fresh_seal_in_window",
                TIER_HIGH,
                "2026-08-02T10:00:10Z",
                "2026-08-02T10:00:20Z",
                "urn:uuid:00000000-0000-4000-8000-000000000001",
            ),
            _case(
                signer,
                "reject_stale_seal_in_gap",
                TIER_HIGH,
                "2026-08-02T09:59:50Z",
                "2026-08-02T10:00:20Z",
                "urn:uuid:00000000-0000-4000-8000-000000000002",
            ),
            _case(
                signer,
                "accept_non_sensitive_tier",
                TIER_ROUTINE,
                "2026-08-02T09:59:50Z",
                "2026-08-02T10:00:20Z",
                "urn:uuid:00000000-0000-4000-8000-000000000003",
            ),
            _case(
                signer,
                "reject_missing_seal",
                TIER_HIGH,
                None,
                "2026-08-02T10:00:20Z",
                "urn:uuid:00000000-0000-4000-8000-000000000004",
            ),
        ],
    }
    out = Path(__file__).parent / "vector.json"
    out.write_text(json.dumps(vector, indent=2, sort_keys=False) + "\n")
    print(f"wrote {out} ({out.stat().st_size} bytes)")
    for c in vector["cases"]:
        print(f"  {c['name']}: expected_reason={c['expected_reason']!r}")


if __name__ == "__main__":
    main()
