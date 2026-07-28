"""
Generate the shared Authority Freshness interop vector.

Python is the source of truth. The Rust core, the TypeScript SDK, and the Go
sidecar MUST:

  1. Reproduce `proofValue` exactly from (ed25519.seed_b64, unsigned_credential,
     verificationMethod, created). Ed25519, JCS, and SHA-256 are deterministic,
     so the AuthorityState proof is reproducible byte-for-byte.
  2. Verify `signed_credential` against ed25519.public_key_b64.
  3. Run `evaluate_authority_freshness` for each freshness case and match the
     expected allow/reason, proving the collapse rule is identical across
     languages.

Run from the repo root:  python test-vectors/authority-state/generate.py
"""

import base64
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from vouch import data_integrity
from vouch.authority_state import build_authority_state

# Fixed 32-byte Ed25519 seed (test material only, never for production): the
# same all-zero-but-last-byte seed the eddsa-jcs-2022 vector uses.
SEED = bytes([0] * 31 + [1])

ISSUER_DID = "did:web:treasury.example.com"
VERIFICATION_METHOD = f"{ISSUER_DID}#key-1"
CREATED = "2026-07-26T10:00:00Z"
VALID_FROM = "2026-07-26T10:00:00Z"
VALID_UNTIL = "2026-07-26T10:05:00Z"
CREDENTIAL_ID = "urn:uuid:11111111-1111-4111-8111-111111111111"
AUTHORITY_EPOCH = 5


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def main() -> None:
    priv = Ed25519PrivateKey.from_private_bytes(SEED)
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    unsigned = build_authority_state(
        ISSUER_DID,
        AUTHORITY_EPOCH,
        status="active",
        valid_from=datetime.fromisoformat(VALID_FROM.replace("Z", "+00:00")),
        credential_id=CREDENTIAL_ID,
    )
    # Pin validUntil so the vector is fully deterministic.
    unsigned["validUntil"] = VALID_UNTIL

    created_dt = datetime.fromisoformat(CREATED.replace("Z", "+00:00")).astimezone(timezone.utc)
    proof = data_integrity.build_proof(unsigned, priv, VERIFICATION_METHOD, created=created_dt)
    signed = dict(unsigned)
    signed["proof"] = proof

    # The collapse rule. Each case is (tier, voucher_epoch, last_seen_epoch,
    # current_status, live_cosign_ok) -> (allow, reason). A verifier in any
    # language must reach the same verdict.
    freshness_cases = [
        {
            "name": "routine_ignores_stale_epoch",
            "tier": "routine",
            "voucher_epoch": 5,
            "last_seen_epoch": 9,
            "current_status": None,
            "live_cosign_ok": None,
            "expected_allow": True,
        },
        {
            "name": "sensitive_allows_current_epoch",
            "tier": "sensitive",
            "voucher_epoch": 9,
            "last_seen_epoch": 9,
            "current_status": None,
            "live_cosign_ok": None,
            "expected_allow": True,
        },
        {
            "name": "sensitive_rejects_stale_epoch",
            "tier": "sensitive",
            "voucher_epoch": 5,
            "last_seen_epoch": 9,
            "current_status": None,
            "live_cosign_ok": None,
            "expected_allow": False,
            "expected_reason": "authority_epoch_stale:seen=9,voucher=5",
        },
        {
            "name": "suspended_status_fails_closed",
            "tier": "sensitive",
            "voucher_epoch": 9,
            "last_seen_epoch": 9,
            "current_status": "suspended",
            "live_cosign_ok": None,
            "expected_allow": False,
            "expected_reason": "authority_status_not_active:status=suspended",
        },
        {
            # An absent epoch renders as "?" in every language, so this reason
            # code is byte-identical across Python, Rust, TypeScript, and Go.
            "name": "sensitive_rejects_unknown_voucher_epoch",
            "tier": "sensitive",
            "voucher_epoch": None,
            "last_seen_epoch": 9,
            "current_status": None,
            "live_cosign_ok": None,
            "expected_allow": False,
            "expected_reason": "authority_epoch_unknown:voucher=?,seen=9",
        },
        {
            "name": "sensitive_rejects_unknown_last_seen_epoch",
            "tier": "sensitive",
            "voucher_epoch": 5,
            "last_seen_epoch": None,
            "current_status": None,
            "live_cosign_ok": None,
            "expected_allow": False,
            "expected_reason": "authority_epoch_unknown:voucher=5,seen=?",
        },
        {
            "name": "critical_requires_live_cosign",
            "tier": "critical",
            "voucher_epoch": 9,
            "last_seen_epoch": 9,
            "current_status": None,
            "live_cosign_ok": None,
            "expected_allow": False,
            "expected_reason": "live_cosign_required:tier=critical",
        },
        {
            "name": "critical_allows_with_live_cosign",
            "tier": "critical",
            "voucher_epoch": 9,
            "last_seen_epoch": 9,
            "current_status": None,
            "live_cosign_ok": True,
            "expected_allow": True,
        },
    ]

    vector = {
        "description": (
            "Shared Authority Freshness interop vector. Reproduce proofValue "
            "byte-for-byte from (ed25519.seed_b64, unsigned_credential, "
            "verificationMethod, created); verify signed_credential against "
            "ed25519.public_key_b64; and evaluate every freshness case to the "
            "same allow/reason. This proves the AuthorityState credential and "
            "the epoch-collapse rule are identical across the Rust core, the "
            "TypeScript SDK, the Go sidecar, and Python."
        ),
        "cryptosuite": "eddsa-jcs-2022",
        "ed25519": {"seed_b64": _b64(SEED), "public_key_b64": _b64(pub)},
        "verificationMethod": VERIFICATION_METHOD,
        "created": CREATED,
        "unsigned_credential": unsigned,
        "signed_credential": signed,
        "proofValue": proof["proofValue"],
        "freshness": {
            "description": (
                "evaluate_authority_freshness(tier, voucher_epoch, "
                "last_seen_epoch, current_status, live_cosign_ok) -> "
                "(allow, reason)"
            ),
            "cases": freshness_cases,
        },
    }

    out = Path(__file__).resolve().parent / "vector.json"
    out.write_text(json.dumps(vector, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
