"""
Vouch conformance runner (Phase 1, local).

Runs an implementation against the published conformance levels (Specification
section 17) and reports the highest level it fully satisfies. This local runner
proves the contract against the in-process Python SDK. The hosted verifier (the
conformance worker) reuses the same level map, but issues fresh server-side
challenges so a result cannot be faked by replaying the public test vectors.

Levels are graded on byte-testable plus attested requirements:

  L1 Credential            canonicalization, eddsa-jcs-2022 sign and verify,
                           validity window, nonce replay resistance
  L2 Structural-Security   plus BitstringStatusList revocation, delegation
                           narrowing, the Identity Sidecar allow and deny
                           behaviour, a hash-linked audit trail
  L3 State Verifiable + PQ plus hybrid dual-proof (eddsa-jcs-2022 and
                           mldsa44-jcs-2026), Heartbeat renewal chain, and an
                           M-of-N validator quorum

Robotics is a SEPARATE profile (Robotics Conformant), not part of L1 to L3.

Run it against the reference SDK:

    python -m vouch.conformance
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, List, Tuple

from vouch import jcs, keys
from vouch.nonce import MemoryNonceTracker
from vouch.signer import Signer
from vouch.verifier import Verifier

VECTORS_DIR = Path(__file__).resolve().parent.parent / "test-vectors"


class Status(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"  # contract defined, not yet implemented in this runner


@dataclass
class CheckResult:
    name: str
    status: Status
    detail: str = ""


# --- L1 checks (implemented) ------------------------------------------------


def check_canonicalization() -> CheckResult:
    """RFC 8785 JCS: every shared vector input canonicalizes byte-identically."""
    path = VECTORS_DIR / "jcs" / "vectors.json"
    vectors = json.loads(path.read_text(encoding="utf-8"))["vectors"]
    for vec in vectors:
        got = jcs.canonicalize(vec["input"]).decode("utf-8")
        if got != vec["canonical"]:
            return CheckResult(
                "canonicalization",
                Status.FAIL,
                f"{vec['name']}: expected {vec['canonical']!r}, got {got!r}",
            )
    return CheckResult("canonicalization", Status.PASS, f"{len(vectors)} vectors")


def check_sign_verify() -> CheckResult:
    """eddsa-jcs-2022: a signed credential verifies, a tampered one is rejected."""
    kp = keys.generate_identity("conformance.test")
    signer = Signer(private_key=kp.private_key_jwk, did=kp.did)
    credential = signer.sign_credential(
        intent={
            "action": "conformance_probe",
            "target": "vector:001",
            "resource": "https://conformance.test/probe",
        }
    )
    valid, _ = Verifier.verify_credential(credential, public_key=kp.public_key_jwk)
    if not valid:
        return CheckResult("sign_verify", Status.FAIL, "a valid credential was rejected")

    tampered = json.loads(json.dumps(credential))
    tampered["credentialSubject"]["intent"]["action"] = "tampered"
    bad_valid, _ = Verifier.verify_credential(tampered, public_key=kp.public_key_jwk)
    if bad_valid:
        return CheckResult("sign_verify", Status.FAIL, "a tampered credential was accepted")

    return CheckResult("sign_verify", Status.PASS, "round-trip and tamper rejection")


# A timestamp far enough out that the tracked nonce never expires mid-check.
_NONCE_FAR_FUTURE = 4102444800  # 2100-01-01T00:00:00Z


def check_validity_window() -> CheckResult:
    """Temporal claims: a fresh credential verifies, an expired one is rejected."""
    kp = keys.generate_identity("conformance.test")
    signer = Signer(private_key=kp.private_key_jwk, did=kp.did)
    intent = {
        "action": "conformance_probe",
        "target": "vector:validity",
        "resource": "https://conformance.test/probe",
    }
    fresh = signer.sign_credential(intent=intent, valid_seconds=3600)
    fresh_valid, _ = Verifier.verify_credential(fresh, public_key=kp.public_key_jwk)
    if not fresh_valid:
        return CheckResult("validity_window", Status.FAIL, "a fresh credential was rejected")

    expired = signer.sign_credential(intent=intent, valid_seconds=-3600)
    expired_valid, _ = Verifier.verify_credential(expired, public_key=kp.public_key_jwk)
    if expired_valid:
        return CheckResult("validity_window", Status.FAIL, "an expired credential was accepted")

    return CheckResult("validity_window", Status.PASS, "fresh accepted, expired rejected")


def check_nonce_replay() -> CheckResult:
    """Replay resistance: a credential id seen twice is flagged on the second use."""
    kp = keys.generate_identity("conformance.test")
    signer = Signer(private_key=kp.private_key_jwk, did=kp.did)
    credential = signer.sign_credential(
        intent={
            "action": "conformance_probe",
            "target": "vector:nonce",
            "resource": "https://conformance.test/probe",
        }
    )
    nonce = credential["id"]

    async def present_twice() -> Tuple[bool, bool]:
        tracker = MemoryNonceTracker()
        first = await tracker.is_used(nonce)
        await tracker.mark_used(nonce, expires_at=_NONCE_FAR_FUTURE)
        second = await tracker.is_used(nonce)
        return first, second

    # A dedicated loop we open and close ourselves; unlike asyncio.run() this
    # never calls set_event_loop(None), so it cannot strand async tests that
    # run later in the same process (a Python 3.9 event-loop pitfall).
    loop = asyncio.new_event_loop()
    try:
        first_seen, second_seen = loop.run_until_complete(present_twice())
    finally:
        loop.close()
    if first_seen:
        return CheckResult("nonce_replay", Status.FAIL, "a fresh nonce was reported as used")
    if not second_seen:
        return CheckResult("nonce_replay", Status.FAIL, "a repeated nonce was not detected")
    return CheckResult("nonce_replay", Status.PASS, "first use accepted, replay rejected")


# --- L2 / L3 checks (contract defined, implementation pending) --------------


def _pending(name: str, contract: str) -> Callable[[], CheckResult]:
    def run() -> CheckResult:
        return CheckResult(name, Status.SKIP, contract)

    return run


# The level contract: each level lists (check name, callable). A level is
# granted only when every check at that level and all lower levels passes.
LEVELS: Dict[str, List[Tuple[str, Callable[[], CheckResult]]]] = {
    "L1": [
        ("canonicalization", check_canonicalization),
        ("sign_verify", check_sign_verify),
        ("validity_window", check_validity_window),
        ("nonce_replay", check_nonce_replay),
    ],
    "L2": [
        (
            "revocation",
            _pending(
                "revocation",
                "A BitstringStatusList with the credential's bit set verifies as revoked.",
            ),
        ),
        (
            "delegation_narrowing",
            _pending(
                "delegation_narrowing",
                "A delegated credential narrows its parent and honours the five-link depth bound.",
            ),
        ),
        (
            "sidecar_allow_deny",
            _pending(
                "sidecar_allow_deny",
                "Behavioural: an allowed intent signs, a disallowed intent is rejected with a structured code.",
            ),
        ),
        (
            "audit_trail",
            _pending(
                "audit_trail",
                "A sequence of actions produces a valid hash-linked audit trail.",
            ),
        ),
    ],
    "L3": [
        (
            "hybrid_pq",
            _pending(
                "hybrid_pq",
                "Dual-proof: both eddsa-jcs-2022 and mldsa44-jcs-2026 proofs over the same JCS bytes verify.",
            ),
        ),
        (
            "heartbeat",
            _pending(
                "heartbeat",
                "Behavioural: a renewed heartbeat chain is valid, hash-linked, and within interval.",
            ),
        ),
        (
            "validator_quorum",
            _pending(
                "validator_quorum",
                "Attested: an M-of-N quorum-signed digest verifies against the threshold.",
            ),
        ),
    ],
}


@dataclass
class ConformanceReport:
    results: Dict[str, List[CheckResult]]
    achieved: str | None  # highest fully-passing level, or None


def run_conformance() -> ConformanceReport:
    """Run every level's checks and derive the highest fully-passing level."""
    results: Dict[str, List[CheckResult]] = {}
    achieved: str | None = None
    blocked = False

    for level, checks in LEVELS.items():
        level_results: List[CheckResult] = []
        for name, fn in checks:
            try:
                level_results.append(fn())
            except Exception as exc:  # a crash is a failed check, not a runner crash
                level_results.append(CheckResult(name, Status.FAIL, f"error: {exc}"))
        results[level] = level_results

        if not blocked and all(r.status is Status.PASS for r in level_results):
            achieved = level
        else:
            blocked = True

    return ConformanceReport(results=results, achieved=achieved)


def _print_report(report: ConformanceReport) -> None:
    glyph = {Status.PASS: "PASS", Status.FAIL: "FAIL", Status.SKIP: "....."}
    for level, level_results in report.results.items():
        print(f"\n{level}")
        for r in level_results:
            print(f"  [{glyph[r.status]}] {r.name}: {r.detail}")
    print(f"\nHighest fully-passing level: {report.achieved or 'none yet'}")
    print("(..... = contract defined, implementation pending in this runner)")


if __name__ == "__main__":
    _print_report(run_conformance())
