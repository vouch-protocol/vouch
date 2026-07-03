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

from vouch import jcs, keys, vc
from vouch.audit_trail import AuditTrail, verify_entries
from vouch.gate import CredentialGate
from vouch.heartbeat import HeartbeatSession, HeartbeatValidator
from vouch.nonce import MemoryNonceTracker
from vouch.quorum import HeartbeatQuorum, QuorumValidator
from vouch.signer import Signer
from vouch.status_list import (
    StatusList,
    build_status_list_credential,
    build_status_list_entry,
    verify_status,
)
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


# --- L2 checks (Structural-Security) ----------------------------------------


def check_revocation() -> CheckResult:
    """BitstringStatusList: a set status bit reads as revoked, a clear bit reads as active."""
    status_list = StatusList(status_list_id="https://conformance.test/status/1")
    revoked_index = status_list.allocate_index()
    active_index = status_list.allocate_index()
    status_list.revoke(revoked_index)
    status_list_credential = build_status_list_credential(
        issuer_did="did:web:conformance.test",
        status_list=status_list,
    )
    revoked_entry = build_status_list_entry(
        status_list_credential="https://conformance.test/status/1",
        status_list_index=revoked_index,
    )
    active_entry = build_status_list_entry(
        status_list_credential="https://conformance.test/status/1",
        status_list_index=active_index,
    )
    if not verify_status(
        credential_status=revoked_entry, status_list_credential=status_list_credential
    ):
        return CheckResult(
            "revocation", Status.FAIL, "a revoked credential did not read as revoked"
        )
    if verify_status(credential_status=active_entry, status_list_credential=status_list_credential):
        return CheckResult("revocation", Status.FAIL, "an active credential read as revoked")
    return CheckResult("revocation", Status.PASS, "set bit reads revoked, clear bit reads active")


def check_delegation_narrowing() -> CheckResult:
    """Delegation: a child chains to its parent, and the five-link depth bound is enforced."""
    root = keys.generate_identity("conformance.test")
    root_signer = Signer(private_key=root.private_key_jwk, did=root.did)
    parent = root_signer.sign_credential(
        intent={
            "action": "manage",
            "target": "all_tables",
            "resource": "https://conformance.test/db",
        }
    )
    child_id = keys.generate_identity("conformance.test")
    child_signer = Signer(private_key=child_id.private_key_jwk, did=child_id.did)
    child = child_signer.sign_credential(
        intent={
            "action": "read",
            "target": "users_table",
            "resource": "https://conformance.test/db/users",
        },
        parent_credential=parent,
    )
    chain = child.get("credentialSubject", {}).get("delegationChain") or []
    if len(chain) != 1 or chain[0].get("issuer") != root.did:
        return CheckResult(
            "delegation_narrowing",
            Status.FAIL,
            "the child did not record its parent in the delegation chain",
        )

    # Extend the chain link by link; the depth bound must reject a further link.
    current = parent
    depth_enforced = False
    for _ in range(8):
        link_id = keys.generate_identity("conformance.test")
        link_signer = Signer(private_key=link_id.private_key_jwk, did=link_id.did)
        try:
            current = link_signer.sign_credential(
                intent={
                    "action": "read",
                    "target": "users_table",
                    "resource": "https://conformance.test/db/users",
                },
                parent_credential=current,
            )
        except ValueError:
            depth_enforced = True
            break
    if not depth_enforced:
        return CheckResult(
            "delegation_narrowing", Status.FAIL, "the five-link depth bound was not enforced"
        )
    return CheckResult(
        "delegation_narrowing", Status.PASS, "child chains to parent, depth bound enforced"
    )


def check_sidecar_allow_deny() -> CheckResult:
    """Identity Sidecar: an allowed intent passes the gate, a disallowed one is rejected with a reason."""
    ident = keys.generate_identity("conformance.test")
    signer = Signer(private_key=ident.private_key_jwk, did=ident.did)
    credential = signer.sign_credential(
        intent={
            "action": "read",
            "target": "data",
            "resource": "https://conformance.test/data",
        }
    )
    allow_gate = CredentialGate(
        public_key=ident.public_key_jwk, require_action="read", allow_did_resolution=False
    )
    allowed = allow_gate.check(credential)
    if not allowed.ok:
        return CheckResult(
            "sidecar_allow_deny", Status.FAIL, f"an allowed intent was rejected: {allowed.reason}"
        )

    deny_gate = CredentialGate(
        public_key=ident.public_key_jwk, require_action="write", allow_did_resolution=False
    )
    denied = deny_gate.check(credential)
    if denied.ok:
        return CheckResult("sidecar_allow_deny", Status.FAIL, "a disallowed intent was allowed")
    if not denied.reason:
        return CheckResult(
            "sidecar_allow_deny", Status.FAIL, "a rejection carried no structured reason"
        )
    return CheckResult(
        "sidecar_allow_deny",
        Status.PASS,
        "allowed intent passes, disallowed rejected with a reason",
    )


def check_audit_trail() -> CheckResult:
    """Audit trail: a sequence of actions is hash-linked and verifies, and a tampered entry is caught."""
    trail = AuditTrail()
    trail.append(action="ALLOWED", actor="did:web:conformance.test", resource="read_file")
    trail.append(
        action="BLOCKED",
        actor="did:web:conformance.test",
        resource="run_command",
        decision="untrusted",
    )
    trail.append(action="ALLOWED", actor="did:web:conformance.test", resource="write_file")

    ok, broken = trail.verify()
    if not ok or broken is not None:
        return CheckResult(
            "audit_trail", Status.FAIL, f"a valid trail failed verification (broken={broken})"
        )

    entries = trail.entries
    if (
        entries[1].prev_hash != entries[0].entry_hash
        or entries[2].prev_hash != entries[1].entry_hash
    ):
        return CheckResult("audit_trail", Status.FAIL, "entries are not hash-linked")

    entries[1].resource = "exfiltrate_secrets"
    bad_ok, bad_broken = verify_entries(entries)
    if bad_ok or bad_broken is None:
        return CheckResult("audit_trail", Status.FAIL, "a tampered trail was not caught")
    return CheckResult("audit_trail", Status.PASS, "hash-linked, verifies, tamper detected")


# --- L3 checks (State Verifiable + Post-Quantum) ----------------------------


def check_hybrid_pq() -> CheckResult:
    """Hybrid dual-proof: a credential carrying eddsa-jcs-2022 and mldsa44 proofs verifies under both."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from vouch.data_integrity_hybrid import (
            build_hybrid_proof,
            generate_mldsa44_keypair,
            verify_hybrid_proof,
        )
    except ImportError as exc:  # post-quantum support is optional at runtime
        return CheckResult("hybrid_pq", Status.SKIP, f"post-quantum support unavailable: {exc}")

    ed_priv = Ed25519PrivateKey.generate()
    ed_pub = ed_priv.public_key()
    ml_pub, ml_sec = generate_mldsa44_keypair()
    credential = vc.build_vouch_credential(
        issuer_did="did:web:conformance.test",
        intent={
            "action": "conformance_probe",
            "target": "vector:hybrid",
            "resource": "https://conformance.test/probe",
        },
    )
    credential["proof"] = build_hybrid_proof(
        credential,
        ed25519_private_key=ed_priv,
        mldsa44_secret_key=ml_sec,
        verification_method="did:web:conformance.test#key-1",
    )
    if credential["proof"].get("cryptosuite") != "hybrid-eddsa-mldsa44-jcs-2026":
        return CheckResult("hybrid_pq", Status.FAIL, "the proof is not the hybrid cryptosuite")
    if not verify_hybrid_proof(credential, ed25519_public_key=ed_pub, mldsa44_public_key=ml_pub):
        return CheckResult("hybrid_pq", Status.FAIL, "both proofs did not verify")

    tampered = json.loads(json.dumps(credential))
    tampered["credentialSubject"]["intent"]["action"] = "tampered"
    if verify_hybrid_proof(tampered, ed25519_public_key=ed_pub, mldsa44_public_key=ml_pub):
        return CheckResult("hybrid_pq", Status.FAIL, "a tampered hybrid credential verified")
    return CheckResult("hybrid_pq", Status.PASS, "eddsa-jcs-2022 and mldsa44 proofs both verify")


def check_heartbeat() -> CheckResult:
    """Heartbeat: a renewed chain validates, and each interval is distinct and advancing."""
    session = HeartbeatSession(subject_did="did:web:conformance.test")
    validator = HeartbeatValidator(validator_did="did:web:validator.conformance.test")

    session.record_action(b"conformance-1")
    req1 = session.build_request()
    r1 = validator.validate(req1.to_dict())
    if not r1.ok:
        return CheckResult(
            "heartbeat", Status.FAIL, f"the first heartbeat was rejected: {r1.reasons}"
        )

    session.record_action(b"conformance-2")
    req2 = session.build_request()
    r2 = validator.validate(req2.to_dict())
    if not r2.ok:
        return CheckResult(
            "heartbeat", Status.FAIL, f"a renewed heartbeat was rejected: {r2.reasons}"
        )

    if req1.interval_index != 0 or req2.interval_index != 1:
        return CheckResult("heartbeat", Status.FAIL, "the interval index did not advance")
    if req1.action_merkle_root == req2.action_merkle_root:
        return CheckResult("heartbeat", Status.FAIL, "consecutive intervals were not distinct")
    return CheckResult(
        "heartbeat", Status.PASS, "renewal chain valid, intervals linked and advancing"
    )


def check_validator_quorum() -> CheckResult:
    """Validator quorum: an M-of-N quorum approves at threshold, and denies when fewer approve."""
    session = HeartbeatSession(subject_did="did:web:conformance.test")
    session.record_action(b"conformance-quorum")
    request = session.build_request().to_dict()

    def make_validators() -> List[HeartbeatValidator]:
        return [
            HeartbeatValidator(validator_did=f"did:web:v{i}.conformance.test") for i in range(3)
        ]

    # Met: two of three is enough, and all three approve a fresh request.
    met = HeartbeatQuorum(
        validators=[QuorumValidator(validator=v) for v in make_validators()],
        threshold=2,
    )
    met_result = met.validate(request)
    if not met_result.ok or met_result.votes_for < 2:
        return CheckResult("validator_quorum", Status.FAIL, "a met quorum was not approved")

    # Denied: require all three, but pre-seed one validator so it rejects the
    # replayed interval as stale, leaving only two approvals under a threshold of three.
    validators = make_validators()
    validators[0].validate(request)
    denied = HeartbeatQuorum(
        validators=[QuorumValidator(validator=v) for v in validators],
        threshold=3,
    )
    denied_result = denied.validate(request)
    if denied_result.ok:
        return CheckResult("validator_quorum", Status.FAIL, "a quorum below threshold was approved")
    return CheckResult(
        "validator_quorum", Status.PASS, "approves at threshold, denies below threshold"
    )


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
        ("revocation", check_revocation),
        ("delegation_narrowing", check_delegation_narrowing),
        ("sidecar_allow_deny", check_sidecar_allow_deny),
        ("audit_trail", check_audit_trail),
    ],
    "L3": [
        ("hybrid_pq", check_hybrid_pq),
        ("heartbeat", check_heartbeat),
        ("validator_quorum", check_validator_quorum),
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
