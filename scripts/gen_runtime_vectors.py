#!/usr/bin/env python3
"""
Canonical test-vector generator for the six Vouch runtime modules.

This is the upstream piece the runtime-module ports (issues #94 through #105)
build against. Each port adds a Go / TypeScript implementation of one module and
must reproduce ``test-vectors/<module>/vector.json`` byte-for-byte. Python is the
source of truth: this single harness imports each module, drives it with fixed
inputs, and writes a deterministic vector file.

Covered modules (each maps to ``vouch/<module>.py``):

  trust_entropy           - time-decaying trust computation (Specification 11.5)
  quorum                  - M-of-N validator coordination (Specification 11.6)
  merkle                  - Merkle tree + inclusion proofs (Specification 11.3)
  canary                  - commit/reveal canary chain (Specification 11.7)
  behavioral_attestation  - per-interval behavioural digest (Specification 11.3)
  heartbeat               - heartbeat request + validation (Specification 11.3)

Determinism
-----------
Every source of non-determinism is pinned by the ``pinned()`` context manager:

  * Wall-clock in trust_entropy / heartbeat is supplied explicitly via the
    ``at_time`` / ``now`` parameters those APIs already accept.
  * ``os.urandom`` (canary secrets) is replaced by a counter-driven function so
    the nth call returns the single byte ``(n + 1)`` repeated to the requested
    length. The counter resets every time ``pinned()`` is entered, so each
    builder is generated independently of the others' execution order.
  * ``build_session_voucher`` (vouch/vc.py) reads ``datetime.now`` and a random
    UUID; both are pinned so heartbeat and quorum vouchers are fully reproducible.
  * ``behavioral_attestation._now_ns`` is pinned for the audit samples (it never
    feeds ``digest()``, but pinning keeps any captured sample stable).

Run ``python scripts/gen_runtime_vectors.py`` to (re)write all six files.
``tests/test_runtime_vectors.py`` regenerates each vector in memory under the same
``pinned()`` context and asserts byte-for-byte equality, so CI catches any drift.
"""

from __future__ import annotations

import base64
import contextlib
import itertools
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from vouch import behavioral_attestation as ba
from vouch import canary as canary_mod
from vouch import heartbeat as hb
from vouch import merkle as merkle_mod
from vouch import quorum as quorum_mod
from vouch import trust_entropy as te

# ---------------------------------------------------------------------------
# Pinned constants
# ---------------------------------------------------------------------------

FIXED_NOW = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
FIXED_NOW_ISO = "2026-01-01T00:00:00Z"
FIXED_NOW_NS = int(FIXED_NOW.timestamp()) * 1_000_000_000
FIXED_URN = "urn:uuid:00000000-0000-4000-8000-000000000001"

VECTOR_ROOT = Path(__file__).resolve().parent.parent / "test-vectors"

OS_URANDOM_RULE = (
    "os.urandom is pinned: the nth call (0-indexed) returns the single byte "
    "(n + 1) repeated to the requested length. The counter resets per vector."
)


class _PinnedDateTime(datetime):
    """datetime subclass whose now() is fixed; arithmetic stays intact."""

    @classmethod
    def now(cls, tz=None):  # noqa: A003 - mirrors datetime.now signature
        if tz is None:
            return FIXED_NOW
        return FIXED_NOW.astimezone(tz)


def _pinned_secret(index: int, size: int) -> bytes:
    return bytes([(index + 1) % 256]) * size


@contextlib.contextmanager
def pinned():
    """Pin every non-deterministic input for the duration of one vector build."""
    counter = itertools.count()

    def fake_urandom(size: int) -> bytes:
        return _pinned_secret(next(counter), size)

    # ExitStack (not a parenthesised `with`) so this parses on Python 3.9, which
    # the CI matrix still runs; parenthesised context managers are 3.10+ grammar.
    with contextlib.ExitStack() as stack:
        stack.enter_context(mock.patch("os.urandom", side_effect=fake_urandom))
        stack.enter_context(mock.patch("vouch.vc._new_uuid_urn", return_value=FIXED_URN))
        stack.enter_context(mock.patch("vouch.vc.datetime", _PinnedDateTime))
        stack.enter_context(
            mock.patch("vouch.behavioral_attestation._now_ns", return_value=FIXED_NOW_NS)
        )
        yield


# ---------------------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------------------


def _multibase(b: bytes) -> str:
    """Multibase base64url-no-pad (prefix 'u'), as the modules emit byte values."""
    return "u" + base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Per-module builders
# ---------------------------------------------------------------------------


def _session_voucher(initial_trust: float, decay_lambda: float) -> dict:
    return {
        "type": ["VerifiableCredential", "SessionVoucher"],
        "validFrom": FIXED_NOW_ISO,
        "credentialSubject": {
            "id": "did:web:agent.example.com",
            "initialTrust": initial_trust,
            "decayLambda": decay_lambda,
        },
    }


def build_trust_entropy_vector() -> dict:
    cases = []

    base = _session_voucher(1.0, 0.01)
    for elapsed in (0, 60, 100, 600, 3600):
        at = FIXED_NOW + timedelta(seconds=elapsed)
        cases.append(
            {
                "name": f"compute_trust_at_elapsed_{elapsed}s",
                "function": "compute_trust_at",
                "input": {"session_voucher": base, "at_time": _iso(at)},
                "expected": {"trust": te.compute_trust_at(base, at)},
            }
        )

    overflow = _session_voucher(1.0, 1.0)
    at_overflow = FIXED_NOW + timedelta(seconds=1000)
    cases.append(
        {
            "name": "compute_trust_at_overflow_guard_returns_zero",
            "function": "compute_trust_at",
            "input": {"session_voucher": overflow, "at_time": _iso(at_overflow)},
            "expected": {"trust": te.compute_trust_at(overflow, at_overflow)},
        }
    )

    pass_voucher = _session_voucher(1.0, 0.01)
    at_eval = FIXED_NOW + timedelta(seconds=100)
    cases.append(
        {
            "name": "evaluate_trust_passes_low_threshold",
            "function": "evaluate_trust",
            "input": {"session_voucher": pass_voucher, "threshold": 0.3, "at_time": _iso(at_eval)},
            "expected": te.evaluate_trust(pass_voucher, 0.3, at_eval).to_dict(),
        }
    )
    cases.append(
        {
            "name": "evaluate_trust_fails_high_threshold",
            "function": "evaluate_trust",
            "input": {"session_voucher": pass_voucher, "threshold": 0.5, "at_time": _iso(at_eval)},
            "expected": te.evaluate_trust(pass_voucher, 0.5, at_eval).to_dict(),
        }
    )

    for lam in (0.01, 0.1):
        cases.append(
            {
                "name": f"half_life_seconds_lambda_{lam}",
                "function": "half_life_seconds",
                "input": {"decay_lambda": lam},
                "expected": {"half_life_seconds": te.half_life_seconds(lam)},
            }
        )

    reachable = _session_voucher(1.0, 0.01)
    tut = te.time_until_threshold(reachable, 0.5, FIXED_NOW)
    cases.append(
        {
            "name": "time_until_threshold_reachable",
            "function": "time_until_threshold",
            "input": {"session_voucher": reachable, "threshold": 0.5, "from_time": FIXED_NOW_ISO},
            "expected": {"seconds": tut.total_seconds() if tut is not None else None},
        }
    )
    above = te.time_until_threshold(reachable, 2.0, FIXED_NOW)
    cases.append(
        {
            "name": "time_until_threshold_above_initial_is_zero",
            "function": "time_until_threshold",
            "input": {"session_voucher": reachable, "threshold": 2.0, "from_time": FIXED_NOW_ISO},
            "expected": {"seconds": above.total_seconds() if above is not None else None},
        }
    )
    constant = _session_voucher(1.0, 0.0)
    never = te.time_until_threshold(constant, 0.5, FIXED_NOW)
    cases.append(
        {
            "name": "time_until_threshold_zero_lambda_is_none",
            "function": "time_until_threshold",
            "input": {"session_voucher": constant, "threshold": 0.5, "from_time": FIXED_NOW_ISO},
            "expected": {"seconds": never.total_seconds() if never is not None else None},
        }
    )

    return {
        "description": (
            "Trust-entropy decay vectors (Specification 11.5). trust(t) = "
            "initialTrust * exp(-decayLambda * (t - validFrom)). Each case pins "
            "at_time / from_time explicitly so the wall-clock default is never used. "
            "Floats are the Python source-of-truth values; cross-language ports "
            "comparing exp() results should allow a small tolerance (see README)."
        ),
        "module": "vouch.trust_entropy",
        "spec_reference": "Specification 11.5",
        "version": "1.0",
        "pinned": {"now": FIXED_NOW_ISO},
        "cases": cases,
    }


def build_merkle_vector() -> dict:
    leaves = [b"action-0", b"action-1", b"action-2"]
    leaves_utf8 = [x.decode("ascii") for x in leaves]

    left = merkle_mod.hash_leaf(b"action-0")
    right = merkle_mod.hash_leaf(b"action-1")
    tree = merkle_mod.MerkleTree(leaves=list(leaves))
    proof = tree.proof(1)

    cases = [
        {
            "name": "hash_leaf_empty",
            "function": "hash_leaf",
            "input": {"utf8": ""},
            "expected": {"hash_hex": merkle_mod.hash_leaf(b"").hex()},
        },
        {
            "name": "hash_leaf_action0",
            "function": "hash_leaf",
            "input": {"utf8": "action-0"},
            "expected": {"hash_hex": merkle_mod.hash_leaf(b"action-0").hex()},
        },
        {
            "name": "hash_node",
            "function": "hash_node",
            "input": {"left_hex": left.hex(), "right_hex": right.hex()},
            "expected": {"hash_hex": merkle_mod.hash_node(left, right).hex()},
        },
        {
            "name": "merkle_root_three_leaves",
            "function": "MerkleTree.root",
            "input": {"leaves_utf8": leaves_utf8},
            "expected": {"root_multibase": tree.root_multibase(), "root_hex": tree.root().hex()},
        },
        {
            "name": "inclusion_proof_leaf_1_verifies",
            "function": "MerkleTree.proof + verify_inclusion",
            "input": {"leaves_utf8": leaves_utf8, "leaf_index": 1},
            "expected": {
                "proof": proof.to_dict(),
                "verifies": merkle_mod.verify_inclusion(
                    leaf=leaves[1], proof=proof, root=tree.root()
                ),
            },
        },
        {
            "name": "inclusion_proof_wrong_leaf_fails",
            "function": "verify_inclusion",
            "input": {"leaf_utf8": "not-in-tree", "proof": proof.to_dict(), "leaf_index": 1},
            "expected": {
                "verifies": merkle_mod.verify_inclusion(
                    leaf=b"not-in-tree", proof=proof, root=tree.root()
                )
            },
        },
        {
            "name": "action_merkle_root_empty",
            "function": "compute_action_merkle_root",
            "input": {"actions_utf8": []},
            "expected": {"root_multibase": merkle_mod.compute_action_merkle_root([])},
        },
        {
            "name": "action_merkle_root_populated",
            "function": "compute_action_merkle_root",
            "input": {"actions_utf8": leaves_utf8},
            "expected": {"root_multibase": merkle_mod.compute_action_merkle_root(list(leaves))},
        },
    ]

    return {
        "description": (
            "Merkle tree vectors (Specification 11.3, RFC 6962 domain separation). "
            "Leaves are UTF-8 byte strings; raw 32-byte hashes are hex, the tree "
            "root and proof siblings are multibase base64url-no-pad (prefix 'u'). "
            "The three-leaf case exercises odd-level duplication."
        ),
        "module": "vouch.merkle",
        "spec_reference": "Specification 11.3",
        "version": "1.0",
        "cases": cases,
    }


def build_canary_vector() -> dict:
    secret_a = bytes([0xA1]) * 32
    commitment_a = canary_mod.compute_commitment(secret_a)
    revealed_a = _multibase(secret_a)
    commitment_other = canary_mod.compute_commitment(bytes([0xB2]) * 32)

    chain = canary_mod.CanaryChain()
    heartbeats = [chain.next_heartbeat().to_dict() for _ in range(3)]

    verifier = canary_mod.CanaryVerifier()
    wrong_reveal = _multibase(bytes([0xFF]) * 32)
    observations = [
        {
            "commitment": heartbeats[0]["canaryCommitment"],
            "reveal": heartbeats[0].get("canaryReveal"),
        },
        {
            "commitment": heartbeats[1]["canaryCommitment"],
            "reveal": heartbeats[1].get("canaryReveal"),
        },
        {"commitment": heartbeats[2]["canaryCommitment"], "reveal": wrong_reveal},
    ]
    results = [verifier.observe(o["commitment"], o["reveal"]) for o in observations]

    cases = [
        {
            "name": "compute_commitment",
            "function": "compute_commitment",
            "input": {"secret_b64": _b64(secret_a)},
            "expected": {"commitment": commitment_a},
        },
        {
            "name": "verify_reveal_match",
            "function": "verify_reveal",
            "input": {"revealed": revealed_a, "prior_commitment": commitment_a},
            "expected": {"matches": canary_mod.verify_reveal(revealed_a, commitment_a)},
        },
        {
            "name": "verify_reveal_mismatch",
            "function": "verify_reveal",
            "input": {"revealed": revealed_a, "prior_commitment": commitment_other},
            "expected": {"matches": canary_mod.verify_reveal(revealed_a, commitment_other)},
        },
        {
            "name": "canary_chain_three_intervals",
            "function": "CanaryChain.next_heartbeat",
            "input": {"secret_bytes": 32, "intervals": 3},
            "expected": {"heartbeats": heartbeats},
        },
        {
            "name": "canary_verifier_intact_then_broken",
            "function": "CanaryVerifier.observe",
            "input": {"observations": observations},
            "expected": {"results": results},
        },
    ]

    return {
        "description": (
            "Canary commit/reveal chain vectors (Specification 11.7). Commitments "
            "and reveals are multibase base64url-no-pad (prefix 'u'). The chain "
            "case advances three intervals with pinned secrets; the verifier case "
            "stays intact for two heartbeats then rejects a non-matching reveal."
        ),
        "module": "vouch.canary",
        "spec_reference": "Specification 11.7",
        "version": "1.0",
        "pinned": {"os_urandom": OS_URANDOM_RULE},
        "cases": cases,
    }


def build_behavioral_attestation_vector() -> dict:
    api_calls = [
        {
            "endpoint": "https://api.example.com/orders",
            "tokens": 120,
            "resource": "order:1",
            "drift": 0.1,
        },
        {
            "endpoint": "https://api.example.com/orders",
            "tokens": 80,
            "resource": "order:1",
            "drift": 0.2,
        },
        {
            "endpoint": "https://api.example.com/users",
            "tokens": 50,
            "resource": "user:7",
            "drift": 0.0,
        },
    ]
    resource_accesses = ["config:flags"]
    drift_samples = [0.3]

    collector = ba.BehavioralCollector()
    for call in api_calls:
        collector.record_api_call(
            call["endpoint"], tokens=call["tokens"], resource=call["resource"], drift=call["drift"]
        )
    for resource in resource_accesses:
        collector.record_resource_access(resource)
    for sample in drift_samples:
        collector.record_drift_sample(sample)
    digest = collector.digest()

    scorer_samples = [0.1, 0.2, 0.0, 0.3]
    ewma = ba.ewma_drift_scorer(alpha=0.3)

    invalid_digests = [
        {"apiCalls": -1, "tokensConsumed": 0, "resourcesAccessed": [], "intentDriftScore": 0.0},
        {"apiCalls": 1, "tokensConsumed": 0, "resourcesAccessed": [], "intentDriftScore": 1.5},
        {"apiCalls": 1, "tokensConsumed": 0, "resourcesAccessed": []},
    ]

    cases = [
        {
            "name": "digest_from_recorded_signals",
            "function": "BehavioralCollector.digest",
            "input": {
                "api_calls": api_calls,
                "resource_accesses": resource_accesses,
                "drift_samples": drift_samples,
            },
            "expected": {"digest": digest},
        },
        {
            "name": "mean_drift_scorer",
            "function": "mean_drift_scorer",
            "input": {"samples": scorer_samples},
            "expected": {"score": ba.mean_drift_scorer(scorer_samples)},
        },
        {
            "name": "max_drift_scorer",
            "function": "max_drift_scorer",
            "input": {"samples": scorer_samples},
            "expected": {"score": ba.max_drift_scorer(scorer_samples)},
        },
        {
            "name": "ewma_drift_scorer_alpha_0.3",
            "function": "ewma_drift_scorer",
            "input": {"alpha": 0.3, "samples": scorer_samples},
            "expected": {"score": ewma(scorer_samples)},
        },
        {
            "name": "validate_behavioral_digest_valid",
            "function": "validate_behavioral_digest",
            "input": {"digest": digest},
            "expected": {"valid": True},
        },
    ]

    for i, bad in enumerate(invalid_digests):
        try:
            ba.validate_behavioral_digest(bad)
            valid = True
        except ba.BehavioralAttestationError:
            valid = False
        cases.append(
            {
                "name": f"validate_behavioral_digest_invalid_{i}",
                "function": "validate_behavioral_digest",
                "input": {"digest": bad},
                "expected": {"valid": valid},
            }
        )

    return {
        "description": (
            "Behavioural-attestation digest vectors (Specification 11.3). digest() "
            "aggregates recorded signals (apiCalls, tokensConsumed, resourcesAccessed, "
            "intentDriftScore=mean of drift samples). The scorer cases pin the three "
            "reference aggregators; the validate cases give one valid and three "
            "invalid digests (validate raises on the invalid ones)."
        ),
        "module": "vouch.behavioral_attestation",
        "spec_reference": "Specification 11.3",
        "version": "1.0",
        "cases": cases,
    }


def _heartbeat_session(session_id: str) -> hb.HeartbeatSession:
    collector = ba.BehavioralCollector()
    collector.record_api_call(
        "https://api.example.com/orders", tokens=100, resource="order:1", drift=0.05
    )
    session = hb.HeartbeatSession(
        subject_did="did:web:agent.example.com", session_id=session_id, collector=collector
    )
    session.record_action(b"submit_claim:HC-001")
    session.record_action(b"read:order:1")
    return session


def build_heartbeat_vector() -> dict:
    session_id = "urn:uuid:00000000-0000-4000-8000-0000000000ab"
    session = _heartbeat_session(session_id)

    req0 = session.build_request(now=FIXED_NOW).to_dict()
    session.collector.record_api_call("https://api.example.com/users", tokens=40, drift=0.1)
    session.record_action(b"update:user:7")
    req1 = session.build_request(now=FIXED_NOW + timedelta(seconds=60)).to_dict()

    validator = hb.HeartbeatValidator(validator_did="did:web:validator.example.com")
    accept = validator.validate(req0)

    tampered = dict(req1)
    tampered["canaryReveal"] = _multibase(bytes([0xFF]) * 32)
    reject = validator.validate(tampered)

    cases = [
        {
            "name": "build_request_two_intervals",
            "function": "HeartbeatSession.build_request",
            "input": {
                "subject_did": "did:web:agent.example.com",
                "session_id": session_id,
                "interval_0_now": FIXED_NOW_ISO,
                "interval_1_now": _iso(FIXED_NOW + timedelta(seconds=60)),
            },
            "expected": {"interval_0": req0, "interval_1": req1},
        },
        {
            "name": "validate_accepts_first_heartbeat",
            "function": "HeartbeatValidator.validate",
            "input": {"validator_did": "did:web:validator.example.com", "request": req0},
            "expected": {
                "ok": accept.ok,
                "reasons": accept.reasons,
                "session_voucher": accept.session_voucher,
            },
        },
        {
            "name": "validate_rejects_broken_canary_chain",
            "function": "HeartbeatValidator.validate",
            "input": {"validator_did": "did:web:validator.example.com", "request": tampered},
            "expected": {
                "ok": reject.ok,
                "reasons": reject.reasons,
                "session_voucher": reject.session_voucher,
            },
        },
    ]

    return {
        "description": (
            "Heartbeat protocol vectors (Specification 11.3). build_request emits the "
            "wire format across two intervals (the canary reveal appears in interval 1 "
            "and interval_index increments). validate accepts the first heartbeat and "
            "returns a fully pinned SessionVoucher; a tampered reveal is rejected with "
            "reason 'canary_chain_broken'. The voucher's id/validFrom/validUntil come "
            "from the pinned clock and UUID."
        ),
        "module": "vouch.heartbeat",
        "spec_reference": "Specification 11.3",
        "version": "1.0",
        "pinned": {"now": FIXED_NOW_ISO, "uuid": FIXED_URN, "os_urandom": OS_URANDOM_RULE},
        "cases": cases,
    }


def _quorum_validators() -> list:
    v1 = hb.HeartbeatValidator(
        validator_did="did:web:policy.example.com",
        initial_trust=1.0,
        decay_lambda=0.01,
        scope=["agent_actions", "read"],
    )
    v2 = hb.HeartbeatValidator(
        validator_did="did:web:behavioral.example.com",
        initial_trust=0.9,
        decay_lambda=0.02,
        scope=["agent_actions", "write"],
    )
    v3 = hb.HeartbeatValidator(
        validator_did="did:web:budget.example.com",
        initial_trust=0.8,
        decay_lambda=0.03,
        scope=["agent_actions"],
    )
    return [
        quorum_mod.QuorumValidator(validator=v1, role=quorum_mod.ROLE_POLICY),
        quorum_mod.QuorumValidator(validator=v2, role=quorum_mod.ROLE_BEHAVIORAL),
        quorum_mod.QuorumValidator(validator=v3, role=quorum_mod.ROLE_BUDGET),
    ]


def _quorum_validator_summary(qvs: list) -> list:
    return [
        {
            "validator_did": qv.validator.validator_did,
            "role": qv.role,
            "weight": qv.weight,
            "initial_trust": qv.validator.initial_trust,
            "decay_lambda": qv.validator.decay_lambda,
            "scope": list(qv.validator.scope),
        }
        for qv in qvs
    ]


def build_quorum_vector() -> dict:
    # Approval: a fresh 2-of-3 quorum approves the first heartbeat.
    approve_qvs = _quorum_validators()
    approve_quorum = quorum_mod.HeartbeatQuorum(validators=approve_qvs, threshold=2)
    approve_session = _heartbeat_session("urn:uuid:00000000-0000-4000-8000-0000000000c1")
    approve_request = approve_session.build_request(now=FIXED_NOW).to_dict()
    approve_result = approve_quorum.validate(approve_request)

    # Rejection: validators see an intact interval-0 heartbeat, then a tampered
    # interval-1 reveal breaks the chain for all of them, so votes fall below 2.
    reject_qvs = _quorum_validators()
    reject_quorum = quorum_mod.HeartbeatQuorum(validators=reject_qvs, threshold=2)
    reject_session = _heartbeat_session("urn:uuid:00000000-0000-4000-8000-0000000000c2")
    setup_request = reject_session.build_request(now=FIXED_NOW).to_dict()
    reject_quorum.validate(setup_request)
    follow_up = reject_session.build_request(now=FIXED_NOW + timedelta(seconds=60)).to_dict()
    tampered = dict(follow_up)
    tampered["canaryReveal"] = _multibase(bytes([0xFF]) * 32)
    reject_result = reject_quorum.validate(tampered)

    cases = [
        {
            "name": "quorum_2_of_3_approves",
            "function": "HeartbeatQuorum.validate",
            "input": {
                "threshold": 2,
                "validators": _quorum_validator_summary(approve_qvs),
                "request": approve_request,
            },
            "expected": {
                "ok": approve_result.ok,
                "threshold": approve_result.threshold,
                "votes_for": approve_result.votes_for,
                "approving_dids": approve_result.approving_dids,
                "rejections": approve_result.rejections,
                "session_voucher": approve_result.session_voucher,
            },
        },
        {
            "name": "quorum_rejects_below_threshold",
            "function": "HeartbeatQuorum.validate",
            "input": {
                "threshold": 2,
                "validators": _quorum_validator_summary(reject_qvs),
                "request": tampered,
                "note": "validators already observed an intact interval-0 heartbeat",
            },
            "expected": {
                "ok": reject_result.ok,
                "threshold": reject_result.threshold,
                "votes_for": reject_result.votes_for,
                "approving_dids": reject_result.approving_dids,
                "rejections": reject_result.rejections,
                "session_voucher": reject_result.session_voucher,
            },
        },
    ]

    return {
        "description": (
            "Validator-quorum vectors (Specification 11.6). A 2-of-3 quorum over three "
            "validators with differing trust params and scopes. On approval the "
            "aggregate SessionVoucher uses min(initialTrust), max(decayLambda) and the "
            "intersection of scopes, with issuer set to the approving DIDs; its "
            "id/validFrom/validUntil come from the pinned clock and UUID. The rejection "
            "case breaks the canary chain so votes fall below the threshold."
        ),
        "module": "vouch.quorum",
        "spec_reference": "Specification 11.6",
        "version": "1.0",
        "pinned": {"now": FIXED_NOW_ISO, "uuid": FIXED_URN, "os_urandom": OS_URANDOM_RULE},
        "cases": cases,
    }


BUILDERS = {
    "trust_entropy": build_trust_entropy_vector,
    "quorum": build_quorum_vector,
    "merkle": build_merkle_vector,
    "canary": build_canary_vector,
    "behavioral_attestation": build_behavioral_attestation_vector,
    "heartbeat": build_heartbeat_vector,
}


def serialize(vector: dict) -> str:
    """Canonical on-disk form: 2-space indent, UTF-8, single trailing newline."""
    return json.dumps(vector, indent=2, ensure_ascii=False) + "\n"


def main() -> None:
    for name, builder in BUILDERS.items():
        with pinned():
            text = serialize(builder())
        out_path = VECTOR_ROOT / name / "vector.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(text, encoding="utf-8")
        print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
