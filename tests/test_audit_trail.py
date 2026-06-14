"""Tests for the tamper-evident audit trail and human-oversight attestation."""

import copy

import pytest

from vouch import Signer, generate_identity
from vouch.attribution import _pub_from_jwk
from vouch import audit_trail as at


@pytest.fixture
def signer_identity():
    ident = generate_identity(domain="auditor.example.com")
    return ident, Signer(private_key=ident.private_key_jwk, did=ident.did)


def _trail():
    t = at.AuditTrail()
    t.append(action="ALLOWED", actor="did:web:agent.example.com", resource="read_file",
             timestamp="2026-06-14T00:00:00Z")
    t.append(action="BLOCKED", actor="did:web:agent.example.com", resource="run_command",
             decision="not_trusted", timestamp="2026-06-14T00:00:01Z")
    t.append(action="ALLOWED", actor="did:web:agent.example.com", resource="write_file",
             timestamp="2026-06-14T00:00:02Z")
    return t


def test_chain_builds_and_verifies():
    t = _trail()
    assert len(t) == 3
    ok, broken = t.verify()
    assert ok and broken is None
    # Each entry links to the previous.
    es = t.entries
    assert es[0].prev_hash == at.GENESIS_HASH
    assert es[1].prev_hash == es[0].entry_hash
    assert es[2].prev_hash == es[1].entry_hash
    assert t.head == es[2].entry_hash


def test_determinism():
    # Same inputs produce the same hashes, so the format is reproducible.
    assert _trail().head == _trail().head


def test_tampered_entry_detected():
    t = _trail()
    es = t.entries
    es[1].resource = "exfiltrate_secrets"  # edit a recorded action
    ok, broken = at.verify_entries(es)
    assert not ok and broken == 1


def test_deletion_detected():
    t = _trail()
    es = t.entries
    del es[1]  # drop the blocked event to hide it
    # Reseating seq is required for the loop; the surviving entry keeps seq=2.
    ok, broken = at.verify_entries(es)
    assert not ok


def test_signed_export_verifies(signer_identity):
    ident, signer = signer_identity
    manifest = at.signed_export(_trail(), signer)
    ok, reasons = at.verify_export(manifest, _pub_from_jwk(ident.public_key_jwk))
    assert ok, reasons


def test_signed_export_tamper_rejected(signer_identity):
    ident, signer = signer_identity
    manifest = at.signed_export(_trail(), signer)
    tampered = copy.deepcopy(manifest)
    tampered["entries"][0]["resource"] = "something_else"
    ok, reasons = at.verify_export(tampered, _pub_from_jwk(ident.public_key_jwk))
    assert not ok
    # Either the proof breaks or the chain recomputation breaks; both are fine.
    assert reasons


def test_from_flight_recorder():
    from vouch.shield.flight_recorder import LogEntry
    logs = [
        LogEntry(timestamp="2026-06-14T00:00:00Z", event="ALLOWED",
                 did="did:web:a.example.com", tool="read"),
        LogEntry(timestamp="2026-06-14T00:00:01Z", event="BLOCKED",
                 did="did:web:a.example.com", tool="rm", reason="blocked"),
    ]
    t = at.AuditTrail.from_flight_recorder(logs)
    ok, _ = t.verify()
    assert ok and len(t) == 2


def test_human_oversight_attestation(signer_identity):
    ident, signer = signer_identity
    cred = at.build_human_oversight_attestation(
        signer,
        reviewer="did:web:lead.example.com",
        action_ref="abc123entryhash",
        decision="approved",
        note="checked the diff, looks safe",
    )
    assert cred["type"][-1] == at.OVERSIGHT_TYPE
    assert cred["credentialSubject"]["decision"] == "approved"
    assert at.verify_human_oversight_attestation(cred, _pub_from_jwk(ident.public_key_jwk))


def test_matches_interop_vector():
    # Lock the hash-chain format against the published test vector so other
    # language implementations can validate byte-identically.
    import json
    from pathlib import Path

    vec_path = Path(__file__).resolve().parents[1] / "test-vectors" / "audit-trail" / "vectors.json"
    vector = json.loads(vec_path.read_text())
    entries = [at.AuditEntry.from_dict(d) for d in vector["entries"]]
    # Recomputing each entry hash from its content must reproduce the vector.
    for e in entries:
        assert e.compute_hash() == e.entry_hash
    ok, broken = at.verify_entries(entries)
    assert ok and broken is None
    assert entries[-1].entry_hash == vector["head"]


def test_human_oversight_wrong_key_fails(signer_identity):
    _, signer = signer_identity
    other = generate_identity(domain="attacker.example.com")
    cred = at.build_human_oversight_attestation(
        signer, reviewer="did:web:lead.example.com", action_ref="x", decision="approved",
    )
    assert not at.verify_human_oversight_attestation(cred, _pub_from_jwk(other.public_key_jwk))
