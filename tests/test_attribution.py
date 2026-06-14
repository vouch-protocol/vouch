"""Tests for per-region human/AI authorship attribution."""

import copy
import json

import pytest

from vouch import Signer, generate_identity
from vouch import attribution as attr


@pytest.fixture
def human():
    ident = generate_identity(domain="dev.example.com")
    signer = Signer(private_key=ident.private_key_jwk, did=ident.did)
    return ident, signer


@pytest.fixture
def session(tmp_path):
    return attr.AttributionSession(tmp_path / "sess", model="claude-opus-4-8")


def test_ai_then_human_regions(session, human):
    ident, signer = human
    # AI writes a new file with three lines.
    session.record_edit("app.py", "import os\ndef a():\n    return 1\n")
    # Human appends two lines and edits one (line 3 changes).
    final = "import os\ndef a():\n    return 2\ndef b():\n    return 3\n"
    manifest = session.finalize({"app.py": final}, signer)

    s = attr.summarize(manifest)
    # Lines 1,2 stay AI; line 3 changed by human; 4,5 added by human => 2 AI, 3 human.
    assert s["lines"][attr.SOURCE_AI] == 2
    assert s["lines"][attr.SOURCE_HUMAN] == 3

    lines = attr.blame(manifest, "app.py")
    assert lines[0]["source"] == attr.SOURCE_AI
    assert lines[0]["author"] == session.ai_did
    assert lines[0]["model"] == "claude-opus-4-8"
    assert lines[2]["source"] == attr.SOURCE_HUMAN
    assert lines[2]["author"] == ident.did


def test_manifest_verifies(session, human):
    ident, signer = human
    session.record_edit("m.py", "a = 1\nb = 2\n")
    final = "a = 1\nb = 2\nc = 3\n"
    manifest = session.finalize({"m.py": final}, signer)

    res = attr.verify_manifest(
        manifest,
        ident.public_key_jwk,
        session.ai_public_key_jwk,
        files_on_disk={"m.py": final},
    )
    assert res.ok, res.reasons


def test_tampered_bytes_rejected(session, human):
    ident, signer = human
    session.record_edit("t.py", "x = 1\n")
    final = "x = 1\ny = 2\n"
    manifest = session.finalize({"t.py": final}, signer)

    # The committed file on disk no longer matches the signed hash.
    res = attr.verify_manifest(
        manifest, ident.public_key_jwk, session.ai_public_key_jwk,
        files_on_disk={"t.py": "x = 99\ny = 2\n"},
    )
    assert not res.ok
    assert any("content hash" in r for r in res.reasons)


def test_forged_ai_region_rejected(session, human):
    """Re-label a human region as AI without an AI attestation -> rejected."""
    ident, signer = human
    session.record_edit("f.py", "ai = 1\n")
    final = "ai = 1\nhuman = 2\n"
    manifest = session.finalize({"f.py": final}, signer)

    tampered = copy.deepcopy(manifest)
    for f in tampered["files"]:
        for r in f["regions"]:
            if r["source"] == attr.SOURCE_HUMAN:
                r["source"] = attr.SOURCE_AI
                r["author"] = session.ai_did
    # Human proof now broken AND the AI region is unbacked. Either is enough.
    res = attr.verify_manifest(
        tampered, ident.public_key_jwk, session.ai_public_key_jwk,
    )
    assert not res.ok


def test_human_proof_tamper_rejected(session, human):
    ident, signer = human
    session.record_edit("p.py", "z = 1\n")
    manifest = session.finalize({"p.py": "z = 1\n"}, signer)

    tampered = copy.deepcopy(manifest)
    tampered["createdBy"] = "did:web:attacker.example.com"
    res = attr.verify_manifest(tampered, ident.public_key_jwk, session.ai_public_key_jwk)
    assert not res.ok
    assert any("human proof" in r for r in res.reasons)


def test_regions_cover_every_line(session, human):
    ident, signer = human
    session.record_edit("c.py", "1\n2\n3\n")
    final = "1\n2\n3\n4\n5\n"
    manifest = session.finalize({"c.py": final}, signer)
    f = manifest["files"][0]
    covered = []
    for r in f["regions"]:
        covered.extend(range(r["startLine"], r["endLine"] + 1))
    assert covered == [1, 2, 3, 4, 5]


def test_untouched_file_is_human(session, human):
    ident, signer = human
    # AI never touched this file; committer owns it.
    manifest = session.finalize({"only_human.py": "hand = 1\n"}, signer)
    lines = attr.blame(manifest, "only_human.py")
    assert all(l["source"] == attr.SOURCE_HUMAN for l in lines)


def test_persistence_across_session_reload(tmp_path, human):
    ident, signer = human
    d = tmp_path / "persist"
    s1 = attr.AttributionSession(d, model="claude-opus-4-8")
    s1.record_edit("k.py", "p = 1\n")
    ai_did = s1.ai_did

    # New session object, same dir: must reuse the AI identity and state.
    s2 = attr.AttributionSession(d)
    assert s2.ai_did == ai_did
    s2.record_edit("k.py", "p = 1\nq = 2\n")
    manifest = s2.finalize({"k.py": "p = 1\nq = 2\n"}, signer)
    s = attr.summarize(manifest)
    assert s["lines"][attr.SOURCE_AI] == 2


def test_ai_key_separate_from_human(session, human):
    ident, signer = human
    session.record_edit("s.py", "a = 1\n")
    # The AI session DID is not the human DID: distinct keys.
    assert session.ai_did != ident.did
    assert session.ai_public_key_jwk != ident.public_key_jwk
