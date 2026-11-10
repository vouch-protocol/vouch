"""Python against the shared delegation-chain vectors (the interop contract)."""

from __future__ import annotations

import importlib.util
import json
from datetime import datetime
from pathlib import Path

import pytest

from vouch.verifier import Verifier, verify_delegation_chain

ROOT = Path(__file__).resolve().parent.parent
VECTOR = ROOT / "test-vectors" / "delegation-chain" / "vector.json"
CASES = json.loads(VECTOR.read_text(encoding="utf-8"))["cases"]


def _at(iso: str) -> datetime:
    return datetime.fromisoformat(iso.replace("Z", "+00:00"))


def test_vector_file_matches_generator():
    spec = importlib.util.spec_from_file_location(
        "gen_delegation_chain_vectors", ROOT / "scripts" / "gen_delegation_chain_vectors.py"
    )
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    assert gen.render() == VECTOR.read_text(encoding="utf-8")


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_chain_verdict(case):
    assert verify_delegation_chain(case["credential"], now=_at(case["now"])) == case["expected"]


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_full_verify_agrees(case):
    cred = case["credential"]
    issuer = cred["issuer"]
    leaf_key = issuer.split("did:key:", 1)[1]
    ok, _ = Verifier.verify(cred, public_key=leaf_key, now=_at(case["now"]))
    assert ok is (case["expected"] is None)
