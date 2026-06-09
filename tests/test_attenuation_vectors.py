"""
Cross-language interop vectors for capability attenuation (Specification v1.7,
Sections 9.3 to 9.5, CH-001).

These run the shared vectors in test-vectors/delegation-attenuation/vector.json
through the Python reference. The TypeScript and Go SDKs run the SAME vectors
and MUST produce identical accept/reject decisions and identical rejection
reasons. Do not fork the expectations per language.
"""

import json
import os

import pytest

from vouch import attenuation as A
from vouch.verifier import Verifier

VECTOR_PATH = os.path.join(
    os.path.dirname(__file__),
    "..",
    "test-vectors",
    "delegation-attenuation",
    "vector.json",
)


def _load_vectors():
    with open(VECTOR_PATH, "r", encoding="utf-8") as f:
        return json.load(f)["vectors"]


def _budget(vec):
    if not vec.get("budget"):
        return None
    return A.VerifierBudget(**vec["budget"])


def _cap_to_link(cap):
    """Map a capability node to a delegationChain link the verifier consumes."""
    link = {"intent": {k: cap[k] for k in ("action", "target", "resource") if k in cap}}
    for k in ("validFrom", "validUntil", "rate", "policy"):
        if k in cap:
            link[k] = cap[k]
    return link


@pytest.mark.parametrize("vec", _load_vectors(), ids=lambda v: v["name"])
def test_attenuation_vector_module(vec):
    """The attenuation module decides each vector exactly as specified."""
    result = A.validate_chain(vec["chain"], budget=_budget(vec))
    assert result.ok == vec["accept"], (
        f"{vec['name']}: ok={result.ok} reason={result.reason} detail={result.detail}"
    )
    if not vec["accept"]:
        assert result.reason == vec["reason"], (
            f"{vec['name']}: reason={result.reason} (want {vec['reason']})"
        )


@pytest.mark.parametrize("vec", _load_vectors(), ids=lambda v: v["name"])
def test_attenuation_vector_via_verifier(vec):
    """The verifier-side wiring (Verifier.validate_delegation_chain) agrees."""
    credential = {
        "credentialSubject": {"delegationChain": [_cap_to_link(c) for c in vec["chain"]]}
    }
    result = Verifier.validate_delegation_chain(credential, budget=_budget(vec))
    assert result.ok == vec["accept"], (
        f"{vec['name']}: ok={result.ok} reason={result.reason} detail={result.detail}"
    )
    if not vec["accept"]:
        assert result.reason == vec["reason"], (
            f"{vec['name']}: reason={result.reason} (want {vec['reason']})"
        )
