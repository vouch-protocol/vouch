"""
Interop-vector tests for the Root of Trust.

Locks the wire format: the committed vector.json must be byte-reproducible from
the fixed seeds and timestamps, and its chain must verify. Language SDK ports
consume the same vector.json to prove cross-implementation interop.
"""

import importlib.util
import json
import os

from vouch.root_of_trust import verify_identity_chain

_VECTOR_DIR = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "test-vectors", "root-of-trust"
)


def _load_vector():
    with open(os.path.join(_VECTOR_DIR, "vector.json")) as handle:
        return json.load(handle)


def _regenerate():
    spec = importlib.util.spec_from_file_location(
        "rot_generate", os.path.join(_VECTOR_DIR, "generate.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.build_vectors()


def test_vector_is_reproducible():
    """Regenerating from the fixed inputs matches the committed vector byte-for-byte."""
    regenerated = _regenerate()
    committed = _load_vector()
    for key in ("rootOfTrust", "recognizedIssuer", "agentIdentity"):
        assert regenerated[key] == committed[key], f"{key} drifted from the committed vector"
    assert regenerated["trustedRoot"] == committed["trustedRoot"]


def test_vector_chain_verifies():
    """The committed vector's chain verifies and anchors to the pinned root."""
    vector = _load_vector()
    result = verify_identity_chain(
        vector["agentIdentity"],
        vector["recognizedIssuer"],
        trusted_root=vector["trustedRoot"],
        root_credential=vector["rootOfTrust"],
    )
    assert result.ok, result.reason
    assert result.agent_did == vector["expected"]["agentDid"]
    assert result.issuer_did == vector["expected"]["issuerDid"]
    assert result.attributes["owner"] == "Acme"


def test_vector_tamper_breaks_chain():
    """Flipping a byte of the committed identity proof breaks verification."""
    vector = _load_vector()
    identity = json.loads(json.dumps(vector["agentIdentity"]))
    pv = identity["proof"]["proofValue"]
    identity["proof"]["proofValue"] = pv[:-1] + ("A" if pv[-1] != "A" else "B")
    result = verify_identity_chain(
        identity,
        vector["recognizedIssuer"],
        trusted_root=vector["trustedRoot"],
    )
    assert not result.ok
    assert result.reason in ("identity_proof_invalid", "identity_proof_malformed")
