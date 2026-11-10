"""Verify-side delegation chain checks and signer-side refusals.

A delegated credential carries a `delegationChain`. Each link embeds the signed
grant it was derived from (`parentCredential`), so a verifier can check, from
the credential alone: every grant's signature, the parent -> child linkage
(each grant names its delegatee, who is the next issuer), and that no step
broadens its parent on action, target, resource, time, rate, or policy.

Most attacks here are built by hand with `delegation_chain=`, which bypasses
the signer's own checks, so that the verifier is what has to refuse them.
"""

from __future__ import annotations

import base64
import copy
import json
from datetime import datetime, timedelta, timezone

import pytest

from vouch import Signer, generate_identity, multikey
from vouch.verifier import Verifier, verify_delegation_chain

CAL = "https://calendar.example.com/team"


def _did_key_signer():
    kp = generate_identity()
    raw = base64.urlsafe_b64decode(json.loads(kp.public_key_jwk)["x"] + "==")
    did = "did:key:" + multikey.encode_ed25519_public(raw)
    return Signer(private_key=kp.private_key_jwk, did=did)


def _key(signer):
    return signer.get_public_key_multikey()


def _link(parent, subject, child_intent):
    """A chain link exactly as Signer builds it (used to forge chains)."""
    return {
        "issuer": parent["issuer"],
        "subject": subject,
        "intent": child_intent,
        "validFrom": parent.get("validFrom"),
        "validUntil": parent.get("validUntil"),
        "parentProofValue": parent["proof"]["proofValue"][:64],
        "parentCredential": parent,
    }


@pytest.fixture
def parties():
    return {name: _did_key_signer() for name in ("root", "a", "b", "mallory")}


@pytest.fixture
def chain(parties):
    """root -> a (read+update, rate 10/h) -> b (read, rate 5/h) -> leaf read."""
    root, a, b = parties["root"], parties["a"], parties["b"]
    root_grant = root.sign(
        intent={
            "action": ["read", "update"],
            "target": "calendar",
            "resource": CAL,
            "delegatee": a.did,
            "rate": {"limit": 10, "window": "PT1H"},
        },
        valid_seconds=3600,
    )
    a_grant = a.sign(
        intent={
            "action": "read",
            "target": "calendar",
            "resource": CAL,
            "delegatee": b.did,
            "rate": {"limit": 5, "window": "PT1H"},
        },
        parent_credential=root_grant,
        valid_seconds=3600,
    )
    leaf = b.sign(
        intent={"action": "read", "target": "calendar", "resource": CAL + "/events"},
        parent_credential=a_grant,
    )
    return {"root_grant": root_grant, "a_grant": a_grant, "leaf": leaf}


# ---------------------------------------------------------------------------
# The valid case
# ---------------------------------------------------------------------------


def test_valid_two_hop_chain_verifies(parties, chain):
    leaf = chain["leaf"]
    assert len(leaf["credentialSubject"]["delegationChain"]) == 2
    assert verify_delegation_chain(leaf) is None
    ok, passport = Verifier.verify(leaf, public_key=_key(parties["b"]))
    assert ok is True
    assert [link.issuer for link in passport.delegation_chain] == [
        parties["root"].did,
        parties["a"].did,
    ]


def test_trusted_root_enforced_when_given(parties, chain):
    leaf = chain["leaf"]
    assert verify_delegation_chain(leaf, trusted_roots=[parties["root"].did]) is None
    assert (
        verify_delegation_chain(leaf, trusted_roots=[parties["mallory"].did])
        == "untrusted_principal"
    )


# ---------------------------------------------------------------------------
# Forged and tampered grants
# ---------------------------------------------------------------------------


def test_forged_parent_is_rejected(parties):
    """A made-up parent with a fake proof: the verifier must refuse it."""
    mallory = parties["mallory"]
    fake_parent = {
        "issuer": parties["root"].did,
        "validFrom": "2020-01-01T00:00:00Z",
        "validUntil": "2099-01-01T00:00:00Z",
        "credentialSubject": {
            "intent": {
                "action": "wire_funds",
                "target": "bank",
                "resource": "x",
                "delegatee": mallory.did,
            }
        },
        "proof": {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "proofPurpose": "assertionMethod",
            "verificationMethod": parties["root"].did + "#key-1",
            "proofValue": "z" + "1" * 86,
        },
    }
    cred = mallory.sign(
        intent={"action": "wire_funds", "target": "bank", "resource": "x/everything"},
        parent_credential=fake_parent,
    )
    assert verify_delegation_chain(cred) == "delegation_signature_invalid"
    ok, _ = Verifier.verify(cred, public_key=_key(mallory))
    assert ok is False


def test_tampered_root_grant_is_rejected(parties, chain):
    b = parties["b"]
    links = copy.deepcopy(chain["leaf"]["credentialSubject"]["delegationChain"])
    links[0]["parentCredential"]["credentialSubject"]["intent"]["action"] = [
        "read",
        "update",
        "delete",
    ]
    forged = b.sign(
        intent={"action": "read", "target": "calendar", "resource": CAL},
        delegation_chain=links,
    )
    assert verify_delegation_chain(forged) == "delegation_signature_invalid"
    assert Verifier.verify(forged, public_key=_key(b))[0] is False


def test_tampered_intermediate_grant_is_rejected(parties, chain):
    b = parties["b"]
    links = copy.deepcopy(chain["leaf"]["credentialSubject"]["delegationChain"])
    links[1]["parentCredential"]["credentialSubject"]["intent"]["action"] = "update"
    forged = b.sign(
        intent={"action": "update", "target": "calendar", "resource": CAL},
        delegation_chain=links,
    )
    assert verify_delegation_chain(forged) == "delegation_signature_invalid"


def test_swapped_parent_proof_binding_is_rejected(parties, chain):
    b = parties["b"]
    links = copy.deepcopy(chain["leaf"]["credentialSubject"]["delegationChain"])
    links[1]["parentProofValue"] = "z" + "2" * 63
    forged = b.sign(
        intent={"action": "read", "target": "calendar", "resource": CAL},
        delegation_chain=links,
    )
    assert verify_delegation_chain(forged) == "delegation_link_tampered"


def test_legacy_link_without_parent_credential_is_rejected(parties, chain):
    b = parties["b"]
    links = copy.deepcopy(chain["leaf"]["credentialSubject"]["delegationChain"])
    for link in links:
        del link["parentCredential"]
    forged = b.sign(
        intent={"action": "read", "target": "calendar", "resource": CAL},
        delegation_chain=links,
    )
    assert verify_delegation_chain(forged) == "delegation_link_unsigned"
    assert Verifier.verify(forged, public_key=_key(b))[0] is False


# ---------------------------------------------------------------------------
# Linkage
# ---------------------------------------------------------------------------


def test_stolen_chain_used_by_another_agent_is_rejected(parties, chain):
    """Mallory presents b's chain under her own credential."""
    mallory = parties["mallory"]
    links = copy.deepcopy(chain["leaf"]["credentialSubject"]["delegationChain"])
    forged = mallory.sign(
        intent={"action": "read", "target": "calendar", "resource": CAL},
        delegation_chain=links,
    )
    assert verify_delegation_chain(forged) == "delegation_subject_issuer_mismatch"


def test_link_subject_must_be_the_grant_delegatee(parties, chain):
    mallory = parties["mallory"]
    links = copy.deepcopy(chain["leaf"]["credentialSubject"]["delegationChain"])
    links[1]["subject"] = mallory.did  # the a->b grant does not name mallory
    forged = mallory.sign(
        intent={"action": "read", "target": "calendar", "resource": CAL},
        delegation_chain=links,
    )
    assert verify_delegation_chain(forged) == "delegation_subject_mismatch"


def test_grant_without_delegatee_is_rejected(parties):
    root, a = parties["root"], parties["a"]
    bearer = root.sign(intent={"action": "read", "target": "calendar", "resource": CAL})
    forged = a.sign(
        intent={"action": "read", "target": "calendar", "resource": CAL},
        delegation_chain=[_link(bearer, a.did, {"action": "read"})],
    )
    assert verify_delegation_chain(forged) == "delegation_no_delegatee"


# ---------------------------------------------------------------------------
# Narrowing on every dimension (verify side)
# ---------------------------------------------------------------------------


def _grant(signer, delegatee, **intent_kw):
    intent = {"action": "read", "target": "calendar", "resource": CAL, "delegatee": delegatee}
    intent.update(intent_kw)
    return signer.sign(intent=intent, valid_seconds=3600)


@pytest.mark.parametrize(
    "leaf_intent, dimension",
    [
        ({"action": "update", "target": "calendar", "resource": CAL}, "action"),
        ({"action": "read", "target": "payroll", "resource": CAL}, "target"),
        (
            {"action": "read", "target": "calendar", "resource": "https://calendar.example.com"},
            "resource",
        ),
        (
            {
                "action": "read",
                "target": "calendar",
                "resource": CAL,
                "rate": {"limit": 100, "window": "PT1H"},
            },
            "rate",
        ),
    ],
)
def test_leaf_broader_than_grant_is_rejected(parties, leaf_intent, dimension):
    root, a = parties["root"], parties["a"]
    grant = _grant(root, a.did, rate={"limit": 10, "window": "PT1H"})
    forged = a.sign(intent=leaf_intent, delegation_chain=[_link(grant, a.did, leaf_intent)])
    assert verify_delegation_chain(forged) == f"scope_exceeds_parent:{dimension}"
    assert Verifier.verify(forged, public_key=_key(a))[0] is False


def test_intermediate_grant_broader_than_root_is_rejected(parties):
    root, a, b = parties["root"], parties["a"], parties["b"]
    root_grant = _grant(root, a.did)
    widened = {
        "action": ["read", "update"],
        "target": "calendar",
        "resource": CAL,
        "delegatee": b.did,
    }
    a_grant = a.sign(
        intent=widened,
        delegation_chain=[_link(root_grant, a.did, widened)],
        valid_seconds=3600,
    )
    leaf_intent = {"action": "update", "target": "calendar", "resource": CAL}
    leaf = b.sign(
        intent=leaf_intent,
        delegation_chain=[
            _link(root_grant, a.did, widened),
            _link(a_grant, b.did, leaf_intent),
        ],
    )
    assert verify_delegation_chain(leaf) == "scope_exceeds_parent:action"


def test_leaf_outliving_its_grant_is_rejected(parties):
    root, a = parties["root"], parties["a"]
    grant = root.sign(
        intent={"action": "read", "target": "calendar", "resource": CAL, "delegatee": a.did},
        valid_seconds=60,
    )
    leaf_intent = {"action": "read", "target": "calendar", "resource": CAL}
    forged = a.sign(
        intent=leaf_intent,
        delegation_chain=[_link(grant, a.did, leaf_intent)],
        valid_seconds=86400,
    )
    assert verify_delegation_chain(forged) == "scope_exceeds_parent:time"


def test_expired_grant_is_rejected(parties):
    root, a = parties["root"], parties["a"]
    long_ago = datetime.now(timezone.utc) - timedelta(days=2)
    grant = root.sign(
        intent={"action": "read", "target": "calendar", "resource": CAL, "delegatee": a.did},
        valid_from=long_ago,
        valid_seconds=60,
    )
    leaf_intent = {"action": "read", "target": "calendar", "resource": CAL}
    forged = a.sign(intent=leaf_intent, delegation_chain=[_link(grant, a.did, leaf_intent)])
    assert verify_delegation_chain(forged) == "delegation_expired"


def test_unresolvable_issuer_key_is_rejected(parties):
    """A did:web root needs its key from trusted_roots or a resolver."""
    kp = generate_identity(domain="principal.example.com")
    principal = Signer(private_key=kp.private_key_jwk, did=kp.did)
    a = parties["a"]
    grant = _grant(principal, a.did)
    leaf = a.sign(
        intent={"action": "read", "target": "calendar", "resource": CAL},
        parent_credential=grant,
    )
    assert verify_delegation_chain(leaf) == "delegation_issuer_key_unresolved"
    roots = {principal.did: principal.get_public_key_multikey()}
    assert verify_delegation_chain(leaf, trusted_roots=roots) is None
    ok, _ = Verifier.verify(leaf, public_key=_key(a), trusted_roots=roots)
    assert ok is True


# ---------------------------------------------------------------------------
# Signer refuses to mint a credential outside its grant
# ---------------------------------------------------------------------------


def test_signer_refuses_action_outside_grant(parties):
    """The probe case: wire_funds under a read grant."""
    root, a = parties["root"], parties["a"]
    grant = _grant(root, a.did, resource="x")
    with pytest.raises(ValueError, match="non-expansion.*action"):
        a.sign(
            intent={"action": "wire_funds", "target": "calendar", "resource": "x/everything"},
            parent_credential=grant,
        )


def test_signer_refuses_target_outside_grant(parties):
    root, a = parties["root"], parties["a"]
    grant = _grant(root, a.did)
    with pytest.raises(ValueError, match="non-expansion.*target"):
        a.sign(
            intent={"action": "read", "target": "payroll", "resource": CAL},
            parent_credential=grant,
        )


def test_signer_refuses_grant_naming_someone_else(parties):
    root, a, mallory = parties["root"], parties["a"], parties["mallory"]
    grant = _grant(root, a.did)
    with pytest.raises(ValueError, match="delegatee"):
        mallory.sign(
            intent={"action": "read", "target": "calendar", "resource": CAL},
            parent_credential=grant,
        )


def test_signer_refuses_grant_without_delegatee(parties):
    root, a = parties["root"], parties["a"]
    bearer = root.sign(intent={"action": "read", "target": "calendar", "resource": CAL})
    with pytest.raises(ValueError, match="delegatee"):
        a.sign(
            intent={"action": "read", "target": "calendar", "resource": CAL},
            parent_credential=bearer,
        )


def test_signer_refuses_expired_grant(parties):
    root, a = parties["root"], parties["a"]
    grant = root.sign(
        intent={"action": "read", "target": "calendar", "resource": CAL, "delegatee": a.did},
        valid_from=datetime.now(timezone.utc) - timedelta(days=1),
        valid_seconds=60,
    )
    with pytest.raises(ValueError, match="expired"):
        a.sign(
            intent={"action": "read", "target": "calendar", "resource": CAL},
            parent_credential=grant,
        )


def test_signer_clamps_child_validity_to_grant(parties):
    root, a = parties["root"], parties["a"]
    grant = root.sign(
        intent={"action": "read", "target": "calendar", "resource": CAL, "delegatee": a.did},
        valid_seconds=120,
    )
    leaf = a.sign(
        intent={"action": "read", "target": "calendar", "resource": CAL},
        parent_credential=grant,
        valid_seconds=86400,
    )
    assert leaf["validUntil"] <= grant["validUntil"]
    assert verify_delegation_chain(leaf) is None


# ---------------------------------------------------------------------------
# autosign: a widened call never yields a credential
# ---------------------------------------------------------------------------


@pytest.fixture
def autosign_env(monkeypatch):
    from vouch import autosign

    agent = _did_key_signer()
    autosign.reset_default_signer()
    monkeypatch.setattr(autosign, "resolve_signer", lambda signer=None: signer or agent)
    yield agent
    autosign.reset_default_signer()


@pytest.mark.parametrize(
    "action, target",
    [("delete", "calendar"), ("read", "payroll")],
)
def test_autosign_widened_action_or_target_mints_nothing(autosign_env, parties, action, target):
    from vouch import autosign
    from vouch.autosign import current_credential, signed

    grant = _grant(parties["root"], autosign_env.did)
    autosign._current_credential.set(None)

    @signed(action=action, target=target, resource=CAL, parent=grant)
    def overreach():
        return "ran"

    assert overreach() == "ran"  # autosign is fail-open by design
    assert current_credential() is None  # but no widened credential exists


def test_autosign_in_scope_call_is_chained_and_verifies(autosign_env, parties):
    from vouch.autosign import current_credential, signed

    grant = _grant(parties["root"], autosign_env.did)

    @signed(action="read", target="calendar", resource=CAL + "/events", parent=grant)
    def ok_call():
        return current_credential()

    cred = ok_call()
    assert cred is not None
    assert verify_delegation_chain(cred) is None
    assert Verifier.verify(cred, public_key=_key(autosign_env))[0] is True
