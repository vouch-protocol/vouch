#!/usr/bin/env python3
"""
Generate test-vectors/delegation-chain/vector.json.

These vectors pin delegation chain verification (Specification 9.3) across every
SDK. Each case is a signed Vouch Credential whose `delegationChain` links embed
the signed grant they came from (`parentCredential`), an evaluation time, and
the expected verdict of `verify_delegation_chain`: null for a valid chain, or
the reason code a verifier must return.

Every identity is a did:key derived from a fixed seed, every timestamp and id is
fixed, and eddsa-jcs-2022 is deterministic, so the file is byte-for-byte
reproducible. Python is the reference: the expected codes are computed by
`vouch.verifier.verify_delegation_chain` and also asserted against the intended
code for each case, so a generator run cannot silently change a verdict.

Run: python scripts/gen_delegation_chain_vectors.py
"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402
from jwcrypto import jwk  # noqa: E402

from vouch import data_integrity, multikey, vc  # noqa: E402
from vouch.signer import Signer, _clamp_to_parent_window  # noqa: E402
from vouch.verifier import verify_delegation_chain  # noqa: E402

OUT = ROOT / "test-vectors" / "delegation-chain" / "vector.json"

T0 = datetime(2026, 11, 10, 0, 0, 0, tzinfo=timezone.utc)
NOW = "2026-11-10T12:00:00Z"
CAL = "https://calendar.example.com/team"


def _signer(name: str) -> Signer:
    seed = hashlib.sha256(f"vouch-delegation-chain-vector:{name}".encode()).digest()
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    raw_pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    did = "did:key:" + multikey.encode_ed25519_public(raw_pub)
    return Signer(private_key=jwk.JWK.from_pyca(priv).export_private(), did=did)


def _issue(
    signer: Signer,
    intent: Dict[str, Any],
    cid: str,
    *,
    valid_seconds: int = 86400,
    valid_from: datetime = T0,
    parent: Optional[Dict[str, Any]] = None,
    chain: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Sign exactly as Signer.sign does, with a fixed proof `created`."""
    if parent is not None:
        chain = signer._extend_delegation_chain_from_parent(parent, intent)
        valid_from, valid_seconds = _clamp_to_parent_window(parent, valid_from, valid_seconds)
    cred = vc.build_vouch_credential(
        issuer_did=signer.did,
        intent=intent,
        valid_seconds=valid_seconds,
        delegation_chain=chain or None,
        credential_id=cid,
        valid_from=valid_from,
    )
    cred["proof"] = data_integrity.build_proof(
        cred, signer._raw_priv, signer.verification_method_id(), created=valid_from
    )
    return cred


def _link(parent: Dict[str, Any], subject: str, child_intent: Dict[str, Any]) -> Dict[str, Any]:
    """A link in the exact shape Signer builds, for hand-built (attack) chains."""
    return {
        "issuer": parent["issuer"],
        "subject": subject,
        "intent": child_intent,
        "validFrom": parent.get("validFrom"),
        "validUntil": parent.get("validUntil"),
        "parentProofValue": parent["proof"]["proofValue"][:64],
        "parentCredential": parent,
    }


def build() -> Dict[str, Any]:
    root, a, b, mallory = (_signer(n) for n in ("root", "a", "b", "mallory"))

    root_grant = _issue(
        root,
        {
            "action": ["read", "update"],
            "target": "calendar",
            "resource": CAL,
            "delegatee": a.did,
            "rate": {"limit": 10, "window": "PT1H"},
        },
        "urn:uuid:00000000-0000-4000-8000-000000000001",
    )
    a_grant = _issue(
        a,
        {
            "action": "read",
            "target": "calendar",
            "resource": CAL,
            "delegatee": b.did,
            "rate": {"limit": 5, "window": "PT1H"},
        },
        "urn:uuid:00000000-0000-4000-8000-000000000002",
        parent=root_grant,
    )
    read_events = {"action": "read", "target": "calendar", "resource": CAL + "/events"}
    leaf = _issue(
        b, dict(read_events), "urn:uuid:00000000-0000-4000-8000-000000000003", parent=a_grant
    )
    links = leaf["credentialSubject"]["delegationChain"]

    def forged(signer, intent, chain, cid, **kw):
        return _issue(signer, intent, cid, chain=chain, **kw)

    cases: List[Dict[str, Any]] = []

    def case(name, credential, expected, now=NOW, note=""):
        got = verify_delegation_chain(
            credential, now=datetime.fromisoformat(now.replace("Z", "+00:00"))
        )
        if got != expected:
            raise SystemExit(f"{name}: reference returned {got!r}, intended {expected!r}")
        cases.append(
            {"name": name, "note": note, "now": now, "credential": credential, "expected": expected}
        )

    case("valid_two_hop", leaf, None, note="root -> a -> b, each step narrows")

    t = copy.deepcopy(links)
    t[0]["parentCredential"]["proof"]["proofValue"] = a_grant["proof"]["proofValue"]
    case(
        "forged_grant_signature",
        forged(b, dict(read_events), t, "urn:uuid:00000000-0000-4000-8000-000000000010"),
        "delegation_signature_invalid",
        note="the root grant carries a signature that is not the root's",
    )

    t = copy.deepcopy(links)
    t[0]["parentCredential"]["credentialSubject"]["intent"]["action"] = ["read", "update", "delete"]
    case(
        "tampered_root_grant",
        forged(b, dict(read_events), t, "urn:uuid:00000000-0000-4000-8000-000000000011"),
        "delegation_signature_invalid",
        note="the root grant's action set was edited after signing",
    )

    t = copy.deepcopy(links)
    t[1]["parentCredential"]["credentialSubject"]["intent"]["action"] = "update"
    case(
        "tampered_intermediate_grant",
        forged(
            b,
            {"action": "update", "target": "calendar", "resource": CAL},
            t,
            "urn:uuid:00000000-0000-4000-8000-000000000012",
        ),
        "delegation_signature_invalid",
        note="the a -> b grant was edited after signing",
    )

    for dim, intent in (
        ("action", {"action": "delete", "target": "calendar", "resource": CAL}),
        ("target", {"action": "read", "target": "payroll", "resource": CAL}),
        (
            "resource",
            {"action": "read", "target": "calendar", "resource": "https://calendar.example.com"},
        ),
        (
            "rate",
            {
                "action": "read",
                "target": "calendar",
                "resource": CAL,
                "rate": {"limit": 100, "window": "PT1H"},
            },
        ),
    ):
        case(
            f"widened_leaf_{dim}",
            forged(
                a,
                intent,
                [_link(root_grant, a.did, intent)],
                f"urn:uuid:00000000-0000-4000-8000-0000000002{len(cases):02d}",
            ),
            f"scope_exceeds_parent:{dim}",
            note=f"a's own credential is broader than the root grant on {dim}",
        )

    widened = {
        "action": ["read", "update", "delete"],
        "target": "calendar",
        "resource": CAL,
        "delegatee": b.did,
    }
    wide_grant = forged(
        a,
        widened,
        [_link(root_grant, a.did, widened)],
        "urn:uuid:00000000-0000-4000-8000-000000000030",
    )
    delete_intent = {"action": "delete", "target": "calendar", "resource": CAL}
    case(
        "widened_intermediate_grant",
        forged(
            b,
            delete_intent,
            [_link(root_grant, a.did, widened), _link(wide_grant, b.did, delete_intent)],
            "urn:uuid:00000000-0000-4000-8000-000000000031",
        ),
        "scope_exceeds_parent:action",
        note="a re-delegates more actions than it was granted",
    )

    short_grant = _issue(
        root,
        {"action": "read", "target": "calendar", "resource": CAL, "delegatee": a.did},
        "urn:uuid:00000000-0000-4000-8000-000000000040",
        valid_from=T0 + timedelta(hours=11),
        valid_seconds=7200,
    )
    case(
        "leaf_outlives_grant",
        forged(
            a,
            {"action": "read", "target": "calendar", "resource": CAL},
            [_link(short_grant, a.did, {"action": "read"})],
            "urn:uuid:00000000-0000-4000-8000-000000000041",
            valid_from=T0 + timedelta(hours=11),
            valid_seconds=86400,
        ),
        "scope_exceeds_parent:time",
        note="the leaf's validity runs past the grant's",
    )

    case(
        "stolen_chain",
        forged(
            mallory,
            dict(read_events),
            copy.deepcopy(links),
            "urn:uuid:00000000-0000-4000-8000-000000000050",
        ),
        "delegation_subject_issuer_mismatch",
        note="mallory presents b's chain under her own credential",
    )

    t = copy.deepcopy(links)
    t[1]["subject"] = mallory.did
    case(
        "link_subject_not_delegatee",
        forged(mallory, dict(read_events), t, "urn:uuid:00000000-0000-4000-8000-000000000051"),
        "delegation_subject_mismatch",
        note="the link names mallory but the grant names b",
    )

    bearer = _issue(
        root,
        {"action": "read", "target": "calendar", "resource": CAL},
        "urn:uuid:00000000-0000-4000-8000-000000000060",
    )
    case(
        "grant_without_delegatee",
        forged(
            a,
            dict(read_events),
            [_link(bearer, a.did, dict(read_events))],
            "urn:uuid:00000000-0000-4000-8000-000000000061",
        ),
        "delegation_no_delegatee",
        note="a grant that names no delegatee cannot be chained under",
    )

    t = copy.deepcopy(links)
    for link in t:
        del link["parentCredential"]
    case(
        "link_without_signed_grant",
        forged(b, dict(read_events), t, "urn:uuid:00000000-0000-4000-8000-000000000070"),
        "delegation_link_unsigned",
        note="links that carry no signed grant cannot be verified",
    )

    t = copy.deepcopy(links)
    t[1]["parentProofValue"] = "z" + "2" * 63
    case(
        "parent_proof_binding_mismatch",
        forged(b, dict(read_events), t, "urn:uuid:00000000-0000-4000-8000-000000000071"),
        "delegation_link_tampered",
        note="parentProofValue does not match the embedded grant's proof",
    )

    case(
        "expired_grant",
        leaf,
        "delegation_expired",
        now="2026-11-12T00:00:00Z",
        note="the valid chain evaluated after its grants expired",
    )

    return {
        "description": (
            "Delegation chain verification vectors (Specification 9.3). Each credential's "
            "delegationChain links embed the signed grant they came from (parentCredential). "
            "Evaluate verify_delegation_chain at `now`: `expected` is null for a valid chain, "
            "or the reason code. All identities are did:key, so every key resolves offline. "
            "Full credential verification at `now` must succeed exactly when `expected` is null."
        ),
        "spec": "Specification 9.3",
        "version": "1.0",
        "cases": cases,
    }


def render() -> str:
    return json.dumps(build(), indent=2, ensure_ascii=False) + "\n"


if __name__ == "__main__":
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(render(), encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}")
