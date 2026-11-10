#!/usr/bin/env python3
"""
Maintain test-vectors/delegation-attenuation/vector.json.

The base cases were authored with the Rust core, which owns the request/verdict
schema (core::attenuation). This script adds, or replaces by name, the cases for
numeric policy direction, spend caps, and inherited dimensions, then rewrites
the file. It is idempotent: running it twice produces the same bytes.

Numeric policy rule (Specification 9.3, policy dimension):
  - a key starting with "max" is a ceiling: the child may lower it, never raise it;
  - a key starting with "min" is a floor: the child may raise it, never lower it;
  - any other numeric key must be restated unchanged.
Spend: a child whose intent carries `amount` may not exceed the parent's
`policy.maxSpend`. Inheritance: a dimension a link omits is inherited from its
parent, so a later link is compared against the inherited value.

Every expected verdict is computed by the Python reference
(`vouch.attenuation.validate_chain_json`) and asserted against the intended one.

Run: python scripts/gen_attenuation_vectors.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vouch.attenuation import validate_chain_json  # noqa: E402

OUT = ROOT / "test-vectors" / "delegation-attenuation" / "vector.json"
NOW = "2026-04-26T10:00:00Z"
VF = "2026-04-26T09:00:00Z"
VU = "2026-04-26T12:00:00Z"


def _link(
    issuer: str, subject: str, intent: Dict[str, Any], policy: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    link: Dict[str, Any] = {
        "issuer": issuer,
        "subject": subject,
        "intent": intent,
        "validFrom": VF,
        "validUntil": VU,
    }
    if policy is not None:
        link["policy"] = policy
    return link


def _matches(got: Dict[str, Any], expect: Dict[str, Any]) -> bool:
    """A verdict matches when every expected key agrees (free-text detail is not pinned)."""
    return all(got.get(k) == v for k, v in expect.items())


def _case(name: str, chain: List[Dict[str, Any]], expect: Dict[str, Any]) -> Dict[str, Any]:
    request = {"chain": chain, "nowIso": NOW}
    got = json.loads(validate_chain_json(json.dumps(request)))
    if not _matches(got, expect) or set(got) - set(expect) - {"detail"}:
        raise SystemExit(f"{name}: reference returned {got}, intended {expect}")
    return {"name": name, "request": request, "expect": expect}


REJECT_POLICY = {"valid": False, "code": "scope_exceeds_parent", "dimension": "policy"}
VALID = {"valid": True}


def new_cases() -> List[Dict[str, Any]]:
    read = {"action": "read"}
    return [
        _case(
            "policy_cap_lowered_valid",
            [
                _link("did:web:root", "did:web:a", read, {"maxSpend": 50}),
                _link("did:web:a", "did:web:b", read, {"maxSpend": 20}),
            ],
            VALID,
        ),
        _case(
            "policy_cap_raised_rejected",
            [
                _link("did:web:root", "did:web:a", read, {"maxSpend": 50}),
                _link("did:web:a", "did:web:b", read, {"maxSpend": 100}),
            ],
            REJECT_POLICY,
        ),
        _case(
            "policy_unnamed_numeric_restated_valid",
            [
                _link("did:web:root", "did:web:a", read, {"retries": 3}),
                _link("did:web:a", "did:web:b", read, {"retries": 3}),
            ],
            VALID,
        ),
        _case(
            "policy_unnamed_numeric_changed_rejected",
            [
                _link("did:web:root", "did:web:a", read, {"retries": 3}),
                _link("did:web:a", "did:web:b", read, {"retries": 5}),
            ],
            REJECT_POLICY,
        ),
        _case(
            "spend_within_parent_cap_valid",
            [
                _link("did:web:root", "did:web:a", read, {"maxSpend": 20}),
                _link("did:web:a", "did:web:b", {"action": "read", "amount": 15}),
            ],
            VALID,
        ),
        _case(
            "spend_over_parent_cap_rejected",
            [
                _link("did:web:root", "did:web:a", read, {"maxSpend": 20}),
                _link("did:web:a", "did:web:b", {"action": "read", "amount": 30}),
            ],
            REJECT_POLICY,
        ),
        _case(
            "spend_amount_not_a_number_rejected",
            [
                _link("did:web:root", "did:web:a", read, {"maxSpend": 20}),
                _link("did:web:a", "did:web:b", {"action": "read", "amount": "15"}),
            ],
            REJECT_POLICY,
        ),
        _case(
            "inherited_cap_binds_grandchild",
            [
                _link("did:web:root", "did:web:a", read, {"maxSpend": 50}),
                _link("did:web:a", "did:web:b", read),
                _link("did:web:b", "did:web:c", read, {"maxSpend": 100}),
            ],
            REJECT_POLICY,
        ),
        _case(
            "inherited_cap_binds_grandchild_spend",
            [
                _link("did:web:root", "did:web:a", read, {"maxSpend": 50}),
                _link("did:web:a", "did:web:b", read),
                _link("did:web:b", "did:web:c", {"action": "read", "amount": 80}),
            ],
            REJECT_POLICY,
        ),
        _case(
            "inherited_action_binds_grandchild",
            [
                _link("did:web:root", "did:web:a", {"action": "read"}),
                _link("did:web:a", "did:web:b", {}),
                _link("did:web:b", "did:web:c", {"action": "delete"}),
            ],
            {"valid": False, "code": "scope_exceeds_parent", "dimension": "action"},
        ),
    ]


def render() -> str:
    vector = json.loads(OUT.read_text(encoding="utf-8"))
    added = new_cases()
    names = {c["name"] for c in added}
    vector["cases"] = [c for c in vector["cases"] if c["name"] not in names] + added
    for case in vector["cases"]:
        got = json.loads(validate_chain_json(json.dumps(case["request"])))
        if not _matches(got, case["expect"]):
            raise SystemExit(
                f"{case['name']}: reference returned {got}, vector says {case['expect']}"
            )
    return json.dumps(vector, indent=2, ensure_ascii=False) + "\n"


if __name__ == "__main__":
    OUT.write_text(render(), encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}")
