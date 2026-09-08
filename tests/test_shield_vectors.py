"""Vouch Shield decisions against the shared cross-language vectors.

`test-vectors/shield/` is the contract every implementation must meet: the same
rules file, the same calls, the same verdicts, and the same reason strings
character for character. Python is the reference, so it has to pass them first.

The expectations in `cases.json` were written from the documented semantics
rather than generated from this implementation, so a disagreement means one of
the two is wrong and both are worth looking at.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vouch.shield.rules import load_rules, load_rules_file

VECTORS = Path(__file__).resolve().parents[1] / "test-vectors" / "shield"
CASES_PATH = VECTORS / "cases.json"

_doc = json.loads(CASES_PATH.read_text(encoding="utf-8"))
CASES = _doc["cases"]
DEFAULT_DID = _doc["did"]


def _ids():
    return [c["name"] for c in CASES]


@pytest.fixture(scope="module")
def default_rules():
    pytest.importorskip("yaml", reason="the shared rules file is YAML")
    return load_rules_file(VECTORS / _doc["default_rules"])


@pytest.mark.parametrize("case", CASES, ids=_ids())
def test_shield_vector(case, default_rules):
    rules = (
        load_rules(case["rules"], source=f"<case:{case['name']}>")
        if "rules" in case
        else default_rules
    )

    decision = rules.check(
        case.get("did", DEFAULT_DID),
        action=case["action"],
        target=case["target"],
        resource=case["resource"],
    )

    expected = case["expect"]
    assert decision.allow is expected["allow"], (
        f"{case['name']}: expected allow={expected['allow']}, "
        f"got {decision.allow} with reason {decision.reason!r}"
    )
    assert decision.reason == expected["reason"], (
        f"{case['name']}: expected reason {expected['reason']!r}, got {decision.reason!r}"
    )
    if "rule_id" in expected:
        assert decision.rule_id == expected["rule_id"], (
            f"{case['name']}: expected rule_id {expected['rule_id']!r}, got {decision.rule_id!r}"
        )


def test_vector_file_is_substantial():
    """A thin vector set would pass everywhere and prove nothing."""
    assert len(CASES) >= 60


def test_every_reason_string_is_exercised():
    """All six verdict reasons appear, so no implementation can stub one out."""
    reasons = {c["expect"]["reason"] for c in CASES}
    assert reasons == {
        "allowed",
        "unknown did",
        "no matching rule",
        "resource outside scope",
        "invalid resource",
        "malformed rules",
    }


def test_allow_and_deny_are_both_well_represented():
    allowed = sum(1 for c in CASES if c["expect"]["allow"])
    denied = len(CASES) - allowed
    assert allowed >= 15, "too few allow cases to catch an over-strict port"
    assert denied >= 30, "too few deny cases to catch an over-permissive port"
