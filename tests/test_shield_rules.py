"""Shield v2: action / target / resource rules with globs on resource.

The property under test throughout is that nothing is permitted unless a rule
says so, and that a rule says only what it appears to say.
"""

from __future__ import annotations

import json

import pytest

from vouch.shield import Shield, ShieldConfig
from vouch.shield.rules import (
    Decision,
    load_rules,
    load_rules_file,
    normalize_pattern,
    normalize_resource,
    resource_matches,
)

DID = "did:web:agent.example.com"
OTHER = "did:web:someone-else.example.com"


def doc(*allow, did=DID):
    return {"version": 2, "rules": [{"did": did, "allow": list(allow)}], "deny_default": True}


def rule(action="read_file", target="filesystem", resource="reports/**", **kw):
    return {"action": action, "target": target, "resource": resource, **kw}


@pytest.fixture
def rules():
    return load_rules(doc(rule(id="reports-read")))


# ---------------------------------------------------------------------------
# The three fields
# ---------------------------------------------------------------------------


def test_allows_when_all_three_fields_match(rules):
    decision = rules.check(DID, "read_file", "filesystem", "reports/q3.txt")
    assert decision.allow
    assert decision.reason == "allowed"
    assert decision.rule_id == "reports-read"


def test_denies_on_action_mismatch(rules):
    decision = rules.check(DID, "write_file", "filesystem", "reports/q3.txt")
    assert not decision.allow
    assert decision.reason == "no matching rule"


def test_denies_on_target_mismatch(rules):
    decision = rules.check(DID, "read_file", "network", "reports/q3.txt")
    assert not decision.allow
    assert decision.reason == "no matching rule"


def test_denies_on_resource_mismatch_with_a_distinct_reason(rules):
    """'you may not do this' and 'not there' are different things to say."""
    decision = rules.check(DID, "read_file", "filesystem", "secrets/keys.txt")
    assert not decision.allow
    assert decision.reason == "resource outside scope"


def test_unknown_did_is_denied(rules):
    decision = rules.check(OTHER, "read_file", "filesystem", "reports/q3.txt")
    assert not decision.allow
    assert decision.reason == "unknown did"


def test_action_and_target_are_case_sensitive(rules):
    assert not rules.check(DID, "READ_FILE", "filesystem", "reports/q3.txt").allow
    assert not rules.check(DID, "read_file", "Filesystem", "reports/q3.txt").allow


def test_decision_is_falsy_when_denied(rules):
    assert not rules.check(DID, "read_file", "filesystem", "secrets/x")
    assert rules.check(DID, "read_file", "filesystem", "reports/x")


# ---------------------------------------------------------------------------
# Glob depth semantics
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern,resource,expected",
    [
        # '**' is any depth, including the bare prefix.
        ("reports/**", "reports", True),
        ("reports/**", "reports/q3.txt", True),
        ("reports/**", "reports/2026/q3.txt", True),
        ("reports/**", "reports/a/b/c/d", True),
        ("reports/**", "secrets/keys.txt", False),
        # A prefix must match a whole segment, not a substring.
        ("reports/**", "reportsX/a", False),
        # '*' is exactly one segment.
        ("reports/*", "reports/q3.txt", True),
        ("reports/*", "reports/2026/q3.txt", False),
        ("reports/*", "reports", False),
        # '**' in the middle.
        ("a/**/b", "a/b", True),
        ("a/**/b", "a/x/b", True),
        ("a/**/b", "a/x/y/b", True),
        ("a/**/b", "a/x/c", False),
        # Everything.
        ("**", "anything/at/all", True),
        ("**", "single", True),
        # A resource with no '/' is one segment, which is what makes a
        # non-path resource such as a table name work.
        ("public.*", "public.customers", True),
        ("public.*", "internal.salaries", False),
        # '.' is literal, not a regex wildcard.
        ("a.b", "axb", False),
        ("a.b", "a.b", True),
    ],
)
def test_glob_depth_semantics(pattern, resource, expected):
    assert resource_matches(normalize_pattern(pattern), normalize_resource(resource)) is expected


# ---------------------------------------------------------------------------
# Normalisation and traversal
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("reports/q3.txt", "reports/q3.txt"),
        ("/reports/q3.txt", "reports/q3.txt"),
        ("reports//q3.txt", "reports/q3.txt"),
        ("reports/./q3.txt", "reports/q3.txt"),
        ("reports/", "reports"),
        ("a/b/../c", "a/c"),
        # Escapes the root: refused rather than clamped.
        ("../x", None),
        ("..", None),
        ("reports/../..", None),
        ("", None),
        ("a\x00b", None),
        ("a\x1fb", None),
    ],
)
def test_normalisation(raw, expected):
    assert normalize_resource(raw) == expected


def test_traversal_cannot_reach_outside_the_glob():
    """The case the whole normalisation step exists for."""
    rules = load_rules(doc(rule(resource="reports/**")))
    decision = rules.check(DID, "read_file", "filesystem", "reports/../etc/passwd")
    assert not decision.allow
    assert decision.reason == "resource outside scope"


def test_leading_slash_and_double_slash_do_not_change_the_verdict():
    rules = load_rules(doc(rule(resource="reports/**")))
    for variant in ("reports/q3.txt", "/reports/q3.txt", "reports//q3.txt", "reports/./q3.txt"):
        assert rules.check(DID, "read_file", "filesystem", variant).allow, variant


def test_control_characters_are_refused_with_their_own_reason():
    rules = load_rules(doc(rule()))
    decision = rules.check(DID, "read_file", "filesystem", "reports/\x00etc")
    assert not decision.allow
    assert decision.reason == "invalid resource"


def test_a_rule_pattern_is_normalised_too():
    """'/reports/**' and 'reports/**' mean the same thing."""
    rules = load_rules(doc(rule(resource="/reports/**")))
    assert rules.check(DID, "read_file", "filesystem", "reports/q3.txt").allow


# ---------------------------------------------------------------------------
# Fail closed
# ---------------------------------------------------------------------------


def test_empty_rules_denies_everything():
    rules = load_rules({"version": 2, "rules": [], "deny_default": True})
    assert rules.ok
    assert not rules.check(DID, "read_file", "filesystem", "reports/q3.txt").allow


def test_no_rules_key_denies_everything():
    rules = load_rules({"version": 2, "deny_default": True})
    assert not rules.check(DID, "read_file", "filesystem", "reports/q3.txt").allow


@pytest.mark.parametrize(
    "document",
    [
        {"rules": []},  # no version
        {"version": 1, "rules": []},  # v1
        {"version": 2, "rules": {}},  # rules not a list
        {"version": 2, "rules": [{"did": DID}]},  # no allow
        {"version": 2, "rules": [{"did": "", "allow": []}]},
        {"version": 2, "rules": [{"allow": []}]},  # no did
        {"version": 2, "rules": [{"did": DID, "allow": [{"action": "a", "target": "b"}]}]},
        {"version": 2, "rules": [{"did": DID, "allow": [{}]}]},
        {"version": 2, "rules": [], "deny_default": False},
        "not a mapping",
        None,
    ],
)
def test_malformed_rules_deny_everything(document, caplog):
    rules = load_rules(document)
    assert not rules.ok
    decision = rules.check(DID, "read_file", "filesystem", "reports/q3.txt")
    assert not decision.allow
    assert decision.reason == "malformed rules"


def test_malformed_rules_are_logged(caplog):
    with caplog.at_level("ERROR"):
        load_rules({"version": 1, "rules": []})
    assert any("denying all calls" in r.getMessage() for r in caplog.records)


def test_a_typo_in_a_rule_key_is_rejected_not_ignored():
    """'resourse' must not become an allow-anything rule."""
    document = {
        "version": 2,
        "rules": [{"did": DID, "allow": [{"action": "a", "target": "b", "resourse": "x"}]}],
        "deny_default": True,
    }
    rules = load_rules(document)
    assert not rules.ok
    assert not rules.check(DID, "a", "b", "anything").allow


def test_unknown_block_key_is_rejected():
    document = {
        "version": 2,
        "rules": [{"did": DID, "allow": [], "deny": [rule()]}],
        "deny_default": True,
    }
    assert not load_rules(document).ok


@pytest.mark.parametrize("bad", ["a/**b", "a/../b", "a/./b", "", "**b"])
def test_malformed_resource_patterns_are_rejected(bad):
    assert not load_rules(doc(rule(resource=bad))).ok


def test_missing_rules_file_denies_everything(tmp_path):
    rules = load_rules_file(tmp_path / "nope.yaml")
    assert not rules.ok
    assert rules.check(DID, "read_file", "filesystem", "x").reason == "malformed rules"


# ---------------------------------------------------------------------------
# File loading
# ---------------------------------------------------------------------------


def test_loads_json_rules(tmp_path):
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(doc(rule())))
    assert load_rules_file(path).check(DID, "read_file", "filesystem", "reports/x").allow


def test_loads_yaml_rules(tmp_path):
    pytest.importorskip("yaml")
    path = tmp_path / "rules.yaml"
    path.write_text(
        "version: 2\n"
        "rules:\n"
        f"  - did: {DID}\n"
        "    allow:\n"
        '      - {action: read_file, target: filesystem, resource: "reports/**"}\n'
        "deny_default: true\n"
    )
    rules = load_rules_file(path)
    assert rules.ok
    assert rules.check(DID, "read_file", "filesystem", "reports/q3.txt").allow
    assert not rules.check(DID, "read_file", "filesystem", "secrets/x").allow


def test_invalid_json_file_denies_everything(tmp_path):
    path = tmp_path / "rules.json"
    path.write_text("{not json")
    assert not load_rules_file(path).ok


def test_rule_ids_are_assigned_when_absent():
    rules = load_rules(doc(rule(), rule(action="list_dir")))
    decision = rules.check(DID, "list_dir", "filesystem", "reports/x")
    assert decision.allow
    assert decision.rule_id == f"{DID}#1"


def test_several_rules_for_one_did_are_all_considered():
    rules = load_rules(doc(rule(), rule(action="list_dir", resource="logs/**")))
    assert rules.check(DID, "read_file", "filesystem", "reports/x").allow
    assert rules.check(DID, "list_dir", "filesystem", "logs/a/b").allow
    assert not rules.check(DID, "list_dir", "filesystem", "reports/x").allow


# ---------------------------------------------------------------------------
# The Shield facade
# ---------------------------------------------------------------------------


def test_shield_with_no_rules_path_denies_everything():
    shield = Shield(ShieldConfig(require_signature=False))
    assert not shield.check(DID, "read_file", "filesystem", "reports/q3.txt").allow


def test_shield_check_from_a_file(tmp_path):
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(doc(rule())))
    shield = Shield(ShieldConfig(rules_path=str(path), require_signature=False))

    assert shield.check(DID, "read_file", "filesystem", "reports/q3.txt").allow
    assert not shield.check(DID, "read_file", "filesystem", "secrets/k").allow


def test_shield_allow_adds_an_in_memory_rule():
    shield = Shield(ShieldConfig(require_signature=False))
    shield.allow(DID, action="read_file", target="filesystem", resource="reports/**")

    assert shield.check(DID, "read_file", "filesystem", "reports/q3.txt").allow
    assert not shield.check(DID, "read_file", "filesystem", "etc/passwd").allow
    assert len(shield.rules_for(DID)) == 1


def test_shield_intercept_defaults_resource_to_the_arguments():
    """Without an explicit resource, a decision binds to these exact arguments."""
    from vouch import jcs

    shield = Shield(ShieldConfig(require_signature=False, default_target="tool"))
    shield.trust_did(DID)
    args = {"path": "reports/q3.txt"}
    shield.allow(DID, action="read_file", target="tool", resource=jcs.canonicalize_str(args))

    assert shield.intercept(tool="read_file", args=args, did=DID).allowed
    # Different arguments, so a different resource, so no match.
    assert not shield.intercept(tool="read_file", args={"path": "reports/q4.txt"}, did=DID).allowed


def test_decision_is_immutable():
    """A decision is a verdict, not a mutable flag someone can flip later."""
    import dataclasses

    decision = Decision(True, "allowed", "r1")
    with pytest.raises(dataclasses.FrozenInstanceError):
        decision.allow = False  # type: ignore[misc]
