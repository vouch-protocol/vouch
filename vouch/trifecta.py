"""
Lethal-trifecta linter for agent capability sets.

Simon Willison's "lethal trifecta": an agent becomes dangerous when it combines,
in one session, all three of

  1. access to private data,
  2. exposure to untrusted input, and
  3. a way to exfiltrate (send data outward).

Any two are usually fine; all three together means untrusted input can steer the
agent into reading private data and shipping it out. This linter inspects the
capability set an agent has been granted (its Vouch credential intent, scopes,
and delegation chain) and flags or refuses a set that holds all three.

It is deliberately simple and free: a default keyword classifier plus the option
to extend it. The customer-policy-aware, allow-list version is out of scope here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set

PRIVATE_DATA = "private_data"
UNTRUSTED_INPUT = "untrusted_input"
EXFILTRATION = "exfiltration"

CATEGORIES = (PRIVATE_DATA, UNTRUSTED_INPUT, EXFILTRATION)

# Default keyword rules. A capability is split into tokens (on non-alphanumeric
# separators) and a category matches when one of its keywords equals a whole
# token. Token matching, not substring, so "widget" does not match "get" and
# "monkey" does not match "key". A capability can fall in more than one category
# (for example "read_email": "read" is private data, "email" is untrusted input).
DEFAULT_RULES: Dict[str, Set[str]] = {
    PRIVATE_DATA: {
        "read",
        "get",
        "query",
        "db",
        "database",
        "sql",
        "file",
        "files",
        "fs",
        "secret",
        "secrets",
        "credential",
        "key",
        "pii",
        "patient",
        "record",
        "inbox",
        "email_read",
        "read_email",
        "calendar",
        "contacts",
        "memory",
        "vault",
    },
    UNTRUSTED_INPUT: {
        "web",
        "http_get",
        "fetch",
        "browse",
        "scrape",
        "crawl",
        "url",
        "search",
        "rss",
        "webhook",
        "inbox",
        "email_read",
        "read_email",
        "user_input",
        "prompt",
        "comment",
        "issue",
        "ticket",
        "untrusted",
        "email",
        "input",
    },
    EXFILTRATION: {
        "http_post",
        "post",
        "put",
        "send",
        "send_email",
        "email_send",
        "publish",
        "upload",
        "write_external",
        "network",
        "request",
        "webhook_post",
        "dns",
        "exec",
        "shell",
        "command",
        "deploy",
        "tweet",
        "slack",
        "discord",
        "outbound",
        "write",
        "external",
    },
}


def _tokens(capability: str) -> Set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", capability.lower()) if t}


def classify_capability(capability: str, rules: Optional[Dict[str, Set[str]]] = None) -> Set[str]:
    """Return the set of trifecta categories a single capability falls into."""
    rules = rules or DEFAULT_RULES
    tokens = _tokens(capability)
    hits: Set[str] = set()
    for category, keywords in rules.items():
        if tokens & keywords:
            hits.add(category)
    return hits


@dataclass
class TrifectaResult:
    """
    Outcome of analyzing a capability set.

    Attributes:
      lethal: True if all three categories are present at once.
      present: which categories are present.
      contributing: category -> the capabilities that put it there.
      unclassified: capabilities that matched no category.
    """

    lethal: bool
    present: Set[str]
    contributing: Dict[str, List[str]] = field(default_factory=dict)
    unclassified: List[str] = field(default_factory=list)

    @property
    def missing(self) -> Set[str]:
        return set(CATEGORIES) - self.present

    def to_dict(self) -> Dict[str, Any]:
        return {
            "lethal": self.lethal,
            "present": sorted(self.present),
            "missing": sorted(self.missing),
            "contributing": {k: sorted(v) for k, v in self.contributing.items()},
            "unclassified": sorted(self.unclassified),
        }


def analyze(
    capabilities: Iterable[str],
    rules: Optional[Dict[str, Set[str]]] = None,
) -> TrifectaResult:
    """Analyze a capability set for the lethal trifecta."""
    contributing: Dict[str, List[str]] = {}
    unclassified: List[str] = []
    for cap in capabilities:
        cats = classify_capability(cap, rules)
        if not cats:
            unclassified.append(cap)
        for c in cats:
            contributing.setdefault(c, []).append(cap)
    present = set(contributing.keys())
    return TrifectaResult(
        lethal=present.issuperset(CATEGORIES),
        present=present,
        contributing=contributing,
        unclassified=unclassified,
    )


def capabilities_from_credential(credential: Dict[str, Any]) -> List[str]:
    """
    Extract capability tokens from a Vouch credential: the intent action and
    resource, any scope list, and the same fields down the delegation chain.
    """
    caps: List[str] = []
    subject = credential.get("credentialSubject", {}) or {}

    def _from_intent(intent: Dict[str, Any]) -> None:
        if not isinstance(intent, dict):
            return
        for field_name in ("action", "target", "resource"):
            val = intent.get(field_name)
            if isinstance(val, str) and val:
                caps.append(val)

    _from_intent(subject.get("intent", {}))

    scope = subject.get("scope")
    if isinstance(scope, list):
        caps.extend(str(s) for s in scope)

    for link in subject.get("delegationChain", []) or []:
        if isinstance(link, dict):
            _from_intent(link.get("intent", {}))
            link_scope = link.get("scope")
            if isinstance(link_scope, list):
                caps.extend(str(s) for s in link_scope)

    return caps


def analyze_credential(
    credential: Dict[str, Any],
    rules: Optional[Dict[str, Set[str]]] = None,
) -> TrifectaResult:
    """Convenience: extract capabilities from a credential and analyze them."""
    return analyze(capabilities_from_credential(credential), rules)
