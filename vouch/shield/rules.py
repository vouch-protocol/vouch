"""Vouch Shield v2 rules: action / target / resource, with globs on resource.

Shield matches on the same three fields a Vouch credential binds in
``credentialSubject.intent``. That is the whole idea: the policy asks the same
question the evidence answers, so there is no translation step in between where
authority can quietly widen.

Security posture: default-deny. A missing file, a malformed file, an unknown
key, an unparseable resource, or simply no matching rule all produce DENY. There
is no path through this module that turns a failure into an allow.

Glob semantics on ``resource`` are segment-based:

- a **segment** is the text between ``/`` separators, so ``reports/2026/q3.txt``
  has three;
- ``*`` matches exactly one segment and never crosses a ``/``;
- ``**`` matches zero or more segments and does cross ``/``;
- everything else is literal, including ``.``;
- matching is case-sensitive.

A resource with no ``/`` at all is one segment, which is what lets ``public.*``
match a table name like ``public.customers``.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

logger = logging.getLogger(__name__)

__all__ = [
    "Decision",
    "Rule",
    "RuleSet",
    "RuleError",
    "normalize_resource",
    "normalize_pattern",
    "resource_matches",
    "load_rules",
    "load_rules_file",
    "ALLOWED",
    "REASON_UNKNOWN_DID",
    "REASON_NO_MATCHING_RULE",
    "REASON_RESOURCE_OUTSIDE_SCOPE",
    "REASON_INVALID_RESOURCE",
    "REASON_MALFORMED_RULES",
]

# Stable, greppable reason strings. The demo narrates these verbatim, and
# callers are expected to branch on them, so they are part of the API.
ALLOWED = "allowed"
REASON_UNKNOWN_DID = "unknown did"
REASON_NO_MATCHING_RULE = "no matching rule"
REASON_RESOURCE_OUTSIDE_SCOPE = "resource outside scope"
REASON_INVALID_RESOURCE = "invalid resource"
REASON_MALFORMED_RULES = "malformed rules"

# A pattern deeper than this is far past anything legible, and bounds the
# backtracking in _match_segments.
_MAX_PATTERN_SEGMENTS = 64

_RULE_KEYS = {"id", "action", "target", "resource"}


class RuleError(ValueError):
    """Raised when a rules document cannot be loaded."""


@dataclass(frozen=True)
class Decision:
    """The result of a Shield check. ``allow`` is the whole answer."""

    allow: bool
    reason: str
    rule_id: Optional[str] = None

    def __bool__(self) -> bool:
        return self.allow


@dataclass(frozen=True)
class Rule:
    """One allow entry. ``action`` and ``target`` match exactly; ``resource`` globs."""

    action: str
    target: str
    resource: str
    id: str = ""

    def matches_act(self, action: str, target: str) -> bool:
        return self.action == action and self.target == target


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------


def _has_control_chars(value: str) -> bool:
    return any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in value)


def normalize_resource(value: Any) -> Optional[str]:
    """Normalise a resource string for matching, or return None if unusable.

    Lexical only: no filesystem access and no symlink resolution, because this
    is a policy string rather than a path on disk. A server that maps a resource
    onto a real path MUST additionally confine that path to its own root;
    symlinks are outside what this can see.

    Returns None (meaning "invalid, deny") for a non-string, an empty string,
    control characters, or a path that climbs above its root.
    """
    if not isinstance(value, str) or not value:
        return None
    if _has_control_chars(value):
        return None

    parts: List[str] = []
    for segment in value.split("/"):
        # Empty segments come from a leading '/', a trailing '/', or '//'.
        if segment == "" or segment == ".":
            continue
        if segment == "..":
            if parts:
                parts.pop()
            else:
                # Climbed above the root. Refuse rather than clamping to it,
                # so 'reports/../..' can never be read as 'reports'.
                return None
            continue
        parts.append(segment)

    if not parts:
        return None
    return "/".join(parts)


def normalize_pattern(value: Any) -> str:
    """Normalise a rule's resource pattern. Raises RuleError if unusable.

    Deliberately stricter than :func:`normalize_resource`: a pattern containing
    ``.`` or ``..`` segments is a mistake in the rules file, not something to
    silently resolve, because the author's intent is ambiguous.
    """
    if not isinstance(value, str) or not value:
        raise RuleError("resource pattern must be a non-empty string")
    if _has_control_chars(value):
        raise RuleError("resource pattern contains control characters")

    segments = [s for s in value.split("/") if s != ""]
    if not segments:
        raise RuleError(f"resource pattern is empty after normalisation: {value!r}")
    if len(segments) > _MAX_PATTERN_SEGMENTS:
        raise RuleError(f"resource pattern has too many segments: {value!r}")

    for segment in segments:
        if segment in (".", ".."):
            raise RuleError(f"resource pattern must not contain '.' or '..' segments: {value!r}")
        if "**" in segment and segment != "**":
            raise RuleError(f"'**' must be a whole segment, not part of one: {value!r}")
    return "/".join(segments)


# ---------------------------------------------------------------------------
# Glob matching
# ---------------------------------------------------------------------------


def _segment_regex(segment: str) -> "re.Pattern[str]":
    # '*' becomes 'any run of non-slash characters'; everything else literal.
    parts = [".*" if piece == "*" else re.escape(piece) for piece in _split_stars(segment)]
    return re.compile("^" + "".join(parts) + "$")


def _split_stars(segment: str) -> List[str]:
    out: List[str] = []
    buf = ""
    for char in segment:
        if char == "*":
            if buf:
                out.append(buf)
                buf = ""
            out.append("*")
        else:
            buf += char
    if buf:
        out.append(buf)
    return out


def _match_one(pattern_segment: str, segment: str) -> bool:
    if pattern_segment == "*":
        return True
    if "*" not in pattern_segment:
        return pattern_segment == segment
    return bool(_segment_regex(pattern_segment).match(segment))


def _match_segments(pattern: Sequence[str], resource: Sequence[str]) -> bool:
    if not pattern:
        return not resource
    head = pattern[0]
    if head == "**":
        # Zero or more segments. Try every split; patterns are tiny and bounded
        # by _MAX_PATTERN_SEGMENTS, so the branching is not a concern.
        rest = pattern[1:]
        for index in range(len(resource) + 1):
            if _match_segments(rest, resource[index:]):
                return True
        return False
    if not resource:
        return False
    if not _match_one(head, resource[0]):
        return False
    return _match_segments(pattern[1:], resource[1:])


def resource_matches(pattern: str, resource: str) -> bool:
    """Does a normalised resource match a normalised pattern?

    Both arguments are expected to have been through the relevant normaliser.
    """
    return _match_segments(pattern.split("/"), resource.split("/"))


# ---------------------------------------------------------------------------
# Rule sets
# ---------------------------------------------------------------------------


@dataclass
class RuleSet:
    """Parsed rules. A RuleSet that failed to load denies everything."""

    by_did: Dict[str, List[Rule]] = field(default_factory=dict)
    malformed_reason: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.malformed_reason is None

    def check(self, did: str, action: str, target: str, resource: str) -> Decision:
        """Decide one call. See module docstring for glob semantics."""
        if self.malformed_reason is not None:
            return Decision(False, REASON_MALFORMED_RULES)

        normalised = normalize_resource(resource)
        if normalised is None:
            return Decision(False, REASON_INVALID_RESOURCE)

        rules = self.by_did.get(did)
        if not rules:
            return Decision(False, REASON_UNKNOWN_DID)

        # Track whether anything matched action+target, so the caller can be
        # told the difference between "you may not do this" and "you may do
        # this, but not there".
        act_matched = False
        for rule in rules:
            if not rule.matches_act(action, target):
                continue
            act_matched = True
            if resource_matches(rule.resource, normalised):
                return Decision(True, ALLOWED, rule.id)

        if act_matched:
            return Decision(False, REASON_RESOURCE_OUTSIDE_SCOPE)
        return Decision(False, REASON_NO_MATCHING_RULE)


def _deny_all(reason: str) -> RuleSet:
    logger.error("Vouch Shield: denying all calls - %s", reason)
    return RuleSet(malformed_reason=reason)


def load_rules(document: Any, *, source: str = "<memory>") -> RuleSet:
    """Build a RuleSet from an already-parsed document.

    Any structural problem yields a deny-all RuleSet rather than raising, so a
    bad rules file degrades to "nothing is permitted" instead of taking the
    server down in a state where its posture is unclear.
    """
    try:
        return _load_rules_strict(document, source=source)
    except RuleError as exc:
        return _deny_all(f"{source}: {exc}")
    except Exception as exc:  # unknown shape - still deny
        return _deny_all(f"{source}: unexpected error reading rules: {exc}")


def _load_rules_strict(document: Any, *, source: str) -> RuleSet:
    if not isinstance(document, dict):
        raise RuleError("rules document must be a mapping")

    version = document.get("version")
    if version != 2:
        raise RuleError(
            f"unsupported rules version {version!r}; this Shield reads version 2. "
            "See docs/design/shield-v2-and-protected-mcp.md for the format."
        )

    deny_default = document.get("deny_default", True)
    if deny_default is not True:
        raise RuleError("deny_default must be true; Shield has no allow-by-default mode")

    raw_rules = document.get("rules")
    if raw_rules is None:
        raw_rules = []
    if not isinstance(raw_rules, list):
        raise RuleError("rules must be a list")

    by_did: Dict[str, List[Rule]] = {}
    for block_index, block in enumerate(raw_rules):
        if not isinstance(block, dict):
            raise RuleError(f"rules[{block_index}] must be a mapping")
        unknown = set(block) - {"did", "allow"}
        if unknown:
            raise RuleError(f"rules[{block_index}] has unknown keys: {sorted(unknown)}")
        did = block.get("did")
        if not isinstance(did, str) or not did:
            raise RuleError(f"rules[{block_index}].did must be a non-empty string")

        allow = block.get("allow")
        if not isinstance(allow, list):
            raise RuleError(f"rules[{block_index}].allow must be a list")

        parsed: List[Rule] = []
        for entry_index, entry in enumerate(allow):
            where = f"rules[{block_index}].allow[{entry_index}]"
            if not isinstance(entry, dict):
                raise RuleError(f"{where} must be a mapping")
            unknown = set(entry) - _RULE_KEYS
            if unknown:
                # A typo like 'resourse:' must not become an allow-anything
                # rule by having its constraint silently ignored.
                raise RuleError(f"{where} has unknown keys: {sorted(unknown)}")
            for required in ("action", "target", "resource"):
                value = entry.get(required)
                if not isinstance(value, str) or not value:
                    raise RuleError(f"{where}.{required} must be a non-empty string")
            rule_id = entry.get("id") or f"{did}#{entry_index}"
            if not isinstance(rule_id, str):
                raise RuleError(f"{where}.id must be a string")
            parsed.append(
                Rule(
                    action=entry["action"],
                    target=entry["target"],
                    resource=normalize_pattern(entry["resource"]),
                    id=rule_id,
                )
            )

        by_did.setdefault(did, []).extend(parsed)

    return RuleSet(by_did=by_did)


def load_rules_file(path: Union[str, Path]) -> RuleSet:
    """Load a v2 rules file. JSON and YAML are both accepted.

    A missing or unreadable file denies everything, loudly.
    """
    p = Path(path)
    try:
        text = p.read_text()
    except FileNotFoundError:
        return _deny_all(f"rules file not found: {p}")
    except OSError as exc:
        return _deny_all(f"rules file could not be read: {p}: {exc}")

    document, error = _parse_document(text, p)
    if error is not None:
        return _deny_all(error)
    return load_rules(document, source=str(p))


def _parse_document(text: str, path: Path) -> Tuple[Any, Optional[str]]:
    """Parse JSON or YAML. Returns (document, error_message)."""
    suffix = path.suffix.lower()
    if suffix in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError:
            return None, (
                f"{path}: YAML rules need PyYAML. Install it with "
                "'pip install pyyaml', or write the rules as JSON."
            )
        try:
            return yaml.safe_load(text), None
        except yaml.YAMLError as exc:
            return None, f"{path}: invalid YAML: {exc}"

    try:
        return json.loads(text), None
    except json.JSONDecodeError as json_exc:
        # A .json suffix is a clear declaration of intent; anything else might
        # be YAML with an unusual name, so try that before giving up.
        if suffix == ".json":
            return None, f"{path}: invalid JSON: {json_exc}"
        try:
            import yaml

            return yaml.safe_load(text), None
        except ImportError:
            return None, f"{path}: invalid JSON: {json_exc}"
        except yaml.YAMLError as yaml_exc:
            return None, f"{path}: parsed as neither JSON ({json_exc}) nor YAML ({yaml_exc})"
