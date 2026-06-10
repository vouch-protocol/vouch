#!/usr/bin/env python3
"""
Agent Trust Index, self-check grader (CLI).

Run it on your own agent's domain (or its did:web identifier) and it tells you
the Trust Score, the letter grade, and exactly what to fix to score higher.

    python grader/grade.py feedoracle.io
    python grader/grade.py did:web:example.com
    python grader/grade.py example.com --json

It reuses the live scanner's own resolver and scorer (ati.core), so the grade
you see here is the same grade the public Index would give you. Nothing is sent
anywhere: it just fetches the identity document your domain publishes and reads it.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

# Make sure we can import the ati package whether you run this from the repo root
# or from inside the grader/ folder.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from ati.core import resolve_domain, score  # noqa: E402


def normalize_domain(value: str) -> str:
    """Accept a bare domain, a URL, or a did:web identifier and return the host.

    The scanner resolves identity at <domain>/.well-known/did.json, so all we
    need out of any of these forms is the domain host.
        feedoracle.io                 -> feedoracle.io
        https://feedoracle.io/path    -> feedoracle.io
        did:web:example.com           -> example.com
        did:web:example.com:user:bob  -> example.com  (host segment only)
    """
    value = value.strip()
    if value.startswith("did:web:"):
        rest = value[len("did:web:") :]
        # The first colon-separated segment is the host (it may be percent-encoded
        # to carry a port, which the resolver itself decodes).
        host = rest.split(":", 1)[0]
        return host.replace("%3A", ":").replace("%3a", ":")
    # Strip a scheme and any path/query if someone pasted a full URL.
    if "://" in value:
        value = value.split("://", 1)[1]
    value = value.split("/", 1)[0]
    value = value.split("?", 1)[0]
    return value


# Each check: the signal flag it depends on, a human label, and the fix to print
# when it is missing. Order is from foundational to advanced, so the fix list
# reads like a roadmap.
CHECKS = [
    {
        "key": "has_did",
        "points": 60,
        "scored": True,
        "label": "Resolvable identity (did:web)",
        "pass_msg": "Your domain publishes a DID document that resolves.",
        "fix_title": "Publish a DID document",
        "fix": (
            "Publish a DID document at https://{domain}/.well-known/did.json so "
            "anyone can look up who your agent is. This is the single biggest "
            "thing you can do: it is worth 60 of the 100 points."
        ),
    },
    {
        "key": "has_verification_method",
        "points": 40,
        "scored": True,
        "label": "Usable verification key",
        "pass_msg": "Your identity document carries a public key others can verify against.",
        "fix_title": "Add a verification key",
        "fix": (
            "Add a verification method with a public key to your DID document, in "
            "either JWK or Multikey form. Without a key, others can find your "
            "identity but cannot check a signature against it. Worth 40 points."
        ),
    },
    {
        "key": "pq_ready",
        "points": 0,
        "scored": False,
        "label": "Post-quantum ready",
        "pass_msg": "Your key set includes a post-quantum key (ML-DSA).",
        "fix_title": "Add a post-quantum key",
        "fix": (
            "Add an ML-DSA-44 key alongside your Ed25519 key so your identity "
            "still holds up once quantum computers can break today's signatures. "
            "This is a forward-looking signal the Index will start rewarding."
        ),
    },
    {
        "key": "has_revocation",
        "points": 0,
        "scored": False,
        "label": "Service endpoint (revocation, MCP, A2A)",
        "pass_msg": "Your DID document publishes a service endpoint others can reach.",
        "fix_title": "Publish a service endpoint",
        "fix": (
            "Add a service entry to your DID document. The highest value one is a "
            "revocation status list (for example BitstringStatusList) so others can "
            "confirm your agent's authority has not been pulled, but MCP and A2A "
            "endpoints count too."
        ),
    },
    {
        "key": "has_card_identity",
        "points": 0,
        "scored": False,
        "label": "Signed agent card",
        "pass_msg": "Your agent card carries identity (a DID or a signature).",
        "fix_title": "Carry identity in your agent card",
        "fix": (
            "Reference your DID or include a signature in your agent card at "
            "https://{domain}/.well-known/agent.json so tools that read the card "
            "can tie it back to your verifiable identity."
        ),
    },
]

# Match the public site's grade colors so the badge looks identical.
GRADE_COLORS = {"A": "#2f7d4f", "B": "#3fa05f", "C": "#9a7d1f", "D": "#b56b28", "F": "#9b3b44"}


def evaluate(domain: str) -> dict:
    """Resolve, score, and assemble a full breakdown plus fix-it guidance."""
    signals = resolve_domain(domain)
    scored = score(signals)

    breakdown = []
    fixes = []
    for check in CHECKS:
        passed = bool(signals.get(check["key"]))
        breakdown.append(
            {
                "label": check["label"],
                "passed": passed,
                "scored": check["scored"],
                "points": check["points"] if (check["scored"] and passed) else 0,
                "max_points": check["points"] if check["scored"] else 0,
                "message": check["pass_msg"] if passed else check["fix"].format(domain=domain),
            }
        )
        if not passed:
            fixes.append(
                {
                    "title": check["fix_title"],
                    "detail": check["fix"].format(domain=domain),
                    "points": check["points"] if check["scored"] else 0,
                }
            )

    return {
        "domain": domain,
        "did": signals.get("did") or f"did:web:{domain}",
        "score": scored["score"],
        "grade": scored["grade"],
        "method": signals.get("method"),
        "signals": signals,
        "breakdown": breakdown,
        "fixes": fixes,
    }


# ----- pretty terminal output -------------------------------------------------

_BOLD = "\033[1m"
_DIM = "\033[2m"
_RESET = "\033[0m"
_GREEN = "\033[32m"
_RED = "\033[31m"
_YELLOW = "\033[33m"


def _color(text: str, code: str, use_color: bool) -> str:
    return f"{code}{text}{_RESET}" if use_color else text


def print_report(result: dict, use_color: bool = True) -> None:
    g = result["grade"]
    s = result["score"]
    grade_code = {"A": _GREEN, "B": _GREEN, "C": _YELLOW, "D": _YELLOW, "F": _RED}.get(g, "")

    print()
    print(_color("Agent Trust Index, self-check", _BOLD, use_color))
    print(_color("=" * 60, _DIM, use_color))
    print(f"Domain   {result['domain']}")
    print(f"Identity {result['did']}")
    print()
    print(
        f"  Grade {_color(g, _BOLD + grade_code, use_color)}    "
        f"Trust Score {_color(str(s), _BOLD, use_color)} / 100"
    )
    if result["method"]:
        print(_color(f"  Using {result['method']}", _DIM, use_color))
    print()

    print(_color("Breakdown", _BOLD, use_color))
    for item in result["breakdown"]:
        mark = _color("PASS", _GREEN, use_color) if item["passed"] else _color("MISS", _RED, use_color)
        if item["scored"]:
            pts = f"{item['points']}/{item['max_points']}"
        else:
            pts = "bonus" if item["passed"] else "----"
        print(f"  [{mark}] {item['label']:<32} {pts}")
    print()

    if result["fixes"]:
        print(_color("How to improve", _BOLD, use_color))
        for i, fix in enumerate(result["fixes"], 1):
            worth = f" (+{fix['points']} pts)" if fix["points"] else ""
            print(_color(f"  {i}. {fix['title']}{worth}", _BOLD, use_color))
            # Wrap the detail at a readable width.
            words = fix["detail"].split()
            line = "     "
            for w in words:
                if len(line) + len(w) + 1 > 78:
                    print(line)
                    line = "     " + w
                else:
                    line += (" " if line.strip() else "") + w
            if line.strip():
                print(line)
            print()
    else:
        print(_color("Nothing to fix. Your agent is fully verifiable. Nice work.", _GREEN, use_color))
        print()

    # The badge you can embed.
    color = GRADE_COLORS.get(g, "#7c2d3a")
    print(_color("Embeddable badge", _BOLD, use_color))
    print(_color(f"  Grade {g} badge color {color}. Markdown:", _DIM, use_color))
    print(
        f"  ![Agent Trust: {g}]"
        f"(https://index.vouch-protocol.com/badges/{g}.svg)"
    )
    print()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check your own agent's Trust Score and get fix-it guidance."
    )
    parser.add_argument("target", help="your agent's domain or did:web identifier")
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON")
    parser.add_argument("--no-color", action="store_true", help="disable colored output")
    args = parser.parse_args(argv)

    domain = normalize_domain(args.target)
    if not domain:
        print("Could not read a domain from that input.", file=sys.stderr)
        return 2

    result = evaluate(domain)

    if args.json:
        print(json.dumps(result, indent=2))
        return 0

    use_color = (not args.no_color) and sys.stdout.isatty()
    print_report(result, use_color=use_color)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
