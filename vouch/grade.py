"""
Self-check grader for a single agent's trust posture.

The Agent Trust Index scores the whole agent population. This is the on-ramp: a
free, local check of one agent, the same scoring the Index uses, with a letter
grade, the exact reasons, numbered fixes, and an embeddable badge. Run it on your
own agent before anyone else grades it for you.

Scoring mirrors the Index: 60 points for a resolvable DID, 40 for a usable
verification method. Post-quantum readiness, a revocation or service endpoint,
and agent-card identity are reported as extra signals but do not change the
score, exactly as the public Index measures it.

Open and hosting-free: grade from the command line, get an SVG badge to embed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

GRADE_COLORS = {
    "A": "#22c55e",
    "B": "#84cc16",
    "C": "#eab308",
    "D": "#f97316",
    "F": "#ef4444",
}


def empty_signals() -> Dict[str, Any]:
    return {
        "has_did": False,
        "has_verification_method": False,
        "did": None,
        "method": None,
        "pq_ready": False,
        "has_revocation": False,
        "has_card_identity": False,
    }


def score_signals(signals: Dict[str, Any]) -> Dict[str, Any]:
    """Turn signals into a 0-100 score and a letter grade. Mirrors the Index."""
    breakdown = {
        "resolvable_did": 60 if signals.get("has_did") else 0,
        "valid_verification_method": 40 if signals.get("has_verification_method") else 0,
    }
    points = sum(breakdown.values())
    if points >= 90:
        grade = "A"
    elif points >= 75:
        grade = "B"
    elif points >= 60:
        grade = "C"
    elif points >= 40:
        grade = "D"
    else:
        grade = "F"
    return {"score": points, "grade": grade, "breakdown": breakdown}


def fix_its(signals: Dict[str, Any]) -> List[str]:
    """Numbered, actionable remediation for whatever is missing."""
    fixes: List[str] = []
    if not signals.get("has_did"):
        fixes.append(
            "Publish a did:web. Run `vouch init --domain yourdomain.com` and serve the "
            "DID document at https://yourdomain.com/.well-known/did.json."
        )
    if not signals.get("has_verification_method"):
        fixes.append(
            "Add a verificationMethod with your public key to the DID document, so others "
            "can verify what you sign."
        )
    if not signals.get("pq_ready"):
        fixes.append(
            "Add a post-quantum key (ML-DSA-44) alongside your Ed25519 key and sign with "
            "`sign_credential_hybrid`, so credentials survive a future quantum break."
        )
    if not signals.get("has_revocation"):
        fixes.append(
            "Publish a service or revocation endpoint in your DID document, so a "
            "compromised key can be revoked and discovered."
        )
    if not signals.get("has_card_identity"):
        fixes.append(
            "Reference your DID in your agent card (/.well-known/agent.json), so a "
            "counterparty can tie the card to a verifiable identity."
        )
    return fixes


@dataclass
class GradeReport:
    domain: Optional[str]
    score: int
    grade: str
    signals: Dict[str, Any]
    breakdown: Dict[str, int]
    fixes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "score": self.score,
            "grade": self.grade,
            "signals": self.signals,
            "breakdown": self.breakdown,
            "fixes": self.fixes,
        }


def grade_signals(signals: Dict[str, Any], domain: Optional[str] = None) -> GradeReport:
    """Score a set of signals and attach fixes (no network)."""
    scored = score_signals(signals)
    return GradeReport(
        domain=domain,
        score=scored["score"],
        grade=scored["grade"],
        signals=signals,
        breakdown=scored["breakdown"],
        fixes=fix_its(signals),
    )


def resolve_signals(domain: str, timeout: int = 5) -> Dict[str, Any]:
    """
    Resolve one domain and gather trust signals (network). Mirrors the Index's
    per-domain resolution: did:web identity, key type, post-quantum readiness,
    a service/revocation endpoint, and agent-card identity.
    """
    from vouch.did_web import resolve_did_web_sync
    from vouch.multikey import algorithm_of

    sig = empty_signals()
    try:
        doc = resolve_did_web_sync(f"did:web:{domain}", timeout=timeout)
        sig["has_did"] = True
        sig["did"] = f"did:web:{domain}"
        jwk = None
        multibase = None
        try:
            jwk = doc.get_public_key_jwk()
        except Exception:
            jwk = None
        try:
            multibase = doc.get_public_key_multibase()
        except Exception:
            multibase = None
        if jwk:
            sig["has_verification_method"] = True
            sig["method"] = f"did:web, {jwk.get('crv') or jwk.get('kty') or 'key'} (JWK)"
        elif multibase:
            sig["has_verification_method"] = True
            try:
                alg = algorithm_of(multibase)
            except Exception:
                alg = "key"
            sig["method"] = f"did:web, {alg} (Multikey)"
    except Exception:
        return sig

    raw = _get_json(f"https://{domain}/.well-known/did.json", timeout)
    if isinstance(raw, dict):
        services = raw.get("service")
        if isinstance(services, list) and services:
            sig["has_revocation"] = True
        blob = json.dumps(raw).lower()
        if "ml-dsa" in blob or "mldsa" in blob or "dilithium" in blob:
            sig["pq_ready"] = True

    card = _get_json(f"https://{domain}/.well-known/agent.json", timeout) or _get_json(
        f"https://{domain}/.well-known/agent-card.json", timeout
    )
    if isinstance(card, dict):
        blob = json.dumps(card).lower()
        if "did:" in blob or "signature" in blob:
            sig["has_card_identity"] = True

    return sig


def _get_json(url: str, timeout: int = 5) -> Optional[Any]:
    try:
        import httpx

        resp = httpx.get(url, timeout=timeout, follow_redirects=True)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        return None
    return None


def grade_domain(domain: str, timeout: int = 5) -> GradeReport:
    """Resolve a domain live and grade it."""
    return grade_signals(resolve_signals(domain, timeout=timeout), domain=domain)


def badge_svg(report: GradeReport, label: str = "agent trust") -> str:
    """A shields-style SVG badge showing the grade. Embed it in a README or page."""
    grade = report.grade
    color = GRADE_COLORS.get(grade, "#9ca3af")
    value = f"{grade} ({report.score})"
    # Rough width estimates so the two halves fit their text.
    label_w = 7 * len(label) + 16
    value_w = 7 * len(value) + 16
    total = label_w + value_w
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="20" '
        f'role="img" aria-label="{label}: {value}">'
        f'<rect width="{total}" height="20" rx="3" fill="#555"/>'
        f'<rect x="{label_w}" width="{value_w}" height="20" rx="3" fill="{color}"/>'
        f'<rect x="{label_w}" width="4" height="20" fill="{color}"/>'
        f'<g fill="#fff" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11">'
        f'<text x="{label_w / 2:.0f}" y="14" text-anchor="middle">{label}</text>'
        f'<text x="{label_w + value_w / 2:.0f}" y="14" text-anchor="middle">{value}</text>'
        f"</g></svg>"
    )
