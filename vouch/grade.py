"""
Self-check grader for a single agent's trust posture.

The Agent Trust Index scores the whole agent population. This is the on-ramp: a
free, local check of one agent, the same scoring the Index uses, with a letter
grade, the exact reasons, numbered fixes, and an embeddable badge. Run it on your
own agent before anyone else grades it for you.

Scoring mirrors the Index: 60 points for a resolvable DID, 40 for a usable
verification method. Post-quantum readiness, a revocation status list, and
agent-card identity are reported as extra signals but do not change the score,
exactly as the public Index measures it.

The extra signals count only evidence that checks out:

- post-quantum: a verification method that decodes to a well-formed ML-DSA-44
  public key (a Multikey with the ML-DSA-44 multicodec, or a JWK with kty "AKP"
  and alg "ML-DSA-44"), controlled by the DID and listed in assertionMethod.
- revocation: a `BitstringStatusList` service whose https endpoint returns a
  BitstringStatusListCredential issued by the same DID, inside its validity
  period, with an encodedList that decodes, and an eddsa-jcs-2022 proof that
  verifies against an assertionMethod key of the DID document.
- agent card: "verified" when the card carries a vouchCredential issued by the
  domain's DID, bound to the card, and signed by an assertionMethod key of that
  DID document; "declared" when the card only names a DID; "no" otherwise.

Every signal carries its reason. Every network fetch goes through
`vouch.ssrf.fetch_json`. The evidence checks are pure functions of the fetched
documents, so the shared vectors in test-vectors/grade/ run them offline, here
and in the web grader.

Open and hosting-free: grade from the command line, get an SVG badge to embed.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

GRADE_COLORS = {
    "A": "#22c55e",
    "B": "#84cc16",
    "C": "#eab308",
    "D": "#f97316",
    "F": "#ef4444",
}

MLDSA44_PUBLIC_KEY_LENGTH = 1312
ED25519_PUBLIC_KEY_LENGTH = 32
STATUS_LIST_SERVICE_TYPES = ("BitstringStatusList",)
CARD_PATHS = ("/.well-known/agent.json", "/.well-known/agent-card.json")
CARD_STATES = ("no", "declared", "verified")
EDDSA_CRYPTOSUITE = "eddsa-jcs-2022"

# Response and decode limits for the documents the grader fetches.
DID_DOCUMENT_MAX_BYTES = 1024 * 1024
STATUS_LIST_MAX_BYTES = 1024 * 1024
CARD_MAX_BYTES = 256 * 1024
STATUS_LIST_MIN_BITS = 131_072
STATUS_LIST_MAX_DECODED_BYTES = 16 * 1024 * 1024
# Only the first few status-list services are fetched, so a DID document cannot
# make the grader fetch without limit.
STATUS_LIST_MAX_SERVICES = 3

_DID_RE = re.compile(r"did:[a-z0-9]+:[A-Za-z0-9._:%-]+")
_B64URL_RE = re.compile(r"[A-Za-z0-9_-]*")
_TIME_RE = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})"
)

# A fetcher takes a URL and returns the parsed JSON body, or None when the
# document is missing or unsafe to fetch.
Fetcher = Callable[[str], Any]


def empty_signals() -> Dict[str, Any]:
    return {
        "has_did": False,
        "has_verification_method": False,
        "did": None,
        "method": None,
        "pq_ready": False,
        "has_revocation": False,
        "has_card_identity": False,
        "card_identity": "no",
        "reasons": {
            "pq_ready": "no DID document",
            "has_revocation": "no DID document",
            "card_identity": "no agent card",
        },
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


def _found(signals: Dict[str, Any], key: str) -> str:
    reason = (signals.get("reasons") or {}).get(key)
    return f" Found: {reason}." if reason else ""


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
            "Add an ML-DSA-44 key to your DID document (a Multikey verification method "
            "holding the 1312-byte public key, listed in assertionMethod) and sign with "
            "`sign_hybrid`, so credentials survive a future quantum break."
            + _found(signals, "pq_ready")
        )
    if not signals.get("has_revocation"):
        fixes.append(
            "Publish a signed BitstringStatusListCredential at an https URL and list it "
            "in your DID document as a `BitstringStatusList` service, so a revocation "
            "can be published and discovered." + _found(signals, "has_revocation")
        )
    if not signals.get("has_card_identity"):
        if signals.get("card_identity") == "declared":
            text = (
                "Sign your agent card with `sign_agent_card`, using a key in your DID "
                "document's assertionMethod, so a counterparty can verify the identity "
                "the card names."
            )
        else:
            text = (
                "Publish an agent card at /.well-known/agent-card.json and sign it with "
                "`sign_agent_card`, using a key in your DID document's assertionMethod, "
                "so a counterparty can tie the card to a verifiable identity."
            )
        fixes.append(text + _found(signals, "card_identity"))
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


# ---------------------------------------------------------------------------
# Evidence checks (pure functions of the fetched documents)
# ---------------------------------------------------------------------------


def _list(doc: Dict[str, Any], key: str) -> List[Any]:
    value = doc.get(key)
    return value if isinstance(value, list) else []


def _types(value: Any) -> List[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []


def _absolute(ref: Any, did: str) -> Optional[str]:
    if not isinstance(ref, str) or not ref:
        return None
    return did + ref if ref.startswith("#") else ref


def _short(vm_id: str, did: str) -> str:
    return vm_id[len(did) :] if vm_id.startswith(did + "#") else vm_id


def _methods(doc: Dict[str, Any], did: str) -> Dict[str, Dict[str, Any]]:
    """Every verification method in the document, by absolute id: the
    verificationMethod list first, then methods embedded in assertionMethod."""
    found: Dict[str, Dict[str, Any]] = {}
    for vm in _list(doc, "verificationMethod") + _list(doc, "assertionMethod"):
        if isinstance(vm, dict):
            vm_id = _absolute(vm.get("id"), did)
            if vm_id and vm_id not in found:
                found[vm_id] = vm
    return found


def _assertion_ids(doc: Dict[str, Any], did: str) -> List[str]:
    ids: List[str] = []
    for ref in _list(doc, "assertionMethod"):
        vm_id = _absolute(ref.get("id") if isinstance(ref, dict) else ref, did)
        if vm_id:
            ids.append(vm_id)
    return ids


def _b64url_decode(value: Any) -> Optional[bytes]:
    if not isinstance(value, str) or not _B64URL_RE.fullmatch(value):
        return None
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError):
        return None


def _b58_decode(value: str) -> Optional[bytes]:
    from .multikey import _b58decode

    try:
        return _b58decode(value)
    except ValueError:
        return None


def _mldsa44_claim(vm: Dict[str, Any]) -> Optional[Tuple[bool, str]]:
    """None when `vm` does not present an ML-DSA-44 key at all, otherwise
    (well_formed, detail)."""
    from .multikey import MLDSA44_PUB_PREFIX

    multibase = vm.get("publicKeyMultibase")
    if vm.get("type") == "Multikey" and isinstance(multibase, str) and multibase.startswith("z"):
        raw = _b58_decode(multibase[1:])
        if raw is not None and raw[:2] == MLDSA44_PUB_PREFIX:
            size = len(raw) - 2
            return size == MLDSA44_PUBLIC_KEY_LENGTH, (
                f"{size} bytes, expected {MLDSA44_PUBLIC_KEY_LENGTH}"
            )
    jwk = vm.get("publicKeyJwk")
    if isinstance(jwk, dict) and jwk.get("kty") == "AKP" and jwk.get("alg") == "ML-DSA-44":
        raw = _b64url_decode(jwk.get("pub"))
        if raw is None:
            return False, "unreadable pub value"
        return len(raw) == MLDSA44_PUBLIC_KEY_LENGTH, (
            f"{len(raw)} bytes, expected {MLDSA44_PUBLIC_KEY_LENGTH}"
        )
    return None


def post_quantum_signal(doc: Any, did: str) -> Tuple[bool, str]:
    """Yes only for a well-formed ML-DSA-44 public key that the DID controls and
    lists in assertionMethod. Text in ids or descriptions never counts."""
    if not isinstance(doc, dict):
        return False, "no DID document"
    assertion = _assertion_ids(doc, did)
    problems: List[str] = []
    for vm_id, vm in _methods(doc, did).items():
        claim = _mldsa44_claim(vm)
        if claim is None:
            continue
        well_formed, detail = claim
        short = _short(vm_id, did)
        if not well_formed:
            problems.append(f"ML-DSA-44 key {short} is malformed ({detail})")
        elif vm.get("controller") != did:
            problems.append(f"ML-DSA-44 key {short} is not controlled by {did}")
        elif vm_id not in assertion:
            problems.append(f"ML-DSA-44 key {short} is not in assertionMethod")
        else:
            return True, f"ML-DSA-44 key {short} in assertionMethod"
    if problems:
        return False, problems[0]
    return False, "no ML-DSA-44 verification method"


def _ed25519_key(doc: Dict[str, Any], did: str, ref: Any) -> Tuple[Optional[bytes], str]:
    """The raw Ed25519 key a proof names, if it is an assertionMethod key of
    this DID document. Returns (key, short id) or (None, reason)."""
    from .multikey import ED25519_PUB_PREFIX

    vm_id = _absolute(ref, did)
    if vm_id is None:
        return None, "has a proof that names no verificationMethod"
    short = _short(vm_id, did)
    vm = _methods(doc, did).get(vm_id)
    if vm is None:
        return None, f"is signed by {short}, which is not in the DID document"
    if vm.get("controller") != did:
        return None, f"is signed by {short}, which is not controlled by {did}"
    if vm_id not in _assertion_ids(doc, did):
        return None, f"is signed by {short}, which is not in assertionMethod"
    multibase = vm.get("publicKeyMultibase")
    if isinstance(multibase, str) and multibase.startswith("z"):
        raw = _b58_decode(multibase[1:])
        if (
            raw is not None
            and raw[:2] == ED25519_PUB_PREFIX
            and len(raw) == 2 + ED25519_PUBLIC_KEY_LENGTH
        ):
            return raw[2:], short
    jwk = vm.get("publicKeyJwk")
    if isinstance(jwk, dict) and jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519":
        raw = _b64url_decode(jwk.get("x"))
        if raw is not None and len(raw) == ED25519_PUBLIC_KEY_LENGTH:
            return raw, short
    return None, f"is signed by {short}, which is not an Ed25519 key"


def _parse_time(value: Any) -> Optional[datetime]:
    """Parse an XML Schema dateTime with an explicit offset, to the millisecond."""
    if not isinstance(value, str):
        return None
    m = _TIME_RE.fullmatch(value)
    if not m:
        return None
    year, month, day, hour, minute, second, frac, offset = m.groups()
    try:
        dt = datetime(
            int(year),
            int(month),
            int(day),
            int(hour),
            int(minute),
            int(second),
            int((frac or "0")[:3].ljust(3, "0")) * 1000,
            tzinfo=timezone.utc,
        )
    except ValueError:
        return None
    if offset != "Z":
        sign = 1 if offset[0] == "+" else -1
        dt -= sign * timedelta(hours=int(offset[1:3]), minutes=int(offset[4:6]))
    return dt


def _outside_window(cred: Dict[str, Any], now: datetime) -> Optional[str]:
    """None when `now` falls inside the credential's validity period, else why."""
    start = cred.get("validFrom")
    if start is None:
        start = cred.get("issuanceDate")
    end = cred.get("validUntil")
    if end is None:
        end = cred.get("expirationDate")
    if start is not None:
        begins = _parse_time(start)
        if begins is None:
            return "has an unreadable validFrom"
        if now < begins:
            return f"is not valid until {start}"
    if end is not None:
        ends = _parse_time(end)
        if ends is None:
            return "has an unreadable validUntil"
        if now >= ends:
            return f"expired {end}"
    return None


def _verify_assertion(
    cred: Dict[str, Any], doc: Dict[str, Any], did: str, now: datetime
) -> Tuple[bool, str]:
    """Issued by `did`, inside its validity period, and every eddsa-jcs-2022
    proof verifies against an assertionMethod key of `doc`."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    from . import data_integrity

    issuer = cred.get("issuer")
    if isinstance(issuer, dict):
        issuer = issuer.get("id")
    if issuer != did:
        named = issuer if isinstance(issuer, str) else "an unnamed issuer"
        return False, f"is issued by {named}, not {did}"
    outside = _outside_window(cred, now)
    if outside:
        return False, outside
    proof = cred.get("proof")
    proofs = proof if isinstance(proof, list) else [proof]
    eddsa = [p for p in proofs if isinstance(p, dict) and p.get("cryptosuite") == EDDSA_CRYPTOSUITE]
    if not eddsa:
        return False, "has no eddsa-jcs-2022 proof"
    base = {k: v for k, v in cred.items() if k != "proof"}
    signer = ""
    for item in eddsa:
        if (
            item.get("type") != "DataIntegrityProof"
            or item.get("proofPurpose") != "assertionMethod"
        ):
            return False, "has a proof that is not an assertionMethod DataIntegrityProof"
        raw, detail = _ed25519_key(doc, did, item.get("verificationMethod"))
        if raw is None:
            return False, detail
        candidate = dict(base)
        candidate["proof"] = item
        try:
            valid = data_integrity.verify_proof(candidate, Ed25519PublicKey.from_public_bytes(raw))
        except ValueError:
            valid = False
        if not valid:
            return False, f"has a proof that does not verify against {detail}"
        signer = signer or detail
    return True, f"is signed by {signer}"


def _encoded_list_decodes(encoded: Any) -> bool:
    """A multibase base64url GZIP bitstring of at least 131,072 bits. The
    decompressed size is capped, so a small compressed list cannot expand
    without limit."""
    if not isinstance(encoded, str) or not encoded.startswith("u"):
        return False
    compressed = _b64url_decode(encoded[1:])
    if not compressed:
        return False
    inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        bits = inflater.decompress(compressed, STATUS_LIST_MAX_DECODED_BYTES + 1)
    except zlib.error:
        return False
    if len(bits) > STATUS_LIST_MAX_DECODED_BYTES or inflater.unconsumed_tail:
        return False
    if not inflater.eof:
        return False
    return len(bits) * 8 >= STATUS_LIST_MIN_BITS


def _status_list_problem(
    lst: Any, doc: Dict[str, Any], did: str, now: datetime
) -> Tuple[bool, str]:
    if not isinstance(lst, dict):
        return False, "is not a JSON object"
    if "BitstringStatusListCredential" not in _types(lst.get("type")):
        return False, "is not a BitstringStatusListCredential"
    subject = lst.get("credentialSubject")
    if not isinstance(subject, dict) or "BitstringStatusList" not in _types(subject.get("type")):
        return False, "has no BitstringStatusList subject"
    if not _encoded_list_decodes(subject.get("encodedList")):
        return False, "has an encodedList that does not decode"
    ok, why = _verify_assertion(lst, doc, did, now)
    if not ok:
        return False, why
    end = lst.get("validUntil")
    if end is None:
        end = lst.get("expirationDate")
    return True, f"{why}, valid until {end}" if isinstance(end, str) else why


def revocation_signal(doc: Any, did: str, fetch: Fetcher, now: datetime) -> Tuple[bool, str]:
    """Yes only for a `BitstringStatusList` service whose https endpoint returns
    a valid BitstringStatusListCredential issued and signed under this DID."""
    if not isinstance(doc, dict):
        return False, "no DID document"
    services = [s for s in _list(doc, "service") if isinstance(s, dict)]
    if not services:
        return False, "no service in the DID document"
    listed = [
        s for s in services if any(t in STATUS_LIST_SERVICE_TYPES for t in _types(s.get("type")))
    ]
    if not listed:
        found = sorted({t for s in services for t in _types(s.get("type"))})
        return False, "no BitstringStatusList service (found " + (
            ", ".join(found) or "untyped services"
        ) + ")"
    reason = ""
    for service in listed[:STATUS_LIST_MAX_SERVICES]:
        endpoint = service.get("serviceEndpoint")
        if isinstance(endpoint, list):
            endpoint = next((e for e in endpoint if isinstance(e, str)), None)
        if not isinstance(endpoint, str) or not endpoint.startswith("https://"):
            reason = "BitstringStatusList service has no https endpoint"
            continue
        lst = fetch(endpoint)
        if lst is None:
            reason = f"status list {endpoint} could not be fetched"
            continue
        ok, why = _status_list_problem(lst, doc, did, now)
        reason = f"status list {endpoint} {why}"
        if ok:
            return True, reason
    return False, reason


def card_identity_signal(card: Any, doc: Any, did: str, now: datetime) -> Tuple[str, str]:
    """ "verified", "declared" or "no", with the reason."""
    if not isinstance(card, dict):
        return "no", "no agent card"
    credential = card.get("vouchCredential")
    problem = "carries no vouchCredential"
    if isinstance(credential, dict):
        if not isinstance(doc, dict):
            problem = "its vouchCredential cannot be checked without a DID document"
        else:
            ok, why = _verify_assertion(credential, doc, did, now)
            if ok:
                url, name = card.get("url"), card.get("name")
                if isinstance(url, str) and url:
                    expected = url
                elif isinstance(name, str) and name:
                    expected = name
                else:
                    expected = "a2a:agent"
                subject = credential.get("credentialSubject")
                intent = subject.get("intent") if isinstance(subject, dict) else None
                target = intent.get("target") if isinstance(intent, dict) else None
                if target == expected:
                    return "verified", f"vouchCredential {why}"
                why = (
                    f"is bound to {target}, not {expected}"
                    if isinstance(target, str)
                    else "names no target"
                )
            problem = f"its vouchCredential {why}"
    named = _DID_RE.search(json.dumps(card))
    if named is None:
        return "no", "agent card names no DID"
    return "declared", f"agent card names {named.group(0)} but {problem}"


def evidence_signals(
    did: str,
    doc: Any,
    cards: List[Any],
    fetch: Fetcher,
    now: datetime,
) -> Dict[str, Any]:
    """The post-quantum, revocation and agent-card signals for one DID, from
    its DID document, its agent cards, and a fetcher for status lists."""
    pq_ready, pq_reason = post_quantum_signal(doc, did)
    has_revocation, revocation_reason = revocation_signal(doc, did, fetch, now)
    best: Optional[Tuple[str, str]] = None
    for card in cards:
        if card is None:
            continue
        state, why = card_identity_signal(card, doc, did, now)
        if best is None or CARD_STATES.index(state) > CARD_STATES.index(best[0]):
            best = (state, why)
    state, card_reason = best or ("no", "no agent card")
    return {
        "pq_ready": pq_ready,
        "has_revocation": has_revocation,
        "has_card_identity": state == "verified",
        "card_identity": state,
        "reasons": {
            "pq_ready": pq_reason,
            "has_revocation": revocation_reason,
            "card_identity": card_reason,
        },
    }


# ---------------------------------------------------------------------------
# Network resolution
# ---------------------------------------------------------------------------


def _fetch(url: str, timeout: float, max_bytes: int, max_redirects: int) -> Optional[Any]:
    """Fetch JSON through the SSRF guard; None when the document is missing,
    unsafe to fetch, too large, too slow, or not JSON."""
    from . import ssrf

    try:
        return ssrf.fetch_json(
            url, timeout=timeout, max_bytes=max_bytes, max_redirects=max_redirects
        )
    except (ssrf.SSRFError, ssrf.FetchError):
        return None


def inspect_domain(
    domain: str,
    timeout: float = 5,
    *,
    now: Optional[datetime] = None,
    fetch: Optional[Fetcher] = None,
) -> Tuple[Dict[str, Any], List[Any]]:
    """
    Resolve one domain and gather its trust signals (network). Returns the
    signals and the agent cards found, so the Index can look for DIDs a card
    declares. `fetch` replaces the network for every document (tests).
    """
    from .did_web import DIDDocument, did_web_to_url
    from .multikey import algorithm_of

    from . import ssrf

    now = now or datetime.now(timezone.utc)
    did = f"did:web:{domain}"
    if fetch is None:

        def doc_fetch(url: str) -> Any:
            # No redirects, as in did:web resolution.
            return _fetch(url, timeout, DID_DOCUMENT_MAX_BYTES, 0)

        def list_fetch(url: str) -> Any:
            return _fetch(url, timeout, STATUS_LIST_MAX_BYTES, ssrf.DEFAULT_MAX_REDIRECTS)

        def card_fetch(url: str) -> Any:
            return _fetch(url, timeout, CARD_MAX_BYTES, ssrf.DEFAULT_MAX_REDIRECTS)

    else:
        doc_fetch = list_fetch = card_fetch = fetch

    sig = empty_signals()
    doc: Optional[Dict[str, Any]] = None
    raw = doc_fetch(did_web_to_url(did))
    if isinstance(raw, dict):
        try:
            parsed: Optional[DIDDocument] = DIDDocument.from_json(raw)
        except (AttributeError, TypeError, ValueError):
            parsed = None
        if parsed is not None:
            doc = raw
            sig["has_did"] = True
            sig["did"] = did
            jwk = parsed.get_public_key_jwk()
            multibase = parsed.get_public_key_multibase()
            if isinstance(jwk, dict):
                sig["has_verification_method"] = True
                sig["method"] = f"did:web, {jwk.get('crv') or jwk.get('kty') or 'key'} (JWK)"
            elif isinstance(multibase, str):
                sig["has_verification_method"] = True
                try:
                    alg = algorithm_of(multibase)
                except ValueError:
                    alg = "key"
                sig["method"] = f"did:web, {alg} (Multikey)"

    cards = [card_fetch(f"https://{domain}{path}") for path in CARD_PATHS]
    sig.update(evidence_signals(did, doc, cards, list_fetch, now))
    return sig, cards


def resolve_signals(
    domain: str,
    timeout: float = 5,
    *,
    now: Optional[datetime] = None,
    fetch: Optional[Fetcher] = None,
) -> Dict[str, Any]:
    """
    Resolve one domain and gather trust signals (network). Mirrors the Index's
    per-domain resolution: did:web identity, key type, post-quantum readiness,
    a revocation status list, and agent-card identity, each with its reason.
    """
    return inspect_domain(domain, timeout, now=now, fetch=fetch)[0]


def grade_domain(
    domain: str,
    timeout: float = 5,
    *,
    now: Optional[datetime] = None,
    fetch: Optional[Fetcher] = None,
) -> GradeReport:
    """Resolve a domain live and grade it."""
    return grade_signals(resolve_signals(domain, timeout, now=now, fetch=fetch), domain=domain)


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
