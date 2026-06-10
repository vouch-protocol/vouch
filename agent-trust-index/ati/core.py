"""
Agent Trust Index, core crawler and scoring (MVP).

It discovers AI agents from public sources and checks one thing for each: can the
agent prove who it is? Today that means looking for a resolvable decentralized
identity (a did:web document the agent publishes at its own domain) with a usable
key. Almost no agent in the wild publishes one yet, and that gap is the finding
worth showing.

This MVP uses one source, the public Model Context Protocol registry, and the
Vouch did:web resolver. It scans the whole registry (paginated) and resolves each
unique domain once, so the number is defensible rather than a small sample.
"""

from __future__ import annotations

import json
import re
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

REGISTRY_URL = "https://registry.modelcontextprotocol.io/v0/servers"
USER_AGENT = "agent-trust-index/0.1 (+https://vouch-protocol.com)"
PAGE_SIZE = 100


@dataclass
class AgentRecord:
    name: str
    title: str
    description: str
    domains: List[str] = field(default_factory=list)
    source: str = "mcp-registry"


def _fetch_json(url: str) -> Dict[str, Any]:
    """Fetch one registry page, retrying on transient timeouts.

    A single slow page used to kill an entire 11k scan, so we retry a few times
    with a short backoff before giving up.
    """
    last: Optional[Exception] = None
    for attempt in range(5):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.load(resp)
        except Exception as exc:  # noqa: BLE001
            last = exc
            time.sleep(1.5 * (attempt + 1))
    raise last if last else RuntimeError("registry fetch failed")


def _next_cursor(metadata: Dict[str, Any]) -> Optional[str]:
    if not metadata:
        return None
    for key in ("next_cursor", "nextCursor", "cursor", "next"):
        value = metadata.get(key)
        if value:
            return str(value)
    return None


def fetch_servers(max_servers: Optional[int] = None) -> List[AgentRecord]:
    """Page through the whole MCP registry and pull out each agent's domains."""
    records: List[AgentRecord] = []
    cursor: Optional[str] = None
    while True:
        url = f"{REGISTRY_URL}?limit={PAGE_SIZE}"
        if cursor:
            url += f"&cursor={cursor}"
        try:
            data = _fetch_json(url)
        except Exception as exc:  # noqa: BLE001
            # The registry stalled on this page even after retries. Rather than
            # throw away the whole scan, stop paging and keep what we have. The
            # number is then a floor, which is exactly how we present it anyway.
            print(
                f"warning: registry page failed after retries ({exc}); "
                f"stopping with {len(records)} records collected so far",
                file=sys.stderr,
            )
            break
        page = data.get("servers", []) or []
        for item in page:
            server = item.get("server", item)
            domains = []
            for remote in server.get("remotes", []) or []:
                host = urlparse(remote.get("url", "")).hostname
                if host:
                    domains.append(host)
            records.append(
                AgentRecord(
                    name=server.get("name", ""),
                    title=server.get("title", "") or "",
                    description=(server.get("description", "") or "")[:160],
                    domains=sorted(set(domains)),
                )
            )
        cursor = _next_cursor(data.get("metadata", {}) or {})
        if not cursor or not page:
            break
        if max_servers and len(records) >= max_servers:
            break
        time.sleep(0.1)  # be polite to the public registry between pages
    return records


def _get_json(url: str, timeout: int = 6):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.load(resp)
    except Exception:
        return None


DID_RE = re.compile(r"did:(?:web|key):[A-Za-z0-9._:%#-]+")


def _resolve_declared_did(did: str, sig: Dict[str, Any]) -> None:
    """Pick up a DID an agent declares in its card but does not serve at the bare
    domain: a path-based did:web (resolves at domain/path/did.json) or a did:key.
    The bare did:web:<domain> check never finds these, so they were undercounted.
    """
    from vouch.did_web import resolve_did_web_sync
    from vouch.multikey import algorithm_of

    did = did.split("#", 1)[0]
    try:
        if did.startswith("did:key:"):
            mb = did.split("did:key:", 1)[1]
            try:
                alg = algorithm_of(mb)
            except Exception:
                alg = "key"
            sig["has_did"] = True
            sig["has_verification_method"] = True
            sig["did"] = did
            sig["method"] = f"did:key, {alg}"
            return
        # Path-based did:web. The bare did:web:<domain> form was already tried.
        doc = resolve_did_web_sync(did, timeout=5)
        sig["has_did"] = True
        sig["did"] = did
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
            sig["method"] = f"did:web (path), {jwk.get('crv') or jwk.get('kty') or 'key'} (JWK)"
        elif multibase:
            sig["has_verification_method"] = True
            try:
                alg = algorithm_of(multibase)
            except Exception:
                alg = "key"
            sig["method"] = f"did:web (path), {alg} (Multikey)"
    except Exception:
        pass


def resolve_domain(domain: str) -> Dict[str, Any]:
    """Resolve one domain and gather every trust signal we can observe.

    Identity (did:web) is the headline. We also record what key type is used,
    whether the identity is post-quantum ready, whether a revocation or service
    endpoint is published, and whether an agent card carries identity. Delegation
    and continuous trust are deliberately absent: they appear only when an agent
    presents a credential at runtime, never in a static published document.
    """
    from vouch.did_web import resolve_did_web_sync
    from vouch.multikey import algorithm_of

    sig: Dict[str, Any] = {
        "has_did": False,
        "has_verification_method": False,
        "did": None,
        "method": None,
        "pq_ready": False,
        "has_revocation": False,
        "has_card_identity": False,
    }

    try:
        doc = resolve_did_web_sync(f"did:web:{domain}", timeout=5)
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
        pass

    # Extra dimensions from the raw DID document, only worth fetching if a DID exists.
    if sig["has_did"]:
        raw = _get_json(f"https://{domain}/.well-known/did.json")
        if isinstance(raw, dict):
            services = raw.get("service")
            if isinstance(services, list) and services:
                sig["has_revocation"] = True
            blob = json.dumps(raw).lower()
            if "ml-dsa" in blob or "mldsa" in blob or "dilithium" in blob:
                sig["pq_ready"] = True

    # A second discovery signal: an agent card that carries identity.
    card = _get_json(f"https://{domain}/.well-known/agent.json") or _get_json(
        f"https://{domain}/.well-known/agent-card.json"
    )
    if isinstance(card, dict):
        blob = json.dumps(card)
        if "did:" in blob.lower() or "signature" in blob.lower():
            sig["has_card_identity"] = True
        # Catch DIDs the card declares that do not live at the bare-domain
        # .well-known: a path-based did:web or a did:key. Only worth the extra
        # resolves when the bare-domain check did not already find a usable key.
        if not sig["has_verification_method"]:
            for did in dict.fromkeys(DID_RE.findall(blob)):
                if did == f"did:web:{domain}":
                    continue
                _resolve_declared_did(did, sig)
                if sig["has_verification_method"]:
                    break

    return sig


def score(signals: Dict[str, Any]) -> Dict[str, Any]:
    """Turn the signals into a 0 to 100 Trust Score and a letter grade."""
    breakdown = {
        "resolvable_did": 60 if signals["has_did"] else 0,
        "valid_verification_method": 40 if signals["has_verification_method"] else 0,
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


def run(max_servers: Optional[int] = None, workers: int = 20) -> List[Dict[str, Any]]:
    records = fetch_servers(max_servers)

    # Resolve each unique domain exactly once, so a full registry scan is feasible.
    unique_domains = sorted({d for r in records for d in r.domains})
    domain_signals: Dict[str, Dict[str, Any]] = {}
    if unique_domains:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for domain, sig in zip(unique_domains, pool.map(resolve_domain, unique_domains)):
                domain_signals[domain] = sig

    results: List[Dict[str, Any]] = []
    for record in records:
        signals: Dict[str, Any] = {
            "has_did": False,
            "has_verification_method": False,
            "did": None,
            "method": None,
            "pq_ready": False,
            "has_revocation": False,
            "has_card_identity": False,
        }
        for domain in record.domains:
            sig = domain_signals.get(domain, {})
            if sig.get("has_did") and not signals["has_did"]:
                signals["has_did"] = True
                signals["did"] = sig.get("did") or f"did:web:{domain}"
                signals["method"] = sig.get("method")
            for flag in ("has_verification_method", "pq_ready", "has_revocation", "has_card_identity"):
                if sig.get(flag):
                    signals[flag] = True
        scored = score(signals)
        results.append(
            {
                "name": record.name,
                "title": record.title,
                "description": record.description,
                "source": record.source,
                "domains": record.domains,
                "signals": signals,
                "score": scored["score"],
                "grade": scored["grade"],
                "breakdown": scored["breakdown"],
                "checked_at": datetime.now(timezone.utc).isoformat(),
            }
        )

    results.sort(key=lambda r: r["score"], reverse=True)
    return results
