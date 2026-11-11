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

# Any did:web or did:key string embedded in an agent card.
DID_RE = re.compile(r"did:(?:web|key):[A-Za-z0-9._:%#-]+")


@dataclass
class AgentRecord:
    name: str
    title: str
    description: str
    domains: List[str] = field(default_factory=list)
    source: str = "mcp-registry"


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


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
        except Exception as exc:  # noqa: BLE001 - transient network errors
            last = exc
            time.sleep(1.5 * (attempt + 1))
    if last:
        raise last
    raise RuntimeError("registry fetch failed")


def _next_cursor(metadata: Dict[str, Any]) -> Optional[str]:
    """Pull the pagination cursor out of a registry response's metadata."""
    if not metadata:
        return None
    for key in ("next_cursor", "nextCursor", "cursor", "next"):
        value = metadata.get(key)
        if value:
            return str(value)
    return None


# ---------------------------------------------------------------------------
# Registry discovery
# ---------------------------------------------------------------------------


def fetch_servers(max_servers: Optional[int]) -> List[AgentRecord]:
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
            print(
                f"warning: registry page failed after retries ({exc}); "
                f"stopping with {len(records)} records collected so far",
                file=sys.stderr,
            )
            return records

        page = data.get("servers", []) or []
        for item in page:
            server = item.get("server", item)
            domains: List[str] = []
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
            return records
        if max_servers and len(records) >= max_servers:
            return records
        time.sleep(0.1)


# ---------------------------------------------------------------------------
# Identity resolution and scoring
# ---------------------------------------------------------------------------


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
            return
        if multibase:
            sig["has_verification_method"] = True
            try:
                alg = algorithm_of(multibase)
            except Exception:
                alg = "key"
            sig["method"] = f"did:web (path), {alg} (Multikey)"
            return
    except Exception:
        return


def resolve_domain(domain: str) -> Dict[str, Any]:
    """Resolve one domain and gather every trust signal we can observe.

    Identity (did:web) is the headline. The post-quantum, revocation and
    agent-card signals come from `vouch.grade`, the same evidence checks the
    `vouch grade` command and the web grader run, so the Index counts a signal
    only when the key, status list or signed card checks out. Delegation and
    continuous trust are deliberately absent: they appear only when an agent
    presents a credential at runtime, never in a static published document.
    """
    from vouch.grade import inspect_domain

    sig, cards = inspect_domain(domain, timeout=5)

    # Look in the agent cards for a DID the agent declares but does not serve
    # at the bare domain.
    if not sig["has_verification_method"]:
        for card in cards:
            if not isinstance(card, dict):
                continue
            for did in dict.fromkeys(DID_RE.findall(json.dumps(card))):
                if did == f"did:web:{domain}":
                    continue
                _resolve_declared_did(did, sig)
                if sig["has_verification_method"]:
                    break
            if sig["has_verification_method"]:
                break

    return sig


def score(signals: Dict[str, Any]) -> Dict[str, Any]:
    """Turn the signals into a 0 to 100 Trust Score and a letter grade."""
    from vouch.grade import score_signals

    return score_signals(signals)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def run(max_servers: Optional[int] = None, workers: int = 20) -> List[Dict[str, Any]]:
    """Discover agents, resolve each unique domain once, score every agent.

    Domains are resolved concurrently and deduplicated, so an agent that lists
    several domains is scored on the best signals across all of them.
    """
    from vouch.grade import CARD_STATES, empty_signals

    records = fetch_servers(max_servers)
    unique_domains = sorted({d for r in records for d in r.domains})

    domain_signals: Dict[str, Dict[str, Any]] = {}
    if unique_domains:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for domain, sig in zip(unique_domains, pool.map(resolve_domain, unique_domains)):
                domain_signals[domain] = sig

    results: List[Dict[str, Any]] = []
    for record in records:
        signals = empty_signals()
        for domain in record.domains:
            sig = domain_signals.get(domain, {})
            if sig.get("has_did") and not signals["has_did"]:
                signals["has_did"] = True
                signals["did"] = sig.get("did") or f"did:web:{domain}"
                signals["method"] = sig.get("method")
            if sig.get("has_verification_method"):
                signals["has_verification_method"] = True
            reasons = sig.get("reasons") or {}
            for flag in ("pq_ready", "has_revocation"):
                if sig.get(flag) and not signals[flag]:
                    signals[flag] = True
                    signals["reasons"][flag] = reasons.get(flag, "")
            state = sig.get("card_identity", "no")
            if CARD_STATES.index(state) > CARD_STATES.index(signals["card_identity"]):
                signals["card_identity"] = state
                signals["has_card_identity"] = state == "verified"
                signals["reasons"]["card_identity"] = reasons.get("card_identity", "")

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
