"""
Enrich the verifiable agents in data/results.json with what identity method they
use. We already resolved their DID documents during the scan, so this re-resolves
only the ones that have an identity (a small set) and records the key type, so the
site can show a "what they use" column.

    python enrich.py
"""

import json
from pathlib import Path

from vouch.did_web import resolve_did_web_sync
from vouch.multikey import algorithm_of

ROOT = Path(__file__).parent


def method_for(did: str):
    try:
        doc = resolve_did_web_sync(did, timeout=6)
    except Exception:
        return None
    try:
        jwk = doc.get_public_key_jwk()
    except Exception:
        jwk = None
    if jwk:
        crv = jwk.get("crv") or jwk.get("kty") or "key"
        return f"did:web, {crv} (JWK)"
    try:
        multibase = doc.get_public_key_multibase()
    except Exception:
        multibase = None
    if multibase:
        try:
            alg = algorithm_of(multibase)
        except Exception:
            alg = "key"
        return f"did:web, {alg} (Multikey)"
    return "did:web"


def main() -> None:
    path = ROOT / "data" / "results.json"
    results = json.loads(path.read_text())
    enriched = 0
    cache = {}
    for r in results:
        sig = r.get("signals", {})
        did = sig.get("did")
        if sig.get("has_did") and did:
            if did not in cache:
                cache[did] = method_for(did)
            if cache[did]:
                sig["method"] = cache[did]
                enriched += 1
    path.write_text(json.dumps(results, indent=2))
    print(f"Enriched {enriched} verifiable agent entries with method info.")


if __name__ == "__main__":
    main()
