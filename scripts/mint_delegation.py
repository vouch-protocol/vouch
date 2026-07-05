#!/usr/bin/env python3
"""Sign the root -> contributor delegation credential. Run ONCE, locally.

This is signed with the ROOT identity (did:web:vouch-protocol.com), whose
private key is held offline and never goes into CI. The output, delegation.json,
is a PUBLIC artifact (signatures and DIDs only, no private key), so it is safe
to commit. The contributor issuer then attaches it to every badge, so each
badge traces back to the root authority without the root key ever touching CI.

Set the ROOT identity in the environment before running:
  $env:VOUCH_DID = "did:web:vouch-protocol.com"
  $env:VOUCH_PRIVATE_KEY = '<root private-key JWK JSON>'
  python scripts/mint_delegation.py

Then commit the resulting delegation.json (e.g. to contributors/delegation.json).
"""

import json
import os
import sys

from vouch import Signer

# The issuer being authorized, and the resource the authority is scoped to.
CONTRIBUTOR_DID = "did:web:vouch-protocol.com:contributors"
REPO_RESOURCE = "https://github.com/vouch-protocol/vouch"
# Delegations are an operational authority, so they rotate. Ten years is a
# generous window; re-run this script to refresh before it lapses.
VALID_SECONDS = 10 * 365 * 86400


def main() -> int:
    private_key = os.getenv("VOUCH_PRIVATE_KEY")
    did = os.getenv("VOUCH_DID")
    if not private_key or not did:
        print("Set VOUCH_PRIVATE_KEY and VOUCH_DID to the ROOT identity.", file=sys.stderr)
        return 1

    signer = Signer(private_key=private_key, did=did)
    delegation = signer.sign(
        intent={
            "action": "delegate",
            "target": CONTRIBUTOR_DID,
            "resource": REPO_RESOURCE,
            "role": "verified-contributor-issuer",
        },
        valid_seconds=VALID_SECONDS,
    )

    with open("delegation.json", "w", encoding="utf-8") as handle:
        json.dump(delegation, handle, indent=2)
    print("Wrote delegation.json (safe to commit, e.g. contributors/delegation.json)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
