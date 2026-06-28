#!/usr/bin/env python3
"""Mint a "Vouch Verified Integration" credential for an adopter.

The Adopter Authority (a delegated key, see bootstrap_adopter_authority.py)
signs a Verifiable Credential attesting that an independent system integrates
a part of Vouch Protocol against the published schema. The credential traces
back to the root authority through the attached delegation.

The issuer key is read from the environment:
  VOUCH_ADOPTER_PRIVATE_KEY  Ed25519 private key JWK (JSON string)
  VOUCH_ADOPTER_DID          Issuer DID, e.g. did:web:vouch-protocol.com:adopters

Example:
  export VOUCH_ADOPTER_DID='did:web:vouch-protocol.com:adopters'
  export VOUCH_ADOPTER_PRIVATE_KEY='{"kty":"OKP","crv":"Ed25519",...}'
  python scripts/mint_adopter_credential.py \\
      --slug invinoveritas --name invinoveritas --by babyblueviper1 \\
      --focus "Outcome Evidence and the AccountabilityRecord" \\
      --live-surface https://api.babyblueviper.com/.well-known/agent-handshake \\
      --parent adopters/delegation.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from vouch import Signer

# An integration record attests a fact at a point in time. Like the contributor
# badge it does not meaningfully expire; revocation, not expiry, retires it.
DEFAULT_VALID_DAYS = 365 * 100
ADOPTER_RESOURCE = "https://vouch-protocol.com/adopters"


def mint_credential(
    slug: str,
    name: str,
    by: str,
    focus: str,
    live_surface: str,
    discussion: str,
    private_key: str,
    did: str,
    valid_days: int = DEFAULT_VALID_DAYS,
    parent_credential: dict | None = None,
) -> dict:
    """Return a signed Vouch Credential attesting a reference integration."""
    signer = Signer(private_key=private_key, did=did)
    intent = {
        "action": "attest",
        "target": f"adopter:{slug}",
        # resource binds the record beneath the adopter namespace so the
        # delegation's non-expansion rule holds.
        "resource": f"{ADOPTER_RESOURCE}/{slug}",
        "role": "reference-integration",
        "name": name,
        "integrates": focus,
    }
    if by:
        intent["by"] = by
    if live_surface:
        intent["liveSurface"] = live_surface
    if discussion:
        intent["discussion"] = discussion
    return signer.sign_credential(
        intent=intent,
        valid_seconds=valid_days * 86400,
        parent_credential=parent_credential,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Mint a Vouch Verified Integration credential")
    parser.add_argument("--slug", required=True, help="URL slug under /i/<slug>/")
    parser.add_argument("--name", required=True, help="Display name of the integration")
    parser.add_argument("--by", default="", help="Author handle or organization")
    parser.add_argument("--focus", required=True, help="What part of Vouch it integrates")
    parser.add_argument("--live-surface", default="", help="URL a verifier can check")
    parser.add_argument("--discussion", default="", help="Discussion or PR URL")
    parser.add_argument("--out", default="-", help="Output file, or - for stdout")
    parser.add_argument(
        "--parent",
        default="",
        help="Path to the root delegation credential (adopters/delegation.json).",
    )
    args = parser.parse_args(argv)

    private_key = os.getenv("VOUCH_ADOPTER_PRIVATE_KEY")
    did = os.getenv("VOUCH_ADOPTER_DID")
    if not private_key or not did:
        print(
            "VOUCH_ADOPTER_PRIVATE_KEY and VOUCH_ADOPTER_DID must be set to mint a credential.",
            file=sys.stderr,
        )
        return 1

    parent_credential = None
    if args.parent and os.path.exists(args.parent):
        with open(args.parent, encoding="utf-8") as handle:
            parent_credential = json.load(handle)

    credential = mint_credential(
        slug=args.slug,
        name=args.name,
        by=args.by,
        focus=args.focus,
        live_surface=args.live_surface,
        discussion=args.discussion,
        private_key=private_key,
        did=did,
        parent_credential=parent_credential,
    )

    text = json.dumps(credential, indent=2)
    if args.out == "-":
        print(text)
    else:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text)
        print(f"Wrote credential for {args.name} to {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
