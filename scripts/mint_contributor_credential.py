#!/usr/bin/env python3
"""Mint a "Vouch Verified Contributor" credential for a merged-PR author.

This dogfoods the protocol: the project signs a Verifiable Credential
attesting that a GitHub user contributed a merged pull request. It is
designed to run in CI (see .github/workflows/verified-contributor.yml) but
is also runnable locally.

The issuer key is read from the environment:
  VOUCH_PRIVATE_KEY  Ed25519 private key JWK (JSON string)
  VOUCH_DID          Issuer DID, e.g. did:web:vouch-protocol.com

Example:
  export VOUCH_DID='did:web:vouch-protocol.com'
  export VOUCH_PRIVATE_KEY='{"kty":"OKP","crv":"Ed25519",...}'
  python scripts/mint_contributor_credential.py \\
      --subject Franflorio \\
      --pr-url https://github.com/vouch-protocol/vouch/pull/110 \\
      --pr-number 110 --repo vouch-protocol/vouch
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from vouch import Signer


# A contributor badge attests a past fact, so it does not meaningfully expire.
# The verifier requires a validUntil, so we set it far out (100 years) and rely
# on a revocation status list, not expiry, if a badge ever needs to be pulled.
DEFAULT_VALID_DAYS = 365 * 100


def mint_credential(
    subject: str,
    pr_url: str,
    pr_number: str,
    repo: str,
    private_key: str,
    did: str,
    valid_days: int = DEFAULT_VALID_DAYS,
    parent_credential: dict | None = None,
) -> dict:
    """Return a signed Vouch Credential attesting a merged contribution.

    If `parent_credential` (the root -> contributor delegation) is provided, it
    is attached so the badge traces back to the root authority.
    """
    signer = Signer(private_key=private_key, did=did)
    intent = {
        "action": "attest",
        "target": f"github:{subject}",
        # resource is required by the credential model; bind it to the PR.
        "resource": pr_url,
        "role": "verified-contributor",
        "repository": repo,
        "pullRequest": int(pr_number) if pr_number.isdigit() else pr_number,
    }
    return signer.sign(
        intent=intent,
        valid_seconds=valid_days * 86400,
        parent_credential=parent_credential,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Mint a Vouch Verified Contributor credential",
    )
    parser.add_argument("--subject", required=True, help="GitHub handle of the contributor")
    parser.add_argument("--pr-url", required=True, help="HTML URL of the merged pull request")
    parser.add_argument("--pr-number", default="", help="Pull request number")
    parser.add_argument("--repo", default=os.getenv("GITHUB_REPOSITORY", ""), help="owner/repo")
    parser.add_argument("--out", default="-", help="Output file, or - for stdout")
    parser.add_argument(
        "--parent",
        default="",
        help="Path to the root delegation credential (delegation.json). Optional.",
    )
    args = parser.parse_args(argv)

    private_key = os.getenv("VOUCH_PRIVATE_KEY")
    did = os.getenv("VOUCH_DID")
    if not private_key or not did:
        print(
            "VOUCH_PRIVATE_KEY and VOUCH_DID must be set to mint a credential.",
            file=sys.stderr,
        )
        return 1

    parent_credential = None
    if args.parent and os.path.exists(args.parent):
        with open(args.parent, encoding="utf-8") as handle:
            parent_credential = json.load(handle)

    credential = mint_credential(
        subject=args.subject,
        pr_url=args.pr_url,
        pr_number=args.pr_number,
        repo=args.repo,
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
        print(f"Wrote credential for @{args.subject} to {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
