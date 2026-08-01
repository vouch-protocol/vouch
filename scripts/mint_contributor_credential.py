#!/usr/bin/env python3
"""Mint a "Vouch Verified Contributor" credential.

This dogfoods the protocol: the project signs a Verifiable Credential
attesting that a GitHub user contributed to the repository. It is designed to
run in CI (see .github/workflows/verified-contributor.yml) but is also runnable
locally.

Two kinds of contribution can be attested, and the credential says which:

  code    (default) The subject authored the commits in a merged pull request.
          This is what CI mints automatically when a pull request merges.
  design  The subject contributed the design or the problem framing that a
          change implements, without writing the code. The credential records
          what they contributed and which pull request implemented it, and it
          does NOT claim they authored the commits. Minted deliberately, by a
          maintainer, because no automatic signal identifies this contribution.

The issuer key is read from the environment:
  VOUCH_PRIVATE_KEY  Ed25519 private key JWK (JSON string)
  VOUCH_DID          Issuer DID, e.g. did:web:vouch-protocol.com

Examples:
  export VOUCH_DID='did:web:vouch-protocol.com'
  export VOUCH_PRIVATE_KEY='{"kty":"OKP","crv":"Ed25519",...}'

  # A merged pull request's author.
  python scripts/mint_contributor_credential.py \\
      --subject Franflorio \\
      --pr-url https://github.com/vouch-protocol/vouch/pull/110 \\
      --pr-number 110 --repo vouch-protocol/vouch

  # Someone whose design a pull request implements.
  python scripts/mint_contributor_credential.py \\
      --subject SOME_HANDLE \\
      --contribution-type design \\
      --contribution "Proposed X and supplied the Y scenario" \\
      --pr-url https://github.com/vouch-protocol/vouch/pull/123 \\
      --pr-number 123 --repo vouch-protocol/vouch
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

CONTRIBUTION_CODE = "code"
CONTRIBUTION_DESIGN = "design"
VALID_CONTRIBUTION_TYPES = (CONTRIBUTION_CODE, CONTRIBUTION_DESIGN)

# The role recorded in the credential, per contribution type. A design
# contributor gets a distinct role so nothing in the credential implies they
# authored the commits.
_ROLE_BY_TYPE = {
    CONTRIBUTION_CODE: "verified-contributor",
    CONTRIBUTION_DESIGN: "design-contributor",
}


def mint_credential(
    subject: str,
    pr_url: str,
    pr_number: str,
    repo: str,
    private_key: str,
    did: str,
    valid_days: int = DEFAULT_VALID_DAYS,
    parent_credential: dict | None = None,
    contribution_type: str = CONTRIBUTION_CODE,
    contribution: str = "",
) -> dict:
    """Return a signed Vouch Credential attesting a contribution.

    `contribution_type` is `code` (the subject authored the merged pull
    request's commits) or `design` (the subject contributed the design the pull
    request implements, without writing the code). For `design` the credential
    records the contribution in `contribution` and references the implementing
    pull request under `implementedIn`, and it never claims authorship.

    If `parent_credential` (the root -> contributor delegation) is provided, it
    is attached so the badge traces back to the root authority.
    """
    if contribution_type not in VALID_CONTRIBUTION_TYPES:
        raise ValueError(
            f"contribution_type must be one of {VALID_CONTRIBUTION_TYPES}, got {contribution_type!r}"
        )
    if contribution_type == CONTRIBUTION_DESIGN and not contribution:
        raise ValueError(
            "a design contribution must describe what was contributed (--contribution)"
        )

    signer = Signer(private_key=private_key, did=did)
    number = int(pr_number) if pr_number.isdigit() else pr_number
    intent = {
        "action": "attest",
        "target": f"github:{subject}",
        # resource is required by the credential model; bind it to the PR.
        "resource": pr_url,
        "role": _ROLE_BY_TYPE[contribution_type],
        "repository": repo,
        "contributionType": contribution_type,
    }
    if contribution_type == CONTRIBUTION_CODE:
        # The subject authored this pull request.
        intent["pullRequest"] = number
    else:
        # The subject did not author the pull request; it is where their
        # contribution was implemented by someone else.
        intent["implementedIn"] = number
        intent["contribution"] = contribution

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
    parser.add_argument(
        "--contribution-type",
        default=CONTRIBUTION_CODE,
        choices=list(VALID_CONTRIBUTION_TYPES),
        help=(
            "code: the subject authored the pull request's commits (default). "
            "design: the subject contributed the design the pull request "
            "implements, without writing the code."
        ),
    )
    parser.add_argument(
        "--contribution",
        default="",
        help="What was contributed. Required for --contribution-type design.",
    )
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

    try:
        credential = mint_credential(
            subject=args.subject,
            pr_url=args.pr_url,
            pr_number=args.pr_number,
            repo=args.repo,
            private_key=private_key,
            did=did,
            parent_credential=parent_credential,
            contribution_type=args.contribution_type,
            contribution=args.contribution,
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

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
