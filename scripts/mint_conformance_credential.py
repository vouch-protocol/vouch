#!/usr/bin/env python3
"""Mint a "Vouch Verified Conformant" credential for an implementation.

This dogfoods the protocol: the project signs a Verifiable Credential attesting
that an implementation passed the Vouch conformance test at a given level (the
core profile), or passed the robotics profile. It mirrors
scripts/mint_contributor_credential.py. Designed to run in CI (see
.github/workflows/verified-conformance.yml) but is also runnable locally.

The conformance issuer key is read from the environment:
  VOUCH_CONFORMANCE_PRIVATE_KEY  Ed25519 private key JWK (JSON string)
  VOUCH_CONFORMANCE_DID          Issuer DID, e.g. did:web:vouch-protocol.com:conformance

For a post-quantum (L3-grade) badge, also set the persistent ML-DSA-44 issuer
key. When both are present the badge carries a proof set: an eddsa-jcs-2022
proof and an mldsa44-jcs-2024 proof in the credential's proof array. Otherwise
it carries the single classical eddsa-jcs-2022 proof:
  VOUCH_CONFORMANCE_MLDSA_SECRET  base64 of the ML-DSA-44 secret key
  MLDSA_PUBLIC_MULTIKEY           the ML-DSA-44 public key as a z-multikey

Example:
  export VOUCH_CONFORMANCE_DID='did:web:vouch-protocol.com:conformance'
  export VOUCH_CONFORMANCE_PRIVATE_KEY='{"kty":"OKP","crv":"Ed25519",...}'
  python scripts/mint_conformance_credential.py \\
      --subject vouch-protocol/vouch --commit abc1234 \\
      --profile core --level L2 \\
      --parent conformance/delegation.json --out credential.json
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys

from vouch import Signer, multikey

# A conformance pass is for a specific version, re-test on new releases. One year
# keeps a stale pass from lingering; the verifier requires a validUntil.
DEFAULT_VALID_DAYS = 365


def mint_credential(
    subject: str,
    profile: str,
    level: str,
    commit: str,
    transcript_hash: str,
    private_key: str,
    did: str,
    valid_days: int = DEFAULT_VALID_DAYS,
    parent_credential: dict | None = None,
    mldsa_secret: bytes | None = None,
    mldsa_public: bytes | None = None,
) -> dict:
    """Return a signed Vouch Credential attesting a conformance pass.

    If `parent_credential` (the root -> conformance delegation) is provided, it
    is attached so the badge traces back to the project root authority. If the
    ML-DSA-44 issuer keypair is provided, the badge is signed under the hybrid
    post-quantum profile; otherwise it uses the classical Ed25519 proof.
    """
    signer = Signer(private_key=private_key, did=did)
    role = "robotics-conformant" if profile == "robotics" else f"conformant-{level}"
    target = f"github:{subject}@{commit}" if commit else f"github:{subject}"
    intent = {
        "action": "attest",
        "target": target,
        # resource is required by the credential model; bind it to the repo.
        "resource": f"https://github.com/{subject}",
        "role": role,
        "profile": profile,  # "core" or "robotics"
        "level": level,  # "L1"/"L2"/"L3" for core, "" for robotics
        "repository": subject,
        "commit": commit,
        "transcriptHash": transcript_hash,
    }
    if mldsa_secret is not None and mldsa_public is not None:
        # Post-quantum hybrid badge: inject the persistent issuer ML-DSA-44 key
        # so the signer does not generate a fresh random one per run.
        signer._mldsa44_secret = mldsa_secret
        signer._mldsa44_public = mldsa_public
        return signer.sign_hybrid(
            intent=intent,
            valid_seconds=valid_days * 86400,
            parent_credential=parent_credential,
        )
    return signer.sign(
        intent=intent,
        valid_seconds=valid_days * 86400,
        parent_credential=parent_credential,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Mint a Vouch Verified Conformant credential",
    )
    parser.add_argument("--subject", required=True, help="owner/repo of the implementation")
    parser.add_argument(
        "--profile",
        default="core",
        choices=["core", "robotics"],
        help="Conformance profile (default: core)",
    )
    parser.add_argument("--level", default="", help="L1, L2, or L3 (core profile only)")
    parser.add_argument("--commit", default="", help="Commit SHA the run was bound to")
    parser.add_argument("--transcript-hash", default="", help="Hash of the challenge transcript")
    parser.add_argument("--out", default="-", help="Output file, or - for stdout")
    parser.add_argument(
        "--parent",
        default="",
        help="Path to the root delegation credential (conformance/delegation.json). Optional.",
    )
    args = parser.parse_args(argv)

    private_key = os.getenv("VOUCH_CONFORMANCE_PRIVATE_KEY")
    did = os.getenv("VOUCH_CONFORMANCE_DID")
    if not private_key or not did:
        print(
            "VOUCH_CONFORMANCE_PRIVATE_KEY and VOUCH_CONFORMANCE_DID must be set to mint a credential.",
            file=sys.stderr,
        )
        return 1
    if args.profile == "core" and args.level not in ("L1", "L2", "L3"):
        print("The core profile requires --level L1, L2, or L3.", file=sys.stderr)
        return 1

    # Optional post-quantum hybrid signing: both the secret and the published
    # public multikey must be present.
    mldsa_secret = None
    mldsa_public = None
    sec_b64 = os.getenv("VOUCH_CONFORMANCE_MLDSA_SECRET")
    pub_multikey = os.getenv("MLDSA_PUBLIC_MULTIKEY")
    if sec_b64 and pub_multikey:
        mldsa_secret = base64.b64decode(sec_b64)
        _, mldsa_public = multikey.decode(pub_multikey)

    parent_credential = None
    if args.parent and os.path.exists(args.parent):
        with open(args.parent, encoding="utf-8") as handle:
            parent_credential = json.load(handle)

    credential = mint_credential(
        subject=args.subject,
        profile=args.profile,
        level=args.level,
        commit=args.commit,
        transcript_hash=args.transcript_hash,
        private_key=private_key,
        did=did,
        parent_credential=parent_credential,
        mldsa_secret=mldsa_secret,
        mldsa_public=mldsa_public,
    )

    text = json.dumps(credential, indent=2)
    if args.out == "-":
        print(text)
    else:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text)
        label = "robotics" if args.profile == "robotics" else args.level
        suite = credential.get("proof", {}).get("cryptosuite", "")
        print(
            f"Wrote {label} conformance credential ({suite}) for {args.subject} to {args.out}",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
