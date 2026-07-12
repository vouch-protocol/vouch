#!/usr/bin/env python3
"""Bootstrap the Vouch Adopter Authority: a delegated signing key for adopters.

This mirrors the Conformance and Contributor authorities. It creates a delegated
key whose only job is to sign "Vouch Verified Integration" certificates for
systems that build on the protocol, so the root key is never used for routine
issuance.

It is run once by the bootstrap-adopter-authority workflow, which supplies the
root key from the VOUCH_PRIVATE_KEY repository secret, so the root key never
leaves CI. It can also be run locally if you prefer. It:
  1. Generates a fresh Ed25519 keypair for did:web:vouch-protocol.com:adopters.
  2. Writes the public DID document to website/public/adopters/did.json.
  3. Signs a root -> adopter-authority delegation to adopters/delegation.json,
     using the root key supplied in the environment.
  4. Writes the adopter authority PRIVATE key to adopter-authority-key.json
     (gitignored) for storage in the VOUCH_ADOPTER_PRIVATE_KEY secret.

The root key is read from the environment and never written anywhere:
  VOUCH_ROOT_PRIVATE_KEY  Ed25519 private key JWK (JSON string) for the root DID
  VOUCH_ROOT_DID          Root issuer DID (default did:web:vouch-protocol.com)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone

from vouch import Signer, Verifier, generate_identity

ADOPTER_DID = "did:web:vouch-protocol.com:adopters"
ADOPTER_DOMAIN = "vouch-protocol.com:adopters"
# The namespace the adopter authority may attest under. Every integration
# certificate binds its resource beneath this URI, so the delegation never
# widens to broader authority than issuing adopter records.
ADOPTER_RESOURCE = "https://vouch-protocol.com/adopters"
DELEGATION_VALID_DAYS = 365 * 10

DID_DOC_PATH = "website/public/adopters/did.json"
DELEGATION_PATH = "adopters/delegation.json"
PRIVATE_KEY_PATH = "adopter-authority-key.json"


def build_did_document(public_key_jwk: str) -> dict:
    pub = json.loads(public_key_jwk)
    return {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
        ],
        "id": ADOPTER_DID,
        "verificationMethod": [
            {
                "id": f"{ADOPTER_DID}#key-1",
                "type": "JsonWebKey2020",
                "controller": ADOPTER_DID,
                "publicKeyJwk": {
                    "kty": pub["kty"],
                    "crv": pub["crv"],
                    "x": pub["x"],
                },
            }
        ],
        "authentication": [f"{ADOPTER_DID}#key-1"],
        "assertionMethod": [f"{ADOPTER_DID}#key-1"],
    }


def sign_delegation(root_private_key: str, root_did: str) -> dict:
    """Return a root -> adopter-authority delegation credential."""
    signer = Signer(private_key=root_private_key, did=root_did)
    intent = {
        "action": "delegate",
        "target": ADOPTER_DID,
        "resource": ADOPTER_RESOURCE,
        "role": "verified-adopter-issuer",
    }
    valid_from = datetime.now(timezone.utc).replace(microsecond=0)
    return signer.sign(
        intent=intent,
        valid_seconds=DELEGATION_VALID_DAYS * 86400,
        valid_from=valid_from,
    )


def _write_delegation(root_private_key: str, root_did: str) -> int:
    """Sign and write the root -> adopter delegation, then self-check it."""
    delegation = sign_delegation(root_private_key, root_did)
    os.makedirs(os.path.dirname(DELEGATION_PATH), exist_ok=True)
    with open(DELEGATION_PATH, "w", encoding="utf-8") as handle:
        json.dump(delegation, handle, indent=2)
        handle.write("\n")

    root_pub = Signer(private_key=root_private_key, did=root_did).get_public_key_jwk()
    ok, _ = Verifier.verify(json.dumps(delegation), public_key=root_pub)
    if not ok:
        print(
            "::error:: delegation did not verify against the root key. "
            "Check VOUCH_ROOT_PRIVATE_KEY and VOUCH_ROOT_DID.",
            file=sys.stderr,
        )
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Bootstrap the Vouch Adopter Authority")
    parser.add_argument(
        "--delegation-only",
        action="store_true",
        help="Re-sign adopters/delegation.json with the root key without "
        "regenerating the adopter key or DID document.",
    )
    args = parser.parse_args()

    root_private_key = os.getenv("VOUCH_ROOT_PRIVATE_KEY")
    root_did = os.getenv("VOUCH_ROOT_DID") or "did:web:vouch-protocol.com"
    if not root_private_key:
        print(
            "VOUCH_ROOT_PRIVATE_KEY (and optionally VOUCH_ROOT_DID) must be set "
            "to sign the adopter delegation with the root key.",
            file=sys.stderr,
        )
        return 1

    if args.delegation_only:
        # The adopter key already exists and is stored; only re-issue the
        # delegation so it is signed by the true root authority.
        rc = _write_delegation(root_private_key, root_did)
        if rc != 0:
            return rc
        print(f"Re-signed {DELEGATION_PATH} with root {root_did}.")
        print("Commit it. The adopter key and its secrets are unchanged.")
        return 0

    if os.path.exists(DID_DOC_PATH) or os.path.exists(DELEGATION_PATH):
        print(
            "Adopter authority files already exist. Remove "
            f"{DID_DOC_PATH} and {DELEGATION_PATH} first if you intend to rotate "
            "the key. Refusing to overwrite an existing authority.",
            file=sys.stderr,
        )
        return 1

    # 1 + 4: generate the delegated keypair.
    identity = generate_identity(domain=ADOPTER_DOMAIN)

    # 2: publish the public DID document.
    did_doc = build_did_document(identity.public_key_jwk)
    os.makedirs(os.path.dirname(DID_DOC_PATH), exist_ok=True)
    with open(DID_DOC_PATH, "w", encoding="utf-8") as handle:
        json.dump(did_doc, handle, indent=2)
        handle.write("\n")

    # 3: sign the root -> adopter delegation (self-checked against the root key).
    rc = _write_delegation(root_private_key, root_did)
    if rc != 0:
        return rc

    # 4: write the adopter authority private key for the operator to store.
    with open(PRIVATE_KEY_PATH, "w", encoding="utf-8") as handle:
        handle.write(identity.private_key_jwk)
        handle.write("\n")

    print("Adopter authority bootstrapped.")
    print(f"  Wrote public DID document : {DID_DOC_PATH}")
    print(f"  Wrote root delegation     : {DELEGATION_PATH}")
    print(f"  Wrote PRIVATE signing key : {PRIVATE_KEY_PATH}  (gitignored)")
    print()
    print("Next steps:")
    print(f"  1. Commit {DID_DOC_PATH} and {DELEGATION_PATH}.")
    print("  2. Store two repository secrets:")
    print(f"       VOUCH_ADOPTER_DID          = {ADOPTER_DID}")
    print(f"       VOUCH_ADOPTER_PRIVATE_KEY  = contents of {PRIVATE_KEY_PATH}")
    print(f"  3. Delete {PRIVATE_KEY_PATH} once the secret is stored.")
    print("  4. Run the 'Issue adopter certificate' workflow for each adopter.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
