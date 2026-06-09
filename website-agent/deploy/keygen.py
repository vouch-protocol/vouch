#!/usr/bin/env python3
"""Generate the production Vouch agent keypair + DID document.

Run ONCE, locally, before the first deploy. Outputs three files into a
target directory:

    seed.hex         -- 32-byte Ed25519 seed, hex-encoded. Becomes the
                        Fly secret VOUCH_ED25519_SEED. Never commit.
    public.multikey  -- The public key in W3C Multikey form
                        (multicodec 0xed prefix, base58btc encoded).
    did.json         -- The DID document served at
                        https://agent.vouch-protocol.com/.well-known/did.json

The seed is the ONLY piece you need to back up. Public key + DID
document are derivable from it.

Usage:
    python deploy/keygen.py --did did:web:agent.vouch-protocol.com \
        --out ~/.vouch/agent-prod

Safety:
    The script refuses to overwrite an existing seed.hex unless --force
    is passed. Replacing the seed rotates the agent's identity, which
    invalidates every credential it has issued.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# --- Multikey encoding ----------------------------------------------------

_BASE58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58encode(data: bytes) -> str:
    """Base58btc encode (Bitcoin alphabet)."""
    num = int.from_bytes(data, "big")
    out = bytearray()
    while num > 0:
        num, rem = divmod(num, 58)
        out.append(_BASE58_ALPHABET[rem])
    # Preserve leading zero bytes as leading '1's
    for byte in data:
        if byte == 0:
            out.append(_BASE58_ALPHABET[0])
        else:
            break
    return bytes(reversed(out)).decode("ascii")


def ed25519_public_to_multikey(public_bytes: bytes) -> str:
    """W3C Multikey for Ed25519: prefix 0xed01 (varint of 0xed) + key, base58btc."""
    if len(public_bytes) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    # multicodec 0xed (ed25519-pub) as varint = 0xed 0x01
    multicodec = bytes([0xED, 0x01]) + public_bytes
    return "z" + _b58encode(multicodec)


# --- Key + DID generation -------------------------------------------------


def build_did_document(did: str, multikey: str) -> dict:
    vm_id = f"{did}#key-0"
    return {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1",
        ],
        "id": did,
        "verificationMethod": [
            {
                "id": vm_id,
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": multikey,
            }
        ],
        "assertionMethod": [vm_id],
        "authentication": [vm_id],
        "service": [
            {
                "id": f"{did}#agent",
                "type": "VouchAgent",
                "serviceEndpoint": "https://agent.vouch-protocol.com",
            }
        ],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--did", required=True, help="did:web identifier, e.g. did:web:agent.vouch-protocol.com")
    ap.add_argument("--out", required=True, type=Path, help="output directory (will be created if missing)")
    ap.add_argument("--force", action="store_true", help="overwrite an existing seed.hex (rotates identity)")
    args = ap.parse_args()

    out: Path = args.out.expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)

    seed_path = out / "seed.hex"
    if seed_path.exists() and not args.force:
        print(f"refusing to overwrite {seed_path} without --force", file=sys.stderr)
        return 1

    seed = secrets.token_bytes(32)
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    multikey = ed25519_public_to_multikey(public_bytes)
    did_document = build_did_document(args.did, multikey)

    seed_path.write_text(seed.hex() + "\n", encoding="utf-8")
    os.chmod(seed_path, 0o600)

    (out / "public.multikey").write_text(multikey + "\n", encoding="utf-8")
    (out / "did.json").write_text(json.dumps(did_document, indent=2) + "\n", encoding="utf-8")
    (out / "GENERATED").write_text(
        f"Generated {datetime.now(timezone.utc).isoformat()} for {args.did}\n",
        encoding="utf-8",
    )

    print(f"wrote {seed_path}        (32-byte seed, mode 0600)")
    print(f"wrote {out / 'public.multikey'}  ({multikey})")
    print(f"wrote {out / 'did.json'}         (DID document for {args.did})")
    print()
    print("Next steps:")
    print(f"  cp '{out / 'did.json'}' website-agent/deploy/did.json")
    print("  fly secrets set VOUCH_ED25519_SEED=\"$(cat '" + str(seed_path) + "')\"")
    return 0


if __name__ == "__main__":
    sys.exit(main())
