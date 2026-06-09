#!/usr/bin/env python3
"""
Create a personal DID for a user, bound to the Vouch Protocol's publishing
identity by a Vouch Credential.

What this produces:

  1. A fresh Ed25519 keypair for the user.
  2. A DID Document at `docs/u/<handle>/did.json` describing the user's DID
     `did:web:vouch-protocol.com:u:<handle>`, with a Multikey verification
     method, an `alsoKnownAs` alias, and a `service` block pointing at the
     binding credential.
  3. A Data-Integrity-signed binding credential at
     `docs/u/<handle>/binding.jsonld` whose issuer is the protocol
     (`did:web:vouch-protocol.com`) and whose subject is the user's DID.
     The protocol attests that this DID belongs to the named person.
  4. The user's private key in `~/.vouch/keys/did-web-vouch-protocol.com_u_<handle>.json`
     (plaintext for now; the next script moves it to encrypted storage).

Run:

    python scripts/create-user-did.py --handle rampy \\
                                       --name "Ramprasad Anandam Gaddam" \\
                                       --email ram@vouch-protocol.com

The script is idempotent in one direction only: it refuses to overwrite an
existing user DID unless you pass --force. Use --force only if you are
deliberately rotating the key.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

REPO = Path("/home/rampy/vouch-protocol")
PROTOCOL_DID = "did:web:vouch-protocol.com"
PROTOCOL_KEY = Path.home() / ".vouch" / "keys" / "did-web-vouch-protocol.com.json"
USER_KEYS_DIR = Path.home() / ".vouch" / "keys"
DOCS_USERS_DIR = REPO / "docs" / "u"


def make_did(handle: str) -> str:
    return f"{PROTOCOL_DID}:u:{handle}"


def make_did_url(handle: str) -> str:
    # did:web with a path segment resolves to {origin}/u/{handle}/did.json
    return f"https://vouch-protocol.com/u/{handle}/did.json"


def b58encode(data: bytes) -> str:
    """multibase z-prefixed base58btc (matches vouch.multikey._b58encode)."""
    sys.path.insert(0, str(REPO))
    from vouch import multikey
    return multikey._b58encode(data)


def generate_ed25519_keypair():
    """Generate a new Ed25519 keypair. Returns (private_jwk_str, public_multibase, public_jwk_dict)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PrivateFormat,
        PublicFormat,
        NoEncryption,
    )
    from jwcrypto import jwk
    from jwcrypto.common import base64url_encode

    sys.path.insert(0, str(REPO))
    from vouch import multikey

    priv = Ed25519PrivateKey.generate()
    raw_priv = priv.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )
    pub = priv.public_key()
    raw_pub = pub.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)

    # JWK form (what vouch.signer.Signer expects)
    jwk_obj = jwk.JWK.generate(kty="OKP", crv="Ed25519")
    # Replace its random bytes with our deterministic ones
    jwk_obj_dict = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": base64url_encode(raw_pub),
        "d": base64url_encode(raw_priv),
    }
    private_jwk_str = json.dumps(jwk_obj_dict, separators=(",", ":"))

    # Multikey form (what DID Documents use)
    public_multibase = multikey.encode_ed25519_public(raw_pub)

    public_jwk = {"kty": "OKP", "crv": "Ed25519", "x": base64url_encode(raw_pub)}

    return private_jwk_str, public_multibase, public_jwk


def build_did_document(did: str, handle: str, name: str, email: str, public_multibase: str) -> dict:
    """W3C DID Document, Multikey verification method."""
    return {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1",
        ],
        "id": did,
        "alsoKnownAs": [
            f"mailto:{email}",
            f"https://vouch-protocol.com/u/{handle}/",
        ],
        "verificationMethod": [
            {
                "id": f"{did}#key-1",
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": public_multibase,
            }
        ],
        "assertionMethod": [f"{did}#key-1"],
        "authentication": [f"{did}#key-1"],
        "service": [
            {
                "id": f"{did}#vouch-binding",
                "type": "VouchBindingCredential",
                "serviceEndpoint": f"https://vouch-protocol.com/u/{handle}/binding.jsonld",
            }
        ],
        "_meta": {
            "subject": name,
            "issuedBy": PROTOCOL_DID,
            "note": (
                "This DID is the personal Vouch identity of the named subject, "
                "bound to the Vouch Protocol publishing identity by the credential "
                "at the `service` endpoint above."
            ),
        },
    }


def build_binding_credential(did: str, name: str, email: str, did_url: str) -> dict:
    """Unsigned binding credential. Protocol asserts this DID belongs to this person."""
    issued_at = datetime.now(timezone.utc)
    # 100 years validity (matches paper credential)
    from datetime import timedelta
    expires_at = issued_at + timedelta(days=365 * 100)
    iso = lambda dt: dt.isoformat().replace("+00:00", "Z")

    return {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://vouch-protocol.com/contexts/v1",
        ],
        "id": f"urn:uuid:{uuid.uuid4()}",
        "type": ["VerifiableCredential", "VouchCredential", "DIDBindingCredential"],
        "issuer": PROTOCOL_DID,
        "validFrom": iso(issued_at),
        "validUntil": iso(expires_at),
        "credentialSubject": {
            "id": did,
            "vouchVersion": "1.0",
            "intent": {
                "action": "bind_identity",
                "target": did,
                "resource": did_url,
                "person": {"name": name, "email": email},
            },
        },
    }


def attach_data_integrity_proof(credential: dict) -> dict:
    """Sign the credential with the protocol's key (issuer = did:web:vouch-protocol.com)."""
    sys.path.insert(0, str(REPO))
    from vouch.signer import Signer

    if not PROTOCOL_KEY.exists():
        raise FileNotFoundError(f"protocol signing key missing at {PROTOCOL_KEY}")

    key_blob = json.loads(PROTOCOL_KEY.read_text(encoding="utf-8"))
    private_jwk_str = key_blob["private_key"]

    # Use the Signer's data-integrity path manually since the credential is
    # already constructed (Signer.sign_credential builds its own).
    from vouch.data_integrity import build_proof

    signer = Signer(private_key=private_jwk_str, did=PROTOCOL_DID)
    proof = build_proof(
        credential,
        signer._raw_priv,
        verification_method=f"{PROTOCOL_DID}#key-1",
    )
    credential["proof"] = proof
    return credential


def write_user_key(handle: str, did: str, private_jwk_str: str, public_jwk: dict) -> Path:
    """Write the user's private key file in the same shape as the protocol key."""
    USER_KEYS_DIR.mkdir(parents=True, exist_ok=True)
    key_path = USER_KEYS_DIR / f"did-web-vouch-protocol.com_u_{handle}.json"
    payload = {
        "v": 1,
        "id": did,
        "algo": "Ed25519",
        "public_key": json.dumps(public_jwk),
        "encrypted": False,
        "private_key": private_jwk_str,
    }
    key_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    key_path.chmod(0o600)
    return key_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--handle", required=True, help="DID path segment (e.g. 'rampy')")
    parser.add_argument("--name", required=True, help="Display name of the person")
    parser.add_argument("--email", required=True, help="Contact email")
    parser.add_argument("--force", action="store_true", help="Overwrite existing files")
    args = parser.parse_args()

    handle = args.handle.lower().strip()
    if not handle.replace("-", "").isalnum():
        print(f"error: handle must be alphanumeric (with optional dashes): got {handle!r}", file=sys.stderr)
        return 1

    did = make_did(handle)
    did_url = make_did_url(handle)
    user_dir = DOCS_USERS_DIR / handle
    did_doc_path = user_dir / "did.json"
    binding_path = user_dir / "binding.jsonld"

    if (did_doc_path.exists() or binding_path.exists()) and not args.force:
        print(
            f"error: DID artefacts already exist at {user_dir}\n"
            f"   pass --force to overwrite (rotates the key)",
            file=sys.stderr,
        )
        return 1

    print(f"Creating personal DID for {args.name}")
    print(f"  did:       {did}")
    print(f"  resolves:  {did_url}")
    print()

    # 1. Keypair
    private_jwk_str, public_multibase, public_jwk = generate_ed25519_keypair()
    print(f"Generated Ed25519 keypair")
    print(f"  multikey:  {public_multibase}")

    # 2. DID Document
    did_doc = build_did_document(did, handle, args.name, args.email, public_multibase)
    user_dir.mkdir(parents=True, exist_ok=True)
    did_doc_path.write_text(json.dumps(did_doc, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote DID Document: {did_doc_path.relative_to(REPO)}")

    # 3. Binding credential signed by the protocol
    binding = build_binding_credential(did, args.name, args.email, did_url)
    binding = attach_data_integrity_proof(binding)
    binding_path.write_text(json.dumps(binding, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote binding credential: {binding_path.relative_to(REPO)}")

    # 4. Private key
    key_path = write_user_key(handle, did, private_jwk_str, public_jwk)
    print(f"Wrote private key: {key_path}")
    print(f"   chmod 600 (owner read-only)")

    print()
    print("Done. Next steps:")
    print()
    print(f"  1. Verify the binding credential round-trip:")
    print(f"     python -c \"import json; from vouch.verifier import verify_credential; "
          f"v = verify_credential(json.load(open('{binding_path.relative_to(REPO)}'))); print(v)\"")
    print()
    print("  2. Deploy the DID Document (it must be reachable at the resolves URL above)")
    print("     by committing docs/u/{}/  and letting the GitHub Pages action redeploy.".format(handle))
    print()
    print("  3. Re-run the paper publish using the new key:")
    print(f"     python papers/paper-1-vouch-protocol/sign-and-publish.py --signer-did {did}")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
