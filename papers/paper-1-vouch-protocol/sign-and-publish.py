#!/usr/bin/env python3
"""
Sign paper-1-vouch-protocol.pdf with the Vouch Protocol DID and register it
end-to-end through the Vouch HTTP API, so the act of publishing the paper is
itself a working demonstration of the protocol.

Flow:
  1. Compute SHA-256 of the final PDF.
  2. Build a Vouch Credential whose `intent` describes the act of publishing
     this paper (action=publish_paper, target=sha256:<digest>, resource=GitHub PDF URL).
     Attach a Data Integrity proof (eddsa-jcs-2022) using the Vouch Protocol
     Ed25519 signing key at ~/.vouch/keys/did-web-vouch-protocol.com.json.
  3. Mint a separate Vouch-Token JWS authenticating the registration request
     itself, signed by the same Ed25519 key under issuer "github:rampyg"
     (which is on the Worker's PRO_SIGNERS list, granting custom-ID rights).
  4. Dry-run by default: print the equivalent curl command without making any
     network call.
  5. With --publish: POST to https://api.vouch-protocol.com/api/paper/register,
     then GET https://vouch-protocol.com/v/arxiv-1 to verify round-trip.

The two-step token design is intentional and reflects the protocol's intent
binding: the credential signs the paper (a long-lived public artifact); the
Vouch-Token signs a short-lived registration request. They have different
audiences and different validity windows.

Run:
    python papers/paper-1-vouch-protocol/sign-and-publish.py            # dry-run
    python papers/paper-1-vouch-protocol/sign-and-publish.py --publish  # really publish

Output:
    papers/paper-1-vouch-protocol/paper-1-vouch-credential.json
    papers/paper-1-vouch-protocol/paper-1-arxiv-1-kv.json
    papers/paper-1-vouch-protocol/paper-1-vouch-token.txt
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPO = Path("/home/rampy/vouch-protocol")
PAPER_DIR = REPO / "papers" / "paper-1-vouch-protocol"
PDF_PATH = PAPER_DIR / "paper-1-vouch-protocol.pdf"
# Personal DID key for the author. The credential issuer is the user, not the
# protocol; the protocol's role is publishing infrastructure, captured in the
# binding credential at docs/u/rampy/binding.jsonld.
USER_DID = "did:web:vouch-protocol.com:u:rampy"
USER_KEY_PATH = Path.home() / ".vouch" / "keys" / "did-web-vouch-protocol.com_u_rampy.json"
# Auth-token key (legacy github:rampyg label is what the Worker's PRO_SIGNERS
# list recognises). The token is short-lived and only authenticates the
# registration request; it does NOT sign the paper itself.
AUTH_TOKEN_KEY_PATH = Path.home() / ".vouch" / "keys" / "did-web-vouch-protocol.com.json"

CREDENTIAL_OUT = PAPER_DIR / "paper-1-vouch-credential.json"
KV_OUT = PAPER_DIR / "paper-1-arxiv-1-kv.json"
TOKEN_OUT = PAPER_DIR / "paper-1-vouch-token.txt"

PAPER_ID = "arxiv-1"
ISSUER_DID = USER_DID  # the author signs as themselves
GITHUB_SIGNER = "github:rampyg"  # must be on the Worker's PRO_SIGNERS list
AUTHOR = "Ramprasad Anandam Gaddam"
SIGNER_LABEL = USER_DID  # what shows on the verify page as "Signer"
TITLE = (
    "Vouch Protocol: Cryptographic Identity and Continuous State "
    "Verifiability for Autonomous AI Agents"
)

RESOURCE_URL = "https://github.com/vouch-protocol/vouch/blob/main/papers/paper-1-vouch-protocol/paper-1-vouch-protocol.pdf"
SHORTLINK = f"https://vch.sh/{PAPER_ID}"
VERIFY_URL = f"https://vouch-protocol.com/v/{PAPER_ID}"
REGISTER_API = "https://api.vouch-protocol.com/api/paper/register"
VERIFY_API = f"https://api.vouch-protocol.com/api/paper/verify/{PAPER_ID}"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--publish",
        action="store_true",
        help="Actually POST to the Vouch API. Default is a dry run.",
    )
    args = parser.parse_args()

    sys.path.insert(0, str(REPO))

    if not PDF_PATH.exists():
        print(f"error: {PDF_PATH} not found. Build the PDF first.", file=sys.stderr)
        return 1
    if not USER_KEY_PATH.exists():
        print(f"error: personal DID key not found at {USER_KEY_PATH}", file=sys.stderr)
        print(f"   create it first: python scripts/create-user-did.py --handle rampy --name ... --email ...", file=sys.stderr)
        return 1
    if not AUTH_TOKEN_KEY_PATH.exists():
        print(f"error: protocol key for auth-token not found at {AUTH_TOKEN_KEY_PATH}", file=sys.stderr)
        return 1

    # ----------------------------------------------------------------------
    # 1. SHA-256 the PDF.
    # ----------------------------------------------------------------------
    digest = sha256_file(PDF_PATH)
    size_bytes = PDF_PATH.stat().st_size
    print(f"PDF:     {PDF_PATH.relative_to(REPO)}")
    print(f"size:    {size_bytes:,} bytes")
    print(f"sha256:  {digest}")
    print()

    # ----------------------------------------------------------------------
    # 2. Sign the paper itself with a Vouch Credential. Issuer is the user's
    #    personal DID; the protocol's role is captured in the separate
    #    binding credential at docs/u/rampy/binding.jsonld.
    # ----------------------------------------------------------------------
    user_key_blob = json.loads(USER_KEY_PATH.read_text(encoding="utf-8"))
    user_private_jwk_str = user_key_blob["private_key"]

    from vouch.signer import Signer

    paper_signer = Signer(private_key=user_private_jwk_str, did=ISSUER_DID)

    intent = {
        "action": "publish_paper",
        "target": f"sha256:{digest}",
        "resource": RESOURCE_URL,
        "title": TITLE,
        "shortlink": SHORTLINK,
        "paperId": PAPER_ID,
    }
    credential = paper_signer.sign_credential(
        intent=intent,
        valid_seconds=100 * 365 * 24 * 3600,  # 100 years for an archival signature
    )

    CREDENTIAL_OUT.write_text(
        json.dumps(credential, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    print(f"wrote credential:  {CREDENTIAL_OUT.relative_to(REPO)}")

    proof = credential.get("proof", {})
    signature_b58 = proof.get("proofValue")

    # ----------------------------------------------------------------------
    # 3. Mint a Vouch-Token (legacy JWS) authenticating the registration
    #    request to the Cloudflare Worker. Issuer = github:rampyg so the
    #    Worker grants Pro-tier rights, enabling the custom paper ID. This
    #    is the operator's auth token, separate from the paper signature.
    # ----------------------------------------------------------------------
    auth_key_blob = json.loads(AUTH_TOKEN_KEY_PATH.read_text(encoding="utf-8"))
    auth_private_jwk_str = auth_key_blob["private_key"]
    gh_signer = Signer(private_key=auth_private_jwk_str, did=GITHUB_SIGNER)
    vouch_token = gh_signer.sign(
        {
            "action": "register_paper",
            "target": PAPER_ID,
            "resource": REGISTER_API,
            "sha256": digest,
        },
        expiry_seconds=15 * 60,  # 15-minute registration window
    )
    TOKEN_OUT.write_text(vouch_token + "\n", encoding="utf-8")
    print(f"wrote vouch-token: {TOKEN_OUT.relative_to(REPO)}")

    # ----------------------------------------------------------------------
    # 4. Build the registration body.
    # ----------------------------------------------------------------------
    body = {
        "id": PAPER_ID,
        "sha256": digest,
        "author": AUTHOR,
        "signer": SIGNER_LABEL,
        "signature": signature_b58,
        "title": TITLE,
        "resource": RESOURCE_URL,
        "cryptosuite": proof.get("cryptosuite", "eddsa-jcs-2022"),
    }

    # Local KV-shaped record (mirrors what the Worker will store; useful for
    # offline verification and for an emergency wrangler restore).
    kv_record = {
        **body,
        "registered": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "type": "paper",
        "tier": "pro",
        "credential": credential,
        "shortlink": SHORTLINK,
        "resource": RESOURCE_URL,
    }
    KV_OUT.write_text(
        json.dumps(kv_record, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    print(f"wrote kv mirror:   {KV_OUT.relative_to(REPO)}")

    # ----------------------------------------------------------------------
    # 5. Dry-run or publish.
    # ----------------------------------------------------------------------
    print()

    if not args.publish:
        print("Dry run. The equivalent live call would be:")
        print()
        print(f"    curl -X POST {REGISTER_API} \\")
        print("        -H 'Content-Type: application/json' \\")
        print("        -H \"Vouch-Token: $(cat papers/paper-1-vouch-protocol/paper-1-vouch-token.txt)\" \\")
        print("        -d @papers/paper-1-vouch-protocol/paper-1-arxiv-1-register-body.json")
        print()
        print("Re-run with --publish to actually post.")

        # Also emit the exact body JSON so the user can curl it themselves.
        body_path = PAPER_DIR / "paper-1-arxiv-1-register-body.json"
        body_path.write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")
        print(f"wrote body:        {body_path.relative_to(REPO)}")
        return 0

    # --publish: actually call the API.
    print(f"POST {REGISTER_API}")
    req = urllib.request.Request(
        REGISTER_API,
        data=json.dumps(body).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Vouch-Token": vouch_token,
            # Cloudflare's bot fingerprint check (error 1010) rejects
            # Python's default urllib UA. Identify ourselves clearly.
            "User-Agent": "vouch-protocol-paper-publisher/1.0 (+https://github.com/vouch-protocol/vouch)",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            print(f"  status: {resp.status}")
            print(f"  body:   {resp.read().decode('utf-8')}")
    except urllib.error.HTTPError as e:
        print(f"  HTTP {e.code}: {e.read().decode('utf-8')}", file=sys.stderr)
        return 1
    except urllib.error.URLError as e:
        print(f"  network error: {e}", file=sys.stderr)
        return 1

    # Round-trip verify.
    print()
    print(f"GET {VERIFY_API}")
    try:
        verify_req = urllib.request.Request(
            VERIFY_API,
            headers={
                "User-Agent": "vouch-protocol-paper-publisher/1.0 (+https://github.com/vouch-protocol/vouch)",
                "Accept": "application/json",
            },
        )
        with urllib.request.urlopen(verify_req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            print(f"  status: {resp.status}")
            print(f"  verified sha256: {data.get('sha256')}")
            if data.get("sha256") == digest:
                print(f"  OK. Shortlink resolves: {SHORTLINK}")
            else:
                print("  MISMATCH between local digest and stored record.", file=sys.stderr)
                return 1
    except urllib.error.HTTPError as e:
        print(f"  HTTP {e.code}: {e.read().decode('utf-8')}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
