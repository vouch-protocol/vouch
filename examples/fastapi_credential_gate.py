"""
FastAPI Credential Gate — reject unsigned agent requests in one line.

Before, every protected endpoint hand-wrote the same boilerplate: read a header,
call ``Verifier.verify_credential`` with a hard-coded public key, raise 401,
maybe check the intent. ``VouchGate`` collapses that to a single dependency.

Run & verify:
  1. Mint a public key + a signed credential:
       from vouch import Signer, generate_identity
       import json
       ident = generate_identity(domain="example.com")
       print("PUBKEY:", ident.public_key_jwk)
       cred = Signer(private_key=ident.private_key_jwk, did=ident.did).sign_credential(
           intent={"action": "read", "target": "inbox",
                   "resource": "https://example.com/api/inbox"})
       print("CRED:", json.dumps(cred))
  2. export VOUCH_PUBLIC_KEY='<PUBKEY>'
     uvicorn fastapi_credential_gate:app --port 8000
  3. curl -X POST localhost:8000/api/resource -H "Vouch-Credential: <CRED>"   # 200
     curl -X POST localhost:8000/api/resource                                 # 401
"""

import os
from typing import Annotated

from fastapi import Depends, FastAPI

from vouch.integrations.fastapi import VouchGate
from vouch.verifier import CredentialPassport

app = FastAPI(title="Vouch Credential Gate")

# One gate, configured once. Pass `public_key=` for offline verification against
# a known issuer, `trusted_keys={did: key}` for an allowlist, or nothing at all
# to auto-resolve issuers via did:web. Add `require_action=...` to enforce intent.
gate = VouchGate(public_key=os.getenv("VOUCH_PUBLIC_KEY"))


@app.post("/api/resource")
async def protected_resource(passport: Annotated[CredentialPassport, Depends(gate)]):
    """Require a valid Vouch credential; the gate rejects everything else."""
    return {"status": "verified", "agent": passport.sub, "intent": passport.intent}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
