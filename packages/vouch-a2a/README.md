# vouch-a2a

Bind [A2A](https://a2a-protocol.org/) (Agent2Agent) Agent Cards to a
[Vouch](https://vouch-protocol.com) identity, so two agents can establish trust
before they collaborate.

A2A standardized how agents discover and talk to each other through Agent Cards.
It does not, by itself, prove who stands behind an agent. `vouch-a2a` attaches a
W3C Verifiable Credential (`eddsa-jcs-2022` Data Integrity proof) to the card,
optionally with a delegation chain back to the human or org that operates the
agent. A verifier can then refuse an unsigned or impostor peer.

## Install

```bash
pip install vouch-a2a
```

## Sign an Agent Card

```python
from vouch import Signer
from vouch_a2a import sign_agent_card

signer = Signer(private_key=PRIV_JWK, did="did:web:agents.acme.com")

card = {
    "name": "BillingAgent",
    "url": "https://agents.acme.com/billing",
    "version": "1.0.0",
    "capabilities": {"streaming": True},
    "skills": [{"id": "invoice", "name": "Create invoice"}],
}

signed_card = sign_agent_card(signer, card)          # adds a 'vouchCredential' field
# Optionally bind to an org principal:
# signed_card = sign_agent_card(signer, card, parent_credential=org_principal_cred)
```

## Verify a peer's card

```python
from vouch_a2a import verify_agent_card

ok, passport = verify_agent_card(peer_card, public_key=peer_pubkey)
if not ok:
    raise PermissionError("Refusing to collaborate with an unverified agent")
```

The credential binds to the card's `url` (the stable agent identity). The input
card is never mutated; `sign_agent_card` returns a copy.

## License

Apache-2.0.
