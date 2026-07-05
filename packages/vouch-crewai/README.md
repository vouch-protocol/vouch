# vouch-crewai

A [CrewAI](https://www.crewai.com/) tool that issues
[Vouch](https://vouch-protocol.com) Credentials, so the agents in a crew can
cryptographically authorize their tool calls, including across delegation.

Each signed call carries a W3C Verifiable Credential with an `eddsa-jcs-2022`
Data Integrity proof. When a supervisor agent delegates to a worker, the
worker's credential extends the supervisor's chain and can only narrow the
authority, never broaden it.

## Install

```bash
pip install vouch-crewai
```

This pulls in `vouch-protocol[crewai]`.

## Configure

- `VOUCH_PRIVATE_KEY` the agent's private key (JWK JSON string).
- `VOUCH_DID` the agent's DID, e.g. `did:web:agent.example.com`.

## Use

```python
from vouch_crewai import sign_request

# Give the tool to a CrewAI agent. It calls it before an authenticated request.
credential_json = sign_request(
    action="read",
    target="https://api.example.com",
    resource="customer:123",
)
```

## Delegation between agents

See `examples/integrations_delegation.py` in the main repo for a supervisor
that issues a broad credential and a worker that narrows it under capability
attenuation.

## Verify on the receiving side

```python
from vouch import Verifier
ok, passport = Verifier.verify_credential(received_json, public_key=agent_pubkey)
```

## License

Apache-2.0.
