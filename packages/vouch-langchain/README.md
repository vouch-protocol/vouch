# vouch-langchain

A [LangChain](https://www.langchain.com/) tool that issues
[Vouch](https://vouch-protocol.com) Credentials, so a LangChain agent can
cryptographically authorize the tool calls it makes.

Each signed call carries a W3C Verifiable Credential with an `eddsa-jcs-2022`
Data Integrity proof, and optionally a delegation chain back to an accountable
human principal.

## Install

```bash
pip install vouch-langchain
```

This pulls in `vouch-protocol[langchain]`.

## Configure

The tool reads two environment variables:

- `VOUCH_PRIVATE_KEY` the agent's private key (JWK JSON string).
- `VOUCH_DID` the agent's DID, e.g. `did:web:agent.example.com`.

## Use

```python
from vouch_langchain import VouchSignerTool

tool = VouchSignerTool()  # reads VOUCH_PRIVATE_KEY / VOUCH_DID
credential_json = tool._run(
    action="read",
    target="https://api.example.com",
    resource="customer:123",
)
# Attach credential_json as a 'Vouch-Credential' header on your request.
```

Add `tool` to any LangChain agent's tool list. The agent calls it before an
authenticated request and forwards the credential to your service.

## Verify on the receiving side

```python
from vouch import Verifier
ok, passport = Verifier.verify_credential(received_json, public_key=agent_pubkey)
```

## License

Apache-2.0.
