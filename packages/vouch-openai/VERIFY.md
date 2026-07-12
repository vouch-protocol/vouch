# Verifying vouch-openai

A quick end-to-end check that signing and verification work.

```bash
pip install vouch-openai
```

```python
import json
from vouch.keys import generate_identity
from vouch import Signer
from vouch.integrations.openai import sign_tool_call, verify_tool_call

keys = generate_identity(domain="agent.example.com")
signer = Signer(private_key=keys.private_key_jwk, did=keys.did)

# An OpenAI-shaped tool call (name plus JSON arguments).
tool_call = {"function": {"name": "get_weather", "arguments": json.dumps({"city": "Paris"})}}

credential = sign_tool_call(tool_call, signer=signer, publish=False)
print("action:", credential["credentialSubject"]["intent"]["action"])   # get_weather

ok, passport = verify_tool_call(credential, public_key=keys.public_key_jwk)
print("verified:", ok)                                                   # True
print("action:", passport.action)                                        # get_weather
```

Expected output:

```
action: get_weather
verified: True
action: get_weather
```

The smoke tests in `tests/test_smoke.py` cover the dict and object tool-call shapes, the `signed_tool` decorator, and `protect`. Run them with:

```bash
PYTHONPATH=src python -m pytest tests/ -q
```
