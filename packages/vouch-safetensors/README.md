# vouch-safetensors

Embed [Vouch](https://vouch-protocol.com) Credentials in a `.safetensors` file's
existing `__metadata__` header, with zero changes to the safetensors format.

This is deliberately complementary to OpenSSF Model Signing (OMS). OMS proves an
artifact is intact and signed by a key. Vouch adds the agent and delegation
dimension: which principal or pipeline produced the weights, traceable back to an
accountable human. The credential is bound to a SHA-256 of the tensor data
buffer, so any weight tampering breaks verification. Standard loaders (including
Hugging Face) ignore the extra metadata key, so signed files load normally.

## Install

```bash
pip install vouch-safetensors
```

## Sign a model

```python
from vouch import Signer
from vouch_safetensors import sign_safetensors

signer = Signer(private_key=PRIV_JWK, did="did:web:ml.acme.com")
credential = sign_safetensors(signer, "model.safetensors", name="fraud-detector")
# Writes the credential into model.safetensors __metadata__ (in place by default;
# pass out_path=... to write a copy).
```

## Verify a model

```python
from vouch_safetensors import verify_safetensors

ok, passport = verify_safetensors("model.safetensors", public_key=producer_pubkey)
if not ok:
    raise RuntimeError("Unsigned, invalid signature, or weights changed since signing")
```

`verify_safetensors` checks both the signature and that the tensor data still
matches the digest the credential was bound to.

## License

Apache-2.0.
