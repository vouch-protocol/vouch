# vouch-mlflow

Sign [MLflow](https://mlflow.org/) model artifacts with
[Vouch](https://vouch-protocol.com) Credentials, so a registered model carries
verifiable lineage: who registered it, on whose authority, and a content digest
that breaks if the weights are tampered with.

This complements OpenSSF Model Signing. OMS proves an artifact is intact and
signed by a key; Vouch adds the agent and delegation dimension, which principal
or pipeline registered the model, traceable back to an accountable human.

## Install

```bash
pip install vouch-mlflow
```

It has no hard dependency on MLflow. The helpers work on any file or directory
path, so they fit any artifact store.

## Sign at registration time

```python
from vouch import Signer
from vouch_mlflow import sign_model

signer = Signer(private_key=PRIV_JWK, did="did:web:ml.acme.com")

# After mlflow.log_model(...) wrote the model to a local path:
credential = sign_model(signer, "runs:/abc/model_local_path", name="fraud-detector")

# Attach to the run so it travels with the model:
import mlflow, json
mlflow.set_tag("vouch_credential", json.dumps(credential, separators=(",", ":")))
```

## Verify on load

```python
from vouch_mlflow import verify_model

ok, passport = verify_model(model_path, credential, public_key=registrant_pubkey)
if not ok:
    raise RuntimeError("Model signature invalid or weights changed since signing")
```

`verify_model` checks both the signature and that the on-disk content still
matches the digest the credential was bound to.

## License

Apache-2.0.
