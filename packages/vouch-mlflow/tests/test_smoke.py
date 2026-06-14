"""Smoke tests for the vouch-mlflow package."""

import json
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jwcrypto.common import base64url_decode

from vouch import Signer, generate_identity


def _pub(kp):
    return Ed25519PublicKey.from_public_bytes(base64url_decode(json.loads(kp.public_key_jwk)["x"]))


def test_package_exports():
    import vouch_mlflow

    assert vouch_mlflow.sign_model is not None
    assert vouch_mlflow.verify_model is not None
    assert vouch_mlflow.compute_model_digest is not None


def test_sign_and_verify_model(tmp_path):
    from vouch_mlflow import sign_model, verify_model

    model = tmp_path / "model.bin"
    model.write_bytes(b"fake model weights v1")

    kp = generate_identity()
    signer = Signer(private_key=kp.private_key_jwk, did="did:web:ml.acme.com")

    cred = sign_model(signer, str(model), name="fraud-detector")
    assert cred["proof"]["cryptosuite"] == "eddsa-jcs-2022"

    ok, _ = verify_model(str(model), cred, public_key=_pub(kp))
    assert ok is True


def test_tampered_model_fails(tmp_path):
    from vouch_mlflow import sign_model, verify_model

    model = tmp_path / "model.bin"
    model.write_bytes(b"fake model weights v1")

    kp = generate_identity()
    signer = Signer(private_key=kp.private_key_jwk, did="did:web:ml.acme.com")
    cred = sign_model(signer, str(model))

    # Tamper with the weights after signing.
    model.write_bytes(b"poisoned weights")

    ok, _ = verify_model(str(model), cred, public_key=_pub(kp))
    assert ok is False


def test_directory_model(tmp_path):
    from vouch_mlflow import sign_model, verify_model

    d = tmp_path / "model"
    d.mkdir()
    (d / "weights.bin").write_bytes(b"w")
    (d / "config.json").write_bytes(b"{}")

    kp = generate_identity()
    signer = Signer(private_key=kp.private_key_jwk, did="did:web:ml.acme.com")
    cred = sign_model(signer, str(d), name="dir-model")

    ok, _ = verify_model(str(d), cred, public_key=_pub(kp))
    assert ok is True
