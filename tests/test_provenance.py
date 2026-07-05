"""Tests for inference provenance (bind an output to its model and context)."""

import pytest

from vouch import Signer, generate_identity
from vouch.provenance import (
    PROVENANCE_TYPE,
    REASON_CONTEXT_ROOT_MISMATCH,
    REASON_MISSING_BINDING,
    REASON_OUTPUT_MISMATCH,
    REASON_WEIGHTS_MISMATCH,
    ProvenanceError,
    check_replay,
    context_root,
    output_digest,
    sign_inference_provenance,
    verify_context,
    verify_inference_provenance,
    weights_hash,
)

CONTEXT = [
    {"source": "policy://refunds/v4", "text": "Refunds allowed within 30 days."},
    {"source": "order://A-1007", "text": "Delivered 2026-06-20. Amount 120 USD."},
]
OUTPUT = {"action": "approve_refund", "order": "A-1007", "amount": "usd:120"}


def _identity(domain="agent.example.com"):
    kp = generate_identity(domain=domain)
    return kp, Signer(private_key=kp.private_key_jwk, did=kp.did)


class TestHelpers:
    def test_output_digest_deterministic(self):
        assert output_digest(OUTPUT) == output_digest(dict(OUTPUT))

    def test_context_root_order_sensitive(self):
        assert context_root(CONTEXT) != context_root(list(reversed(CONTEXT)))

    def test_context_root_empty_rejected(self):
        with pytest.raises(ProvenanceError):
            context_root([])

    def test_weights_hash_multibase(self):
        assert weights_hash(b"abc").startswith("u")

    def test_to_bytes_type_error(self):
        with pytest.raises(ProvenanceError):
            output_digest(123)


class TestSignAndVerify:
    def test_full_flow(self):
        kp, agent = _identity()
        wh = weights_hash(b"model-weights")
        cred = sign_inference_provenance(
            agent,
            output=OUTPUT,
            model_weights_hash=wh,
            context_chunks=CONTEXT,
            sampler={"seed": 42, "temperature": 0.0},
        )
        assert PROVENANCE_TYPE in cred["type"]
        ok, subject = verify_inference_provenance(cred, kp.public_key_jwk)
        assert ok
        assert subject["provenance"]["modelWeightsHash"] == wh
        assert subject["provenance"]["contextRoot"]["root"] == context_root(CONTEXT)
        assert subject["outputDigest"]["digest"] == output_digest(OUTPUT)

    def test_requires_a_binding(self):
        _, agent = _identity()
        with pytest.raises(ProvenanceError):
            sign_inference_provenance(agent, output=OUTPUT)  # no weights, no context

    def test_weights_only_is_valid(self):
        kp, agent = _identity()
        cred = sign_inference_provenance(
            agent, output=OUTPUT, model_weights_hash=weights_hash(b"m")
        )
        ok, _ = verify_inference_provenance(cred, kp.public_key_jwk)
        assert ok

    def test_context_only_is_valid(self):
        kp, agent = _identity()
        cred = sign_inference_provenance(agent, output=OUTPUT, context_chunks=CONTEXT)
        ok, _ = verify_inference_provenance(cred, kp.public_key_jwk)
        assert ok

    def test_include_output_false_hides_plaintext(self):
        kp, agent = _identity()
        cred = sign_inference_provenance(
            agent, output=OUTPUT, context_chunks=CONTEXT, include_output=False
        )
        ok, subject = verify_inference_provenance(cred, kp.public_key_jwk)
        assert ok and "output" not in subject and subject["outputDigest"]["digest"]

    def test_wrong_key_fails(self):
        _, agent = _identity()
        other_kp, _ = _identity("other.example.com")
        cred = sign_inference_provenance(agent, output=OUTPUT, context_chunks=CONTEXT)
        ok, _ = verify_inference_provenance(cred, other_kp.public_key_jwk)
        assert ok is False

    def test_tamper_breaks_proof(self):
        kp, agent = _identity()
        cred = sign_inference_provenance(agent, output=OUTPUT, context_chunks=CONTEXT)
        cred["credentialSubject"]["output"]["amount"] = "usd:999999"
        ok, _ = verify_inference_provenance(cred, kp.public_key_jwk)
        assert ok is False


class TestContextVerification:
    def _subject(self):
        kp, agent = _identity()
        cred = sign_inference_provenance(agent, output=OUTPUT, context_chunks=CONTEXT)
        _, subject = verify_inference_provenance(cred, kp.public_key_jwk)
        return subject

    def test_same_context_reproduces(self):
        ok, reason = verify_context(CONTEXT, self._subject())
        assert ok and reason is None

    def test_substituted_context_rejected(self):
        forged = [{"source": "policy://refunds/v4", "text": "Refunds any time."}, CONTEXT[1]]
        ok, reason = verify_context(forged, self._subject())
        assert ok is False and reason == REASON_CONTEXT_ROOT_MISMATCH

    def test_reordered_context_rejected(self):
        ok, reason = verify_context(list(reversed(CONTEXT)), self._subject())
        assert ok is False and reason == REASON_CONTEXT_ROOT_MISMATCH

    def test_missing_binding_when_no_context_root(self):
        kp, agent = _identity()
        cred = sign_inference_provenance(
            agent, output=OUTPUT, model_weights_hash=weights_hash(b"m")
        )
        _, subject = verify_inference_provenance(cred, kp.public_key_jwk)
        ok, reason = verify_context(CONTEXT, subject)
        assert ok is False and reason == REASON_MISSING_BINDING


class TestReplay:
    def _subject(self, wh):
        kp, agent = _identity()
        cred = sign_inference_provenance(
            agent, output=OUTPUT, model_weights_hash=wh, context_chunks=CONTEXT
        )
        _, subject = verify_inference_provenance(cred, kp.public_key_jwk)
        return subject

    def test_matching_replay_passes(self):
        wh = weights_hash(b"model")
        assert check_replay(self._subject(wh), output=OUTPUT, model_weights_hash=wh) is None

    def test_output_mismatch(self):
        wh = weights_hash(b"model")
        bad = {"action": "approve_refund", "order": "A-1007", "amount": "usd:999999"}
        assert check_replay(self._subject(wh), output=bad) == REASON_OUTPUT_MISMATCH

    def test_weights_mismatch(self):
        wh = weights_hash(b"model")
        assert (
            check_replay(self._subject(wh), model_weights_hash=weights_hash(b"other"))
            == REASON_WEIGHTS_MISMATCH
        )

    def test_no_checks_supplied_passes(self):
        assert check_replay(self._subject(weights_hash(b"model"))) is None
