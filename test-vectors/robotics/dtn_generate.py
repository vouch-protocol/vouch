#!/usr/bin/env python3
"""
Generate the disconnected-edge (DTN) robotics interop vector (PAD-106 to PAD-124).

Deterministic: fixed signer seed, fixed nonces, and a fixed proof `created` (proofs
are re-attached through `attach_proof(..., created=...)` so the output is
reproducible). Other languages VERIFY these Python-signed credentials, proving a
disconnected-edge credential signed in one language verifies in every other. The
sparse-Merkle revocation accumulator root is pinned so other languages reproduce it
byte-for-byte.

Run:  python test-vectors/robotics/dtn_generate.py
"""

import base64
import json
import math
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from vouch import Signer
from vouch.robotics._signing import attach_proof
from vouch.robotics import (
    SparseMerkleTree,
    bind_credential_to_bundle,
    build_beam_presence,
    build_conditional_revocation,
    build_distress_attestation,
    build_freshness_token,
    build_geoscoped_grant,
    build_integrity_risk_attestation,
    build_non_revocation_proof,
    build_perception_claim,
    build_presence_attestation,
    build_range_observation,
    build_revocation_accumulator_root,
    build_time_quality_attestation,
    build_trust_state_update,
)

SEED = bytes(range(32))
DID = "did:web:issuer.example"
CREATED = "2026-07-19T12:00:00Z"


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def det(cred, signer):
    """Re-attach the proof with a fixed `created` so the credential is reproducible."""
    return attach_proof(dict(cred), signer, created=__import__("datetime").datetime(
        2026, 7, 19, 12, 0, 0, tzinfo=__import__("datetime").timezone.utc))


def main():
    sk = Ed25519PrivateKey.from_private_bytes(SEED)
    pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    priv_jwk = json.dumps({"kty": "OKP", "crv": "Ed25519", "d": b64u(SEED), "x": b64u(pub)})
    s = Signer(private_key=priv_jwk, did=DID)

    entries = []

    def add(name, cred, verify):
        entries.append({"name": name, "credential": det(cred, s), "verify": verify})

    add("freshness_token",
        build_freshness_token(s, subject_did="did:web:node", epoch=100, nonce="fx"),
        {"kind": "freshness_token", "verifierEpoch": 100, "tier": "critical"})

    add("presence",
        build_presence_attestation(s, peer_did="did:web:peer", nonce="n1",
                                   claimed_position=[100.0, 0.0, 0.0], measured_range_m=100.4, tolerance_m=1.0),
        {"kind": "presence", "verifierPosition": [0.0, 0.0, 0.0], "expectedNonce": "n1"})

    add("geoscope",
        build_geoscoped_grant(s, holder_did="did:web:rover", grant_id="g1",
                              region={"type": "sphere", "centerM": [0.0, 0.0, 0.0], "radiusM": 50.0}),
        {"kind": "geoscope", "position": [10.0, 10.0, 0.0]})

    add("conditional_revocation",
        build_conditional_revocation(s, target_credential_id="cred-1", subject_did="did:web:node", deadline_epoch=100),
        {"kind": "conditional_revocation"})

    add("range_observation",
        build_range_observation(s, target_did="did:web:t", observer_position=[1.0, 2.0, 3.0],
                                measured_range_m=10.0, nonce="n", epoch=1),
        {"kind": "range_observation"})

    add("beam_presence",
        build_beam_presence(s, peer_did="did:web:peer", nonce="n", pointing=[1.0, 0.0, 0.0],
                            beamwidth_rad=math.radians(10)),
        {"kind": "beam_presence", "peerDirection": [1.0, 0.02, 0.0], "expectedNonce": "n"})

    add("distress",
        build_distress_attestation(s, target_did="did:web:bad", reason="out_of_envelope",
                                   evidence_ref="frame:abc", epoch=5),
        {"kind": "distress"})

    add("trust_state_update",
        build_trust_state_update(s, scope="rev", change={"op": "revoke", "did": "did:web:x"},
                                 epoch=10, failure_domain="orbit-A"),
        {"kind": "trust_state_update"})

    add("time_quality",
        build_time_quality_attestation(s, source_class="gnss", since_discipline_s=5.0, uncertainty_s=0.5),
        {"kind": "time_quality", "tier": "critical"})

    add("integrity_risk",
        build_integrity_risk_attestation(s, cumulative_risk=0.12, metrics={"doseRad": 180, "seu": 0}),
        {"kind": "integrity_risk"})

    add("perception_claim",
        build_perception_claim(s, scene_nonce="scene-1", feature="obstacle-x", value=10.0, epoch=7),
        {"kind": "perception_claim"})

    add("bundle",
        bind_credential_to_bundle(s, bundle_id="b-1", payload_hash="sha256:abc", intent={"action": "deliver"}),
        {"kind": "bundle", "payloadHash": "sha256:abc"})

    # Sparse-Merkle revocation accumulator: pin the root and two proofs.
    tree = SparseMerkleTree()
    for cid in ["cred-a", "cred-b", "cred-c"]:
        tree.revoke(cid)
    smt = {
        "revokedIds": ["cred-a", "cred-b", "cred-c"],
        "rootMultibase": tree.root_multibase(),
        "signedRoot": det(build_revocation_accumulator_root(s, tree=tree, epoch=42), s),
        "nonRevokedId": "cred-z",
        "nonRevokedProof": build_non_revocation_proof(tree=tree, credential_id="cred-z"),
        "revokedId": "cred-a",
        "revokedProof": build_non_revocation_proof(tree=tree, credential_id="cred-a"),
    }

    doc = {
        "description": (
            "Disconnected-edge (DTN) robotics interop vector, PAD-106 to PAD-124. "
            "Other languages verify these Python-signed credentials and reproduce the "
            "sparse-Merkle revocation root byte-for-byte."
        ),
        "issuerDid": DID,
        "issuerPublicKeyRawB64Url": b64u(pub),
        "created": CREATED,
        "credentials": entries,
        "accumulator": smt,
    }

    out = os.path.join(os.path.dirname(__file__), "dtn_vector.json")
    with open(out, "w") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"wrote {out} with {len(entries)} credentials + accumulator")


if __name__ == "__main__":
    main()
