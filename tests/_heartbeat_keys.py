"""Test-only helper: signing keys for heartbeat subjects.

Heartbeat requests must be signed by their subject. Tests that predate signed
heartbeats keep their subject DIDs; this gives each DID a fresh in-memory key
for the test run, and a resolver a validator can use to find it. The keys are
generated in-process and never written anywhere.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from jwcrypto import jwk

from vouch import Signer
from vouch.heartbeat import HeartbeatSession

_SIGNERS: Dict[str, Signer] = {}


def signer_for(did: str) -> Signer:
    if did not in _SIGNERS:
        key = jwk.JWK.generate(kty="OKP", crv="Ed25519")
        _SIGNERS[did] = Signer(private_key=key.export_private(), did=did)
    return _SIGNERS[did]


def signed_session(subject_did: str, **kwargs: Any) -> HeartbeatSession:
    return HeartbeatSession(subject_did=subject_did, signer=signer_for(subject_did), **kwargs)


def resolve(did: str) -> Optional[str]:
    signer = _SIGNERS.get(did)
    return signer.get_public_key_multikey() if signer is not None else None
