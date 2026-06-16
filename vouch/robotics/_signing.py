"""
Shared signing helper for robotics credentials.

Robotics credentials are custom credential types assembled by hand (a robot
identity, a kill switch, a passport), so they are signed with the low-level
`data_integrity.build_proof` primitive, the same path the rest of the SDK uses
for non-intent credentials, rather than the intent-based `Signer.sign_credential`.
"""

from __future__ import annotations

from typing import Any, Dict

from .. import data_integrity


def _raw_priv(signer: Any):
    raw = getattr(signer, "_raw_priv", None)
    if raw is None:
        raise ValueError("signing requires a Signer with an Ed25519 key")
    return raw


def attach_proof(credential: Dict[str, Any], signer: Any) -> Dict[str, Any]:
    """Attach an eddsa-jcs-2022 Data Integrity proof to a pre-built credential."""
    credential["proof"] = data_integrity.build_proof(
        credential, _raw_priv(signer), signer.verification_method_id()
    )
    return credential
