"""
Shared signing helper for robotics credentials.

Robotics credentials are custom credential types assembled by hand (a robot
identity, a kill switch, a passport), so they are signed with the low-level
`data_integrity.build_proof` primitive, the same path the rest of the SDK uses
for non-intent credentials, rather than the intent-based `Signer.sign`.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from .. import data_integrity


def _raw_priv(signer: Any):
    raw = getattr(signer, "_raw_priv", None)
    if raw is None:
        raise ValueError("signing requires a Signer with an Ed25519 key")
    return raw


def attach_proof(
    credential: Dict[str, Any], signer: Any, *, created: Optional[datetime] = None
) -> Dict[str, Any]:
    """
    Attach an eddsa-jcs-2022 Data Integrity proof to a pre-built credential.

    `created` overrides the proof timestamp, which is used to produce reproducible
    test vectors; it defaults to the current time.
    """
    credential["proof"] = data_integrity.build_proof(
        credential, _raw_priv(signer), signer.verification_method_id(), created=created
    )
    return credential
