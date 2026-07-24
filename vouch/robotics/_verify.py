"""
Shared verification helper for robotics credentials.

Most robotics credentials verify the same way: confirm the credential type,
coerce the public key, and check the eddsa-jcs-2022 Data Integrity proof. This
helper collapses that boilerplate and returns the credentialSubject on success,
or None on any failure (wrong type, unusable key, bad or missing proof).
"""

from __future__ import annotations

from typing import Any, Dict, Optional


def verify_typed_credential(
    credential: Dict[str, Any], public_key: Any, expected_type: str
) -> Optional[Dict[str, Any]]:
    """
    Verify `credential` is of `expected_type` and its proof checks against
    `public_key`. Returns the credentialSubject dict on success, else None.
    """
    from .. import data_integrity
    from ..verifier import _coerce_ed25519_public_key

    if not isinstance(credential, dict):
        return None
    type_field = credential.get("type") or []
    if isinstance(type_field, str):
        type_field = [type_field]
    if expected_type not in type_field:
        return None

    resolved = _coerce_ed25519_public_key(public_key) if public_key is not None else None
    if resolved is None:
        return None
    try:
        if not data_integrity.verify_proof(credential, resolved):
            return None
    except ValueError:
        return None

    subject = credential.get("credentialSubject")
    return subject if isinstance(subject, dict) else None
