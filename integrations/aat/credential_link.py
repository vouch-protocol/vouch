"""Record which AAT authorised an action on the Vouch credential it produced.

The link rides inside the credential's existing ``intent`` object. ``intent`` is
validated only for the presence of ``action``, ``target`` and ``resource``
(``vouch/vc.py::_validate_intent``) and is then placed verbatim into
``credentialSubject.intent``, so extra keys survive into the credential and are
covered by the Data Integrity proof.

That means no new required field, no change to the credential format, and no
change to the cryptosuite. A verifier that knows nothing about AAT still
verifies these credentials byte-for-byte as before.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from .aat_chain import VerifiedChain, _parse_rfc3339

__all__ = [
    "AAT_LINK_KEY",
    "build_aat_link",
    "attach_aat_link",
    "extract_aat_link",
    "sign_with_aat_link",
]


#: Key used inside ``intent`` to carry the authorising delegation.
AAT_LINK_KEY = "authorizedBy"


def build_aat_link(chain: VerifiedChain) -> Dict[str, Any]:
    """Build the link object for a verified chain.

    ``jti`` is the leaf -- the token that actually authorised the call.
    ``chainRoot`` identifies the delegation the leaf descends from, so an
    auditor can tell two chains apart that happen to grant the same tool.
    """
    return {
        "scheme": "aat",
        "jti": chain.leaf_jti,
        "chainRoot": chain.root_jti,
        "depth": chain.depth,
    }


def attach_aat_link(intent: Dict[str, Any], chain: VerifiedChain) -> Dict[str, Any]:
    """Return a copy of ``intent`` carrying the AAT link. Never mutates input."""
    enriched = dict(intent)
    enriched[AAT_LINK_KEY] = build_aat_link(chain)
    return enriched


def extract_aat_link(credential: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Pull the AAT link back out of an issued credential, or ``None``."""
    subject = credential.get("credentialSubject")
    if not isinstance(subject, dict):
        return None
    intent = subject.get("intent")
    if not isinstance(intent, dict):
        return None
    link = intent.get(AAT_LINK_KEY)
    return link if isinstance(link, dict) else None


def _seconds_until_leaf_expiry(chain: VerifiedChain, now: Optional[datetime] = None) -> int:
    moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    remaining = (_parse_rfc3339(chain.expires_at) - moment).total_seconds()
    return int(math.floor(remaining))


def sign_with_aat_link(
    signer: Any,
    chain: VerifiedChain,
    *,
    action: str,
    target: str,
    resource: str,
    valid_seconds: Optional[int] = None,
    clamp_to_leaf_expiry: bool = True,
    **sign_kwargs: Any,
) -> Dict[str, Any]:
    """Issue a Vouch credential that records the AAT which authorised the action.

    The credential's validity is clamped so it never outlives the authority that
    justified it: a credential asserting 'this was authorised' should not remain
    valid after that authorisation has expired.

    Args:
        signer: A ``vouch.signer.Signer``.
        chain: The verified chain whose leaf authorised this action.
        action, target, resource: The required Vouch intent fields.
        valid_seconds: Requested validity. Defaults to the Signer's own default.
        clamp_to_leaf_expiry: Cap validity at the leaf's remaining lifetime.
        **sign_kwargs: Passed through to ``Signer.sign`` unchanged.

    Raises:
        ValueError: if the leaf has already expired, so no valid window exists.
    """
    intent = attach_aat_link({"action": action, "target": target, "resource": resource}, chain)

    requested = (
        valid_seconds if valid_seconds is not None else getattr(signer, "default_expiry", None)
    )

    if clamp_to_leaf_expiry:
        remaining = _seconds_until_leaf_expiry(chain)
        if remaining <= 0:
            raise ValueError(
                f"AAT leaf {chain.leaf_jti} expired at {chain.expires_at}; "
                "refusing to issue a credential for expired authority"
            )
        requested = remaining if requested is None else min(int(requested), remaining)

    if requested is not None:
        sign_kwargs["valid_seconds"] = int(requested)

    return signer.sign(intent=intent, **sign_kwargs)
