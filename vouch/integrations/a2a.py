"""
Vouch Protocol A2A (Agent2Agent) Integration.

Bind an A2A Agent Card to a Vouch identity so two agents can establish trust
before they collaborate. The signed card carries a Vouch Credential
(eddsa-jcs-2022 Data Integrity proof) that proves which principal operates the
agent, optionally through a delegation chain to an accountable human or org.

A2A standardized how agents discover and talk to each other via Agent Cards.
It does not, on its own, prove who stands behind an agent. This module adds
that proof as an optional, additive field on the card, so a verifier can refuse
an unsigned or impostor peer.
"""

from __future__ import annotations

import copy
from typing import Any, Dict, Optional, Tuple

from vouch import Signer, Verifier

# The additive field carrying the Vouch Credential on an Agent Card.
VOUCH_CARD_FIELD = "vouchCredential"


def sign_agent_card(
    signer: Signer,
    card: Dict[str, Any],
    *,
    parent_credential: Optional[Dict[str, Any]] = None,
    hybrid: bool = False,
    valid_seconds: Optional[int] = None,
) -> Dict[str, Any]:
    """Return a copy of an A2A Agent Card with a Vouch Credential attached.

    The credential binds to the card's ``url`` (the stable agent identity), and
    when ``parent_credential`` is supplied, extends a delegation chain so the
    agent's authority traces back to an accountable principal.

    Args:
        signer: The operating agent or principal's Signer.
        card: An A2A Agent Card as a dict (name, url, version, capabilities, ...).
        parent_credential: Optional parent credential to extend (delegation).
        hybrid: Issue under the post-quantum hybrid profile when True.
        valid_seconds: Optional validity window override.

    Returns:
        A new card dict with a ``vouchCredential`` field. The input is not mutated.
    """
    url = card.get("url") or card.get("name") or "a2a:agent"
    intent = {"action": "operate", "target": url, "resource": "a2a:agent-card"}
    issue = signer.sign_hybrid if hybrid else signer.sign
    credential = issue(
        intent=intent,
        parent_credential=parent_credential,
        valid_seconds=valid_seconds,
    )
    signed = copy.deepcopy(card)
    signed[VOUCH_CARD_FIELD] = credential
    return signed


def verify_agent_card(
    card: Dict[str, Any],
    public_key: Optional[Any] = None,
) -> Tuple[bool, Optional[Any]]:
    """Verify the Vouch Credential embedded in an A2A Agent Card.

    Args:
        card: An Agent Card that may carry a ``vouchCredential`` field.
        public_key: The operating agent's public key (Ed25519PublicKey or
            Multikey string). If None, only structural and temporal checks run.

    Returns:
        An ``(is_valid, passport)`` tuple. Returns ``(False, None)`` when no
        credential is present.
    """
    credential = card.get(VOUCH_CARD_FIELD)
    if not credential:
        return False, None
    return Verifier.verify(credential, public_key=public_key)
