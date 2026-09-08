"""AAT <-> Vouch interop adapter.

Verifies an Attenuating Authorization Token chain against its root trust
anchor using the AAT reference implementation, turns the leaf's authority into
Vouch Shield rules, enforces them before a tool call runs, and links the
resulting Vouch credential back to the AAT that authorised the action.

See ``README.md`` for what AAT is and ``DESIGN.md`` for the mapping and its
lossy rows.
"""

from .aat_chain import (
    AatBadSignature,
    AatBrokenChain,
    AatError,
    AatExpired,
    AatMalformedChain,
    AatPopMismatch,
    AatUntrustedRoot,
    AatWidenedScope,
    ChainDocument,
    VerifiedChain,
    load_chain_document,
    verify_chain,
    verify_chain_file,
)
from .aat_to_shield import AatDecision, AatGate, ShieldRules, leaf_to_shield_rules
from .credential_link import (
    AAT_LINK_KEY,
    attach_aat_link,
    build_aat_link,
    extract_aat_link,
    sign_with_aat_link,
)

__all__ = [
    "AatBadSignature",
    "AatBrokenChain",
    "AatError",
    "AatExpired",
    "AatMalformedChain",
    "AatPopMismatch",
    "AatUntrustedRoot",
    "AatWidenedScope",
    "ChainDocument",
    "VerifiedChain",
    "load_chain_document",
    "verify_chain",
    "verify_chain_file",
    "AatDecision",
    "AatGate",
    "ShieldRules",
    "leaf_to_shield_rules",
    "AAT_LINK_KEY",
    "attach_aat_link",
    "build_aat_link",
    "extract_aat_link",
    "sign_with_aat_link",
]
