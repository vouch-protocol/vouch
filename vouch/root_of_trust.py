"""
Root of Trust for Machine Identity (Vouch Protocol).

Lets Vouch Protocol act as the trust anchor for AI agent and robot identity.
A verifier pins ONE Vouch root, then verifies any agent offline by walking:

    action credential  ->  authority-issued identity credential
        ->  recognized-issuer credential  ->  Vouch root

Three credential types compose this chain, all secured with the same
`eddsa-jcs-2022` Data Integrity proof used elsewhere in Vouch:

  1. Root of Trust credential      self-issued by the root (issuer == subject)
  2. Recognized-issuer credential  issued by the root, naming an issuer that
                                   may attest agent or robot identity
  3. Agent identity credential     issued by a recognized issuer, binding an
                                   agent key to real attributes (issuer != subject)

`vouch.vc.build_vouch_credential` is self-issued today (issuer == subject). This
module adds the authority layer that turns a self-asserted DID into an identity
anchored to a trust root, with no external certificate authority and no central
per-agent lookup. Anyone can stand up their own root and recognize their own
issuers, so the model stays self-sovereign.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional

from jwcrypto.common import base64url_decode

from . import data_integrity, multikey
from .keys import KeyPair, generate_identity
from .signer import Signer
from .vc import PROTOCOL_VERSION, VC_CONTEXT_V2, VC_TYPE, VOUCH_CONTEXT_V1
from .verifier import Verifier, CredentialPassport, _parse_iso8601

__all__ = [
    "ROOT_OF_TRUST_TYPE",
    "RECOGNIZED_ISSUER_TYPE",
    "AGENT_IDENTITY_TYPE",
    "ACTION_ISSUE_AGENT_IDENTITY",
    "ACTION_ISSUE_ROBOT_IDENTITY",
    "IdentityChainResult",
    "generate_did_key_identity",
    "build_root_of_trust",
    "build_recognized_issuer",
    "build_agent_identity",
    "verify_identity_chain",
    "register_recognized_issuer",
]

# Credential type identifiers (the second entry in each `type` array).
ROOT_OF_TRUST_TYPE = "VouchRootOfTrust"
RECOGNIZED_ISSUER_TYPE = "RecognizedIssuerCredential"
AGENT_IDENTITY_TYPE = "AgentIdentityCredential"

# Actions an issuer can be recognized to perform.
ACTION_ISSUE_AGENT_IDENTITY = "issueAgentIdentity"
ACTION_ISSUE_ROBOT_IDENTITY = "issueRobotIdentity"

# The three trust-layer credential types. A single credential must carry exactly
# one of these, otherwise one signed object could be replayed into a different
# slot of the chain (type confusion).
_TRUST_TYPES = frozenset({ROOT_OF_TRUST_TYPE, RECOGNIZED_ISSUER_TYPE, AGENT_IDENTITY_TYPE})

# Default validity windows. Roots are long lived; issuer and identity
# credentials rotate more often. All are overridable per call.
_ROOT_VALID_SECONDS = 10 * 365 * 24 * 3600
_ISSUER_VALID_SECONDS = 365 * 24 * 3600
_IDENTITY_VALID_SECONDS = 365 * 24 * 3600


@dataclass
class IdentityChainResult:
    """Outcome of :func:`verify_identity_chain`.

    Attributes:
      ok: True only if every link verified and anchored to the pinned root.
      reason: Structured failure reason when ``ok`` is False, else None.
      agent_did: The subject DID of the identity credential (the agent).
      issuer_did: The recognized issuer that attested the agent identity.
      root_did: The pinned Vouch root the chain anchored to.
      attributes: The identity attributes bound to the agent.
      action: The verified action passport when an action credential was
        supplied and bound to the agent, else None.
    """

    ok: bool
    reason: Optional[str] = None
    agent_did: Optional[str] = None
    issuer_did: Optional[str] = None
    root_did: Optional[str] = None
    attributes: Optional[Dict[str, Any]] = None
    action: Optional[CredentialPassport] = None


# ---------------------------------------------------------------------------
# Identity helpers
# ---------------------------------------------------------------------------


def generate_did_key_identity() -> KeyPair:
    """Generate a fresh ``did:key`` identity (self-certifying, no hosting).

    Unlike :func:`vouch.keys.generate_identity`, which produces a ``did:web``
    identity tied to a domain, this embeds the public key in the identifier so
    the key resolves offline with no network. Wrap it with
    ``Signer.from_keypair(keys)`` to sign.
    """
    keys = generate_identity()
    pub = json.loads(keys.public_key_jwk)
    raw = base64url_decode(pub["x"])
    keys.did = "did:key:" + multikey.encode_ed25519_public(raw)
    return keys


# ---------------------------------------------------------------------------
# Credential builders
# ---------------------------------------------------------------------------


def build_root_of_trust(
    root_signer: Signer,
    *,
    name: str,
    scope: Optional[List[str]] = None,
    valid_seconds: int = _ROOT_VALID_SECONDS,
    credential_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Self-issue the Vouch Root of Trust credential.

    Issuer and subject are both the root's own DID. Verifiers pin the root DID
    and MAY keep this credential to display what the root anchors. It is not
    required for verification (the pinned DID is the anchor), but it makes the
    root self-describing.

    Args:
      root_signer: Signer holding the root key.
      name: Human-readable name of the root (e.g. "Vouch Machine Identity Root").
      scope: What the root anchors. Defaults to ["ai-agent", "robot"].
      valid_seconds: Validity window. Defaults to ten years.
      credential_id: Optional credential id. Defaults to a fresh UUID URN.
    """
    root_did = root_signer.did
    subject = {
        "id": root_did,
        "vouchVersion": PROTOCOL_VERSION,
        "rootOfTrust": {
            "name": name,
            "scope": scope or ["ai-agent", "robot"],
        },
    }
    credential = _envelope(
        credential_id=credential_id,
        types=[VC_TYPE, ROOT_OF_TRUST_TYPE],
        issuer=root_did,
        subject=subject,
        valid_seconds=valid_seconds,
    )
    return _sign(root_signer, credential)


def build_recognized_issuer(
    root_signer: Signer,
    *,
    issuer_did: str,
    recognized_actions: Optional[List[str]] = None,
    valid_seconds: int = _ISSUER_VALID_SECONDS,
    credential_status: Optional[Dict[str, Any]] = None,
    credential_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Issue a recognized-issuer credential from the root.

    The root attests that ``issuer_did`` may issue the given identity actions.
    ``recognizedIn`` chains back to the root DID so a verifier can trace the
    recognition to the anchor it pinned. The holder staples this credential to
    what it presents, so the verifier needs no central lookup.

    Args:
      root_signer: Signer holding the root key.
      issuer_did: The DID being recognized as an issuer.
      recognized_actions: Actions the issuer may perform. Defaults to
        [ACTION_ISSUE_AGENT_IDENTITY].
      valid_seconds: Validity window. Defaults to one year.
      credential_status: Optional W3C `credentialStatus` entry for revocation
        (e.g. via `vouch.status_list.build_status_list_entry`).
      credential_id: Optional credential id.
    """
    if not issuer_did:
        raise ValueError("issuer_did is required")
    root_did = root_signer.did
    subject = {
        "id": issuer_did,
        "recognizedActions": list(recognized_actions or [ACTION_ISSUE_AGENT_IDENTITY]),
        "recognizedIn": root_did,
    }
    credential = _envelope(
        credential_id=credential_id,
        types=[VC_TYPE, RECOGNIZED_ISSUER_TYPE],
        issuer=root_did,
        subject=subject,
        valid_seconds=valid_seconds,
        credential_status=credential_status,
    )
    return _sign(root_signer, credential)


def build_agent_identity(
    issuer_signer: Signer,
    *,
    subject_did: str,
    attributes: Dict[str, Any],
    valid_seconds: int = _IDENTITY_VALID_SECONDS,
    credential_status: Optional[Dict[str, Any]] = None,
    credential_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Issue an authority-issued identity credential for an agent.

    Here the issuer differs from the subject: a recognized issuer binds the
    agent's DID to real attributes (owner, model, capability class, creation
    time). This is the piece that turns a self-asserted agent DID into an
    identity a third party stands behind.

    Args:
      issuer_signer: Signer of a recognized issuer.
      subject_did: The agent's DID (the subject of this credential).
      attributes: Identity attributes to bind (owner, model, capabilityClass,
        createdAt, and so on).
      valid_seconds: Validity window. Defaults to one year.
      credential_status: Optional W3C `credentialStatus` entry for revocation.
      credential_id: Optional credential id.
    """
    if not subject_did:
        raise ValueError("subject_did is required")
    if not isinstance(attributes, dict) or not attributes:
        raise ValueError("attributes must be a non-empty dict")
    subject = {
        "id": subject_did,
        "identity": dict(attributes),
    }
    credential = _envelope(
        credential_id=credential_id,
        types=[VC_TYPE, AGENT_IDENTITY_TYPE],
        issuer=issuer_signer.did,
        subject=subject,
        valid_seconds=valid_seconds,
        credential_status=credential_status,
    )
    return _sign(issuer_signer, credential)


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def verify_identity_chain(
    identity_credential: Dict[str, Any],
    recognized_issuer_credential: Dict[str, Any],
    *,
    trusted_root: str,
    action_credential: Optional[Dict[str, Any]] = None,
    root_credential: Optional[Dict[str, Any]] = None,
    required_action: str = ACTION_ISSUE_AGENT_IDENTITY,
    allow_did_resolution: bool = False,
    trusted_roots: Optional[Dict[str, str]] = None,
    clock_skew_seconds: int = 30,
    is_revoked: Optional[Callable[[Dict[str, Any]], bool]] = None,
) -> IdentityChainResult:
    """Verify an agent identity against a pinned Vouch root.

    Walks the chain: the recognized-issuer credential must be signed by the
    pinned root and grant ``required_action``; the identity credential must be
    signed by that recognized issuer; the optional action credential must be
    signed by the agent the identity describes. Everything anchors at
    ``trusted_root``, which is the ONE DID the verifier trusts up front.

    With ``did:key`` identities this runs fully offline. Set
    ``allow_did_resolution=True`` to resolve ``did:web`` issuers over the
    network, or pass ``trusted_roots`` (DID -> public JWK JSON) to pin keys.

    Args:
      identity_credential: The authority-issued identity for the agent.
      recognized_issuer_credential: The root's recognition of the issuer.
      trusted_root: The Vouch root DID the verifier pins.
      action_credential: Optional agent action credential to bind to the
        identity (the agent's own signed action).
      root_credential: Optional Root of Trust credential to check for
        self-consistency against ``trusted_root``.
      required_action: Action the issuer must be recognized for. Defaults to
        ``issueAgentIdentity``.
      allow_did_resolution: Allow network ``did:web`` resolution. Defaults False.
      trusted_roots: Optional map of DID -> public JWK JSON for offline pinning.
      clock_skew_seconds: Allowed clock drift for temporal checks.
      is_revoked: Optional callable that returns True if a credential is
        revoked. Called on the recognized-issuer and identity credentials.

    Returns:
      An :class:`IdentityChainResult`.
    """
    if not trusted_root:
        return IdentityChainResult(ok=False, reason="no_trusted_root")

    resolve_opts = dict(
        trusted_roots=trusted_roots,
        allow_did_resolution=allow_did_resolution,
        clock_skew_seconds=clock_skew_seconds,
    )

    # 1. The recognition must be signed by the pinned root.
    ok, reason = _verify_trust_credential(
        recognized_issuer_credential, expected_type=RECOGNIZED_ISSUER_TYPE, **resolve_opts
    )
    if not ok:
        return IdentityChainResult(ok=False, reason=f"recognized_issuer_{reason}")
    if _issuer_of(recognized_issuer_credential) != trusted_root:
        return IdentityChainResult(ok=False, reason="recognized_issuer_not_from_root")

    rec_subject = recognized_issuer_credential.get("credentialSubject")
    if not isinstance(rec_subject, dict):
        return IdentityChainResult(ok=False, reason="recognized_issuer_bad_subject")
    recognized_did = rec_subject.get("id")
    if not recognized_did:
        return IdentityChainResult(ok=False, reason="recognized_issuer_no_subject")
    actions = rec_subject.get("recognizedActions")
    if not isinstance(actions, list) or required_action not in actions:
        return IdentityChainResult(ok=False, reason="issuer_not_recognized_for_action")
    if is_revoked is not None and is_revoked(recognized_issuer_credential):
        return IdentityChainResult(ok=False, reason="recognized_issuer_revoked")

    # 2. The identity must be signed by the recognized issuer.
    ok, reason = _verify_trust_credential(
        identity_credential, expected_type=AGENT_IDENTITY_TYPE, **resolve_opts
    )
    if not ok:
        return IdentityChainResult(ok=False, reason=f"identity_{reason}")
    if _issuer_of(identity_credential) != recognized_did:
        return IdentityChainResult(ok=False, reason="identity_not_from_recognized_issuer")
    if is_revoked is not None and is_revoked(identity_credential):
        return IdentityChainResult(ok=False, reason="identity_revoked")

    id_subject = identity_credential.get("credentialSubject")
    if not isinstance(id_subject, dict):
        return IdentityChainResult(ok=False, reason="identity_bad_subject")
    agent_did = id_subject.get("id")
    if not agent_did:
        return IdentityChainResult(ok=False, reason="identity_no_subject")
    attributes = id_subject.get("identity")

    # 3. Optional: confirm the root credential is genuinely self-issued.
    if root_credential is not None:
        ok, reason = _verify_trust_credential(
            root_credential, expected_type=ROOT_OF_TRUST_TYPE, **resolve_opts
        )
        if not ok:
            return IdentityChainResult(ok=False, reason=f"root_{reason}")
        root_sub = root_credential.get("credentialSubject")
        if not isinstance(root_sub, dict):
            return IdentityChainResult(ok=False, reason="root_bad_subject")
        if _issuer_of(root_credential) != trusted_root or root_sub.get("id") != trusted_root:
            return IdentityChainResult(ok=False, reason="root_not_self_issued")

    # 4. Optional: bind the agent's own action to this identity.
    action_passport: Optional[CredentialPassport] = None
    if action_credential is not None:
        verifier = Verifier(
            trusted_roots=trusted_roots or None,
            allow_did_resolution=allow_did_resolution,
            clock_skew_seconds=clock_skew_seconds,
        )
        ok, passport = verifier.check_vouch_credential(action_credential)
        if not ok or passport is None:
            return IdentityChainResult(ok=False, reason="action_proof_invalid")
        if passport.iss != agent_did:
            return IdentityChainResult(ok=False, reason="action_not_from_agent")
        action_passport = passport

    return IdentityChainResult(
        ok=True,
        agent_did=agent_did,
        issuer_did=recognized_did,
        root_did=trusted_root,
        attributes=attributes,
        action=action_passport,
    )


def register_recognized_issuer(registry: Any, recognized_issuer_credential: Dict[str, Any]) -> str:
    """Consume a recognized-issuer credential into a Vouch Shield TrustRegistry.

    The caller should verify the credential first (via
    :func:`verify_identity_chain` or :func:`_verify_trust_credential`). This
    adds the recognized issuer DID to the registry's trusted set and returns it.
    """
    subject = recognized_issuer_credential.get("credentialSubject") or {}
    issuer_did = subject.get("id")
    if not issuer_did:
        raise ValueError("recognized-issuer credential has no subject id")
    registry.trust(issuer_did)
    return issuer_did


# ---------------------------------------------------------------------------
# Module-private helpers
# ---------------------------------------------------------------------------


def _envelope(
    *,
    credential_id: Optional[str],
    types: List[str],
    issuer: str,
    subject: Dict[str, Any],
    valid_seconds: int,
    credential_status: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build the unsigned VC envelope shared by all three credential types."""
    issued_at = datetime.now(timezone.utc)
    expires_at = issued_at + timedelta(seconds=valid_seconds)
    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "id": credential_id or f"urn:uuid:{uuid.uuid4()}",
        "type": types,
        "issuer": issuer,
        "validFrom": _iso(issued_at),
        "validUntil": _iso(expires_at),
        "credentialSubject": subject,
    }
    if credential_status is not None:
        credential["credentialStatus"] = credential_status
    return credential


def _sign(signer: Signer, credential: Dict[str, Any]) -> Dict[str, Any]:
    """Attach an eddsa-jcs-2022 Data Integrity proof using ``signer``'s key.

    Handles both in-process signers (raw Ed25519 key) and backend signers (a
    sign-callback whose key lives outside the process).
    """
    if getattr(signer, "_raw_priv", None) is not None:
        key = signer._raw_priv
    elif getattr(signer, "_sign_func", None) is not None:
        key = signer._sign_func
    else:
        raise ValueError("signer cannot sign: no private key or sign callback available")
    credential = dict(credential)
    credential["proof"] = data_integrity.build_proof(
        credential, key, signer.verification_method_id()
    )
    return credential


def _verify_trust_credential(
    credential: Dict[str, Any],
    *,
    expected_type: str,
    trusted_roots: Optional[Dict[str, str]],
    allow_did_resolution: bool,
    clock_skew_seconds: int,
) -> tuple[bool, Optional[str]]:
    """Verify a trust-layer credential (root, recognized-issuer, or identity).

    Unlike :meth:`Verifier.verify`, this does not require an ``intent.resource``
    (those credentials carry claims, not an agent action). It checks the proof,
    the proof purpose, that the verification method belongs to the issuer, the
    credential type, and the validity window. Returns (ok, reason).
    """
    if not isinstance(credential, dict):
        return False, "not_a_credential"

    types = credential.get("type")
    if not isinstance(types, list) or expected_type not in types:
        return False, "wrong_type"
    # Exactly one trust-layer type, so the credential cannot double as another
    # link in the chain.
    if len(_TRUST_TYPES.intersection(types)) != 1:
        return False, "ambiguous_type"

    issuer = _issuer_of(credential)
    if not issuer:
        return False, "no_issuer"

    proof = credential.get("proof")
    if not isinstance(proof, dict):
        return False, "no_proof"
    if proof.get("proofPurpose") != "assertionMethod":
        return False, "bad_proof_purpose"
    vm = proof.get("verificationMethod")
    if not isinstance(vm, str) or not vm or vm.split("#", 1)[0] != issuer:
        return False, "vm_mismatch"

    public_key = _resolve_key(issuer, vm, trusted_roots, allow_did_resolution)
    if public_key is None:
        return False, "unresolved_key"

    try:
        if not data_integrity.verify_proof(credential, public_key):
            return False, "proof_invalid"
    except ValueError:
        return False, "proof_malformed"

    now = datetime.now(timezone.utc)
    valid_from = _parse_iso8601(credential.get("validFrom"))
    valid_until = _parse_iso8601(credential.get("validUntil"))
    if valid_from is None or valid_until is None:
        return False, "no_validity_window"
    if (now - valid_until).total_seconds() > clock_skew_seconds:
        return False, "expired"
    if (valid_from - now).total_seconds() > clock_skew_seconds:
        return False, "not_yet_valid"

    return True, None


def _resolve_key(
    did: str,
    vm_id: Optional[str],
    trusted_roots: Optional[Dict[str, str]],
    allow_did_resolution: bool,
):
    """Resolve an issuer's Ed25519 public key, reusing the Verifier's resolver.

    ``did:key`` resolves offline from the identifier; ``did:web`` needs
    ``allow_did_resolution``; pinned keys come from ``trusted_roots``.
    """
    verifier = Verifier(
        trusted_roots=trusted_roots or None,
        allow_did_resolution=allow_did_resolution,
    )
    return verifier._resolve_credential_public_key(did, vm_id)


def _issuer_of(credential: Dict[str, Any]) -> Optional[str]:
    """Return the issuer DID, tolerating the list form used by multi-issuer VCs."""
    issuer = credential.get("issuer")
    if isinstance(issuer, list):
        return issuer[0] if issuer else None
    return issuer if isinstance(issuer, str) else None


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
