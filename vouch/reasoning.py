"""
Reasoned Action Proofs: bind an agent's justification to the action it takes.

Vouch answers *who* acted and *under what authority*. A standard credential says
nothing about *why* the agent did it. After an incident, "was this a bug or
deliberate misuse?" is unanswerable, which blocks liability, insurance, and
regulatory audit.

This module adds the missing "why" layer without pretending to read the agent's
mind. Before executing, an agent states a structured **justification**: the intent
plus a set of **evidence anchors**, each a claim tied to a real artifact (a
delegation link, a user message, a retrieved document) by that artifact's hash.
The justification is committed by digest, optionally deposited with a neutral
**escrow** that timestamps it, and the executed action credential carries the
commitment. Three properties then hold:

  - No fabrication. Each reason names an artifact; a verifier re-resolves the
    artifact and checks its hash. "The user told me to" fails if no such message
    exists or its hash does not match.
  - No post-hoc rewrite. The action credential carries the justification digest.
    A justification presented later must recompute to that same digest.
  - Committed before execution. When escrow is used, the receipt's deposit time
    must not be after the action's execution time, so reasoning cannot be
    invented after seeing the outcome.

This does not make deception impossible: a capable deceiver can still write a
plausible reason anchored to real evidence. What it does is put the agent on the
record, so a false justification is provable perjury with downstream cost. It is
the on-protocol form of prior-art disclosures PAD-017 (evidence-anchored
reasoning, sealed-verdict escrow) and PAD-071 (commit-before-outcome), and it
composes with them and with the rest of Vouch: everything here is an ordinary
``eddsa-jcs-2022`` Verifiable Credential and verifies across the language SDKs.
"""

from __future__ import annotations

import base64
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import data_integrity
from .jcs import canonicalize

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"

REASONED_ACTION_TYPE = "ReasonedActionCredential"
ESCROW_RECEIPT_TYPE = "JustificationEscrowReceipt"

JUSTIFICATION_ALGORITHM = "sha-256-jcs"

# Structured verification reasons (stable strings, mirrored by the SDKs).
REASON_INVALID_PROOF = "invalid_proof"
REASON_NOT_REASONED_ACTION = "not_reasoned_action"
REASON_MISSING_COMMITMENT = "missing_commitment"
REASON_MISSING_ESCROW = "missing_escrow"
REASON_ESCROW_INVALID = "escrow_receipt_invalid"
REASON_ESCROW_DIGEST_MISMATCH = "escrow_digest_mismatch"
REASON_ESCROW_AFTER_EXECUTION = "escrow_after_execution"
REASON_JUSTIFICATION_DIGEST_MISMATCH = "justification_digest_mismatch"
REASON_EVIDENCE_UNRESOLVED = "evidence_unresolved"
REASON_EVIDENCE_HASH_MISMATCH = "evidence_hash_mismatch"
REASON_UNANCHORED_CLAIM = "unanchored_claim"


class ReasonedActionError(Exception):
    """Raised on malformed reasoned-action input."""


# ---------------------------------------------------------------------------
# Low-level helpers (kept local so the module stands alone, matching
# vouch.accountability)
# ---------------------------------------------------------------------------


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(s: str) -> datetime:
    try:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError) as exc:
        raise ReasonedActionError(f"malformed timestamp: {s!r}") from exc


def _mb64(b: bytes) -> str:
    return "u" + base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _raw_priv(signer: Any):
    raw = getattr(signer, "_raw_priv", None)
    if raw is None:
        raise ReasonedActionError("signing requires a Signer with an Ed25519 key")
    return raw


def _attach_proof(credential: Dict[str, Any], signer: Any) -> Dict[str, Any]:
    credential["proof"] = data_integrity.build_proof(
        credential, _raw_priv(signer), signer.verification_method_id()
    )
    return credential


def _artifact_bytes(artifact: Any) -> bytes:
    """Canonical bytes of an evidence artifact, for content addressing."""
    if isinstance(artifact, (bytes, bytearray)):
        return bytes(artifact)
    if isinstance(artifact, str):
        return artifact.encode("utf-8")
    if isinstance(artifact, dict):
        return canonicalize(artifact)
    raise ReasonedActionError("evidence artifact must be a dict, str, or bytes")


def artifact_digest(artifact: Any) -> str:
    """Multibase SHA-256 of an evidence artifact."""
    return _mb64(hashlib.sha256(_artifact_bytes(artifact)).digest())


# ---------------------------------------------------------------------------
# Justification: the structured "why", anchored to real evidence
# ---------------------------------------------------------------------------


def evidence_anchor(
    claim: str,
    ref: str,
    *,
    evidence: Any = None,
    evidence_hash: Optional[str] = None,
    anchor_type: str = "artifact",
) -> Dict[str, Any]:
    """
    Build one evidence anchor: a claim tied to a verifiable artifact.

    Args:
        claim: The assertion the agent is making (e.g. "user requested cleanup").
        ref: A resolvable reference to the artifact (a URN, a URL, a message id,
            a delegation-chain locator) the verifier will re-fetch.
        evidence: The artifact itself; its hash is computed and stored. Supply
            this OR ``evidence_hash``.
        evidence_hash: A precomputed multibase SHA-256 of the artifact, when the
            artifact is large or already content-addressed.
        anchor_type: Free-form label (``artifact``, ``user_message``,
            ``delegation``, ``retrieval``, ``policy``, ...).

    Returns:
        An anchor dict with ``type``, ``claim``, ``ref``, and ``evidenceHash``.
    """
    if not claim or not ref:
        raise ReasonedActionError("an evidence anchor needs a claim and a ref")
    if evidence_hash is None:
        if evidence is None:
            raise ReasonedActionError("supply evidence or evidence_hash for the anchor")
        evidence_hash = artifact_digest(evidence)
    return {"type": anchor_type, "claim": claim, "ref": ref, "evidenceHash": evidence_hash}


def build_justification(
    intent: Dict[str, Any],
    anchors: List[Dict[str, Any]],
    *,
    commitment_level: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Assemble a justification: the intent plus its evidence anchors.

    Args:
        intent: The action being justified. Must carry at least ``action`` and
            ``target`` (``resource`` recommended, matching the action credential).
        anchors: Evidence anchors from :func:`evidence_anchor`. At least one is
            required; an empty set is an unanchored justification, which
            :func:`verify_justification` rejects.
        commitment_level: Optional impact level (0..4, per PAD-017 adaptive
            commitment depth) recorded alongside the justification.
    """
    if not isinstance(intent, dict) or not intent.get("action") or not intent.get("target"):
        raise ReasonedActionError("intent must be a dict with at least action and target")
    if not anchors:
        raise ReasonedActionError("a justification needs at least one evidence anchor")
    justification: Dict[str, Any] = {"intent": dict(intent), "evidenceAnchors": list(anchors)}
    if commitment_level is not None:
        justification["commitmentLevel"] = int(commitment_level)
    return justification


def justification_digest(justification: Dict[str, Any]) -> str:
    """Multibase SHA-256 over the JCS-canonical justification."""
    if not isinstance(justification, dict):
        raise ReasonedActionError("justification must be a JSON object")
    return _mb64(hashlib.sha256(canonicalize(justification)).digest())


# ---------------------------------------------------------------------------
# Escrow: a neutral timestamp that fixes the commitment before execution
# ---------------------------------------------------------------------------


def build_escrow_receipt(
    escrow_signer: Any,
    *,
    agent_did: str,
    committed_digest: str,
    deposited_at: Optional[datetime] = None,
    credential_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Issue a signed ``JustificationEscrowReceipt`` fixing a commitment in time.

    The escrow sees only the justification *digest*, never the plaintext, so an
    agent's reasoning stays private while its commitment time is witnessed by a
    party distinct from the agent. In production this is a hosted escrow service or
    a transparency log; :class:`LocalEscrow` is the reference local stand-in.
    """
    deposited = (deposited_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    receipt: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", ESCROW_RECEIPT_TYPE],
        "id": credential_id or f"urn:uuid:{uuid.uuid4()}",
        "issuer": escrow_signer.get_did(),
        "validFrom": _iso(deposited),
        "credentialSubject": {
            "agent": agent_did,
            "committedDigest": committed_digest,
            "depositedAt": _iso(deposited),
        },
    }
    return _attach_proof(receipt, escrow_signer)


def verify_escrow_receipt(
    receipt: Dict[str, Any],
    escrow_public_key: Any,
) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """Verify an escrow receipt's proof and structure. Returns (ok, subject)."""
    from vouch.verifier import _coerce_ed25519_public_key

    if ESCROW_RECEIPT_TYPE not in _type_list(receipt):
        return False, None
    resolved = (
        _coerce_ed25519_public_key(escrow_public_key) if escrow_public_key is not None else None
    )
    if resolved is None:
        return False, None
    try:
        if not data_integrity.verify_proof(receipt, resolved):
            return False, None
    except ValueError:
        return False, None
    subject = receipt.get("credentialSubject") or {}
    if not subject.get("committedDigest") or not subject.get("depositedAt"):
        return False, None
    return True, subject


class LocalEscrow:
    """
    Reference local escrow: wraps an escrow Signer and issues receipts.

    Suitable for tests, demos, and self-hosted single-party deployments. A hosted,
    multi-party, retention-managed escrow is a managed-deployment concern; the
    receipt format it issues is identical, so callers verify both the same way.
    """

    def __init__(self, escrow_signer: Any):
        self._signer = escrow_signer

    @property
    def did(self) -> str:
        return self._signer.get_did()

    def deposit(
        self,
        *,
        agent_did: str,
        committed_digest: str,
        deposited_at: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        return build_escrow_receipt(
            self._signer,
            agent_did=agent_did,
            committed_digest=committed_digest,
            deposited_at=deposited_at,
        )


# ---------------------------------------------------------------------------
# Reasoned action credential: the executed action, carrying its commitment
# ---------------------------------------------------------------------------


def sign_reasoned_action(
    signer: Any,
    *,
    intent: Dict[str, Any],
    justification: Dict[str, Any],
    escrow_receipt: Optional[Dict[str, Any]] = None,
    include_reasoning: bool = True,
    valid_from: Optional[datetime] = None,
    credential_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Issue a ``ReasonedActionCredential``: the action bound to its justification.

    The credential subject carries the ``intent`` and a ``justification`` block
    holding the commitment digest, the optional commitment level, the optional
    escrow receipt, and (unless ``include_reasoning`` is False) the evidence
    anchors themselves. The digest always covers the full justification, so
    withholding the anchors for privacy does not weaken the binding: they can be
    revealed later and checked against the digest.

    Args:
        signer: The acting agent's ``Signer``.
        intent: The action taken. Should match ``justification["intent"]``.
        justification: The object from :func:`build_justification`.
        escrow_receipt: A receipt from :func:`build_escrow_receipt`, proving the
            commitment was fixed before this action. Recommended for consequential
            actions; verifiers can require it.
        include_reasoning: If False, publish only the digest (private reasoning),
            revealing anchors out of band at audit time.
        valid_from: Execution time (defaults to now, UTC). Must not precede the
            escrow deposit when a receipt is attached.
        credential_id: Optional credential id (defaults to a ``urn:uuid``).
    """
    if not isinstance(intent, dict) or not intent.get("action") or not intent.get("target"):
        raise ReasonedActionError("intent must be a dict with at least action and target")

    digest = justification_digest(justification)
    executed = (valid_from or datetime.now(timezone.utc)).astimezone(timezone.utc)

    jblock: Dict[str, Any] = {
        "commitment": {"algorithm": JUSTIFICATION_ALGORITHM, "digest": digest},
    }
    if "commitmentLevel" in justification:
        jblock["commitmentLevel"] = justification["commitmentLevel"]
    if escrow_receipt is not None:
        jblock["escrowReceipt"] = escrow_receipt
    if include_reasoning:
        jblock["evidenceAnchors"] = list(justification.get("evidenceAnchors", []))

    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", REASONED_ACTION_TYPE],
        "id": credential_id or f"urn:uuid:{uuid.uuid4()}",
        "issuer": signer.get_did(),
        "validFrom": _iso(executed),
        "credentialSubject": {"intent": dict(intent), "justification": jblock},
    }
    return _attach_proof(credential, signer)


def check_reasoned_action(
    credential: Dict[str, Any],
    public_key: Any,
    *,
    escrow_public_key: Any = None,
    require_escrow: bool = False,
) -> Optional[str]:
    """
    Verify a reasoned-action credential; return None on success or a structured
    reason string on failure (one of the ``REASON_*`` constants).

    Checks the agent's proof, the presence of a commitment, and, when an escrow
    receipt is attached, the receipt's own proof, that its committed digest equals
    the credential's commitment, and that the deposit time is not after execution
    (commit-before-execute). Set ``require_escrow`` to reject actions with no
    escrow receipt.

    This does not resolve evidence anchors; that needs the artifacts and is done by
    :func:`verify_justification` with a resolver.
    """
    from vouch.verifier import _coerce_ed25519_public_key

    if REASONED_ACTION_TYPE not in _type_list(credential):
        return REASON_NOT_REASONED_ACTION

    resolved = _coerce_ed25519_public_key(public_key) if public_key is not None else None
    if resolved is None:
        return REASON_INVALID_PROOF
    try:
        if not data_integrity.verify_proof(credential, resolved):
            return REASON_INVALID_PROOF
    except ValueError:
        return REASON_INVALID_PROOF

    subject = credential.get("credentialSubject") or {}
    jblock = subject.get("justification") or {}
    commitment = jblock.get("commitment") or {}
    if not commitment.get("digest"):
        return REASON_MISSING_COMMITMENT

    receipt = jblock.get("escrowReceipt")
    if receipt is None:
        return REASON_MISSING_ESCROW if require_escrow else None

    ok, rsubject = verify_escrow_receipt(receipt, escrow_public_key)
    if not ok:
        return REASON_ESCROW_INVALID
    if rsubject.get("committedDigest") != commitment.get("digest"):
        return REASON_ESCROW_DIGEST_MISMATCH

    deposited = _parse_iso(rsubject["depositedAt"])
    executed = _parse_iso(credential.get("validFrom", ""))
    if deposited > executed:
        return REASON_ESCROW_AFTER_EXECUTION
    return None


def verify_reasoned_action(
    credential: Dict[str, Any],
    public_key: Any,
    *,
    escrow_public_key: Any = None,
    require_escrow: bool = False,
) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """
    Convenience wrapper over :func:`check_reasoned_action` returning
    ``(ok, credentialSubject)`` in the style of the rest of the SDK.
    """
    reason = check_reasoned_action(
        credential,
        public_key,
        escrow_public_key=escrow_public_key,
        require_escrow=require_escrow,
    )
    if reason is not None:
        return False, None
    return True, credential.get("credentialSubject") or {}


def verify_justification(
    presented_justification: Dict[str, Any],
    credential_subject: Dict[str, Any],
    *,
    resolver: Callable[[str], Any],
) -> Tuple[bool, Optional[str]]:
    """
    Check a revealed justification against a verified credential's commitment.

    Confirms (1) the presented justification recomputes to the committed digest
    (no post-hoc rewrite) and (2) every evidence anchor resolves via ``resolver``
    and its artifact hashes to the recorded value (no fabricated evidence).

    Args:
        presented_justification: The full justification the agent now discloses.
        credential_subject: The ``credentialSubject`` returned by
            :func:`verify_reasoned_action`.
        resolver: A callable mapping an anchor ``ref`` to its artifact (dict, str,
            or bytes), or None if it cannot be resolved.

    Returns:
        ``(True, None)`` on success, else ``(False, reason)``.
    """
    commitment = (credential_subject.get("justification") or {}).get("commitment") or {}
    committed = commitment.get("digest")
    if not committed:
        return False, REASON_MISSING_COMMITMENT

    if justification_digest(presented_justification) != committed:
        return False, REASON_JUSTIFICATION_DIGEST_MISMATCH

    anchors = presented_justification.get("evidenceAnchors") or []
    if not anchors:
        return False, REASON_UNANCHORED_CLAIM
    for anchor in anchors:
        ref = anchor.get("ref")
        artifact = resolver(ref) if ref is not None else None
        if artifact is None:
            return False, REASON_EVIDENCE_UNRESOLVED
        try:
            if artifact_digest(artifact) != anchor.get("evidenceHash"):
                return False, REASON_EVIDENCE_HASH_MISMATCH
        except ReasonedActionError:
            return False, REASON_EVIDENCE_HASH_MISMATCH
    return True, None


def _type_list(credential: Dict[str, Any]) -> list:
    t = credential.get("type") or []
    return [t] if isinstance(t, str) else list(t)


__all__ = [
    "ReasonedActionError",
    "REASONED_ACTION_TYPE",
    "ESCROW_RECEIPT_TYPE",
    "JUSTIFICATION_ALGORITHM",
    "artifact_digest",
    "evidence_anchor",
    "build_justification",
    "justification_digest",
    "build_escrow_receipt",
    "verify_escrow_receipt",
    "LocalEscrow",
    "sign_reasoned_action",
    "check_reasoned_action",
    "verify_reasoned_action",
    "verify_justification",
]
