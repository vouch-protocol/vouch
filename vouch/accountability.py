"""
Outcome-evidence credentials: commit-before-outcome verdicts and settlement.

Vouch answers "is this authentically agent X, acting under this authority?" It
does not, on its own, answer "does agent X have a verifiable record of being
right?" The existing reputation engine (`vouch.reputation`) keeps a score, but
that score is asserted by whoever runs the engine and can be moved at will. A
record that an agent can edit is not evidence.

This module adds the missing primitive: a verdict, prediction, or recommendation
that an issuer **commits and signs before the outcome is known**, plus a separate
**settlement attestation** that binds the observed outcome back to that
commitment. Two properties make the record non-gameable:

  - Commit-before-outcome. The commitment carries a salted SHA-256 digest over
    the JCS-canonical claim. The claim may stay private until settlement (so it
    cannot be front-run), yet the digest fixes it. No one can backdate a winning
    verdict after seeing the result, because the signed `created` time and the
    digest are fixed at commit time.
  - Neutral settler. The settlement attestation reproduces the revealed claim and
    salt so any verifier recomputes the digest and confirms it matches what was
    committed. The settler may be a third party, distinct from the committer; the
    attestation binds to the committed digest, not to trust in the committer.

Both are ordinary `eddsa-jcs-2022` Verifiable Credentials, so they compose with
the rest of the protocol and verify across the language SDKs. The transport for
the public record (a chain, a notary, a feed, a URL) is left open: the settlement
descriptor names a method and a locator and is deliberately vendor-neutral.

An `accountability_pointer(...)` helper builds a small `AccountabilityRecord`
object that any other credential can embed in its subject to reference such a
record, so an identity credential can point at an agent's settled track record.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from . import data_integrity
from .jcs import canonicalize

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"

OUTCOME_COMMITMENT_TYPE = "OutcomeCommitmentCredential"
OUTCOME_ATTESTATION_TYPE = "OutcomeAttestationCredential"
ACCOUNTABILITY_RECORD_TYPE = "AccountabilityRecord"

COMMITMENT_ALGORITHM = "sha-256-jcs"


class AccountabilityError(Exception):
    """Raised on malformed outcome-evidence input."""


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(s: str) -> datetime:
    try:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError) as exc:
        raise AccountabilityError(f"malformed timestamp: {s!r}") from exc


def _mb64(b: bytes) -> str:
    return "u" + base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _unmb64(s: str) -> bytes:
    if not isinstance(s, str) or not s.startswith("u"):
        raise AccountabilityError("expected multibase 'u' prefix")
    payload = s[1:]
    return base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))


def _raw_priv(signer: Any):
    raw = getattr(signer, "_raw_priv", None)
    if raw is None:
        raise AccountabilityError("signing requires a Signer with an Ed25519 key")
    return raw


def _attach_proof(credential: Dict[str, Any], signer: Any) -> Dict[str, Any]:
    """Attach an eddsa-jcs-2022 Data Integrity proof to a pre-built credential."""
    credential["proof"] = data_integrity.build_proof(
        credential, _raw_priv(signer), signer.verification_method_id()
    )
    return credential


def commitment_digest(claim: Dict[str, Any], salt: Optional[bytes] = None) -> bytes:
    """
    The binding digest for a claim: SHA-256 over the JCS-canonical claim, with an
    optional salt appended. The same canonicalization the rest of the SDK uses, so
    the digest is reproducible across languages.
    """
    if not isinstance(claim, dict):
        raise AccountabilityError("claim must be a JSON object")
    return hashlib.sha256(canonicalize(claim) + (salt or b"")).digest()


def _type_list(credential: Dict[str, Any]) -> list:
    t = credential.get("type") or []
    return [t] if isinstance(t, str) else list(t)


# ---------------------------------------------------------------------------
# Commitment: a verdict signed before the outcome is known
# ---------------------------------------------------------------------------


def commit_outcome(
    signer: Any,
    *,
    claim: Dict[str, Any],
    settlement: Dict[str, Any],
    subject: Optional[str] = None,
    claim_type: str = "prediction",
    private: bool = False,
    salt: Optional[bytes] = None,
    valid_from: Optional[datetime] = None,
    credential_id: Optional[str] = None,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Issue an OutcomeCommitmentCredential: a claim committed and signed before its
    outcome is known.

    The credential subject carries a `commitment` block (algorithm + salted
    SHA-256 digest of the claim) and a vendor-neutral `settlement` descriptor that
    says how the truth will be determined and where it will be recorded. When
    `private` is set, the cleartext claim is withheld and only the digest is
    published, so the verdict cannot be read or front-run before settlement; the
    returned secret carries the salt and claim needed to settle later.

    Args:
        signer: A Vouch ``Signer`` (the committer).
        claim: The verdict, prediction, or recommendation as a JSON object.
        settlement: Descriptor of how the outcome is resolved. Must include
            ``method`` and ``resolutionCriteria``; ``locator`` and ``resolveBy``
            are recommended.
        subject: DID whose claim is being judged. Defaults to the committer's DID
            (a self-commitment).
        claim_type: Free-form label for the claim (``prediction``, ``verdict``,
            ``recommendation``, ...).
        private: If True, withhold the cleartext claim and publish only the digest.
        salt: Optional explicit salt. A random 32-byte salt is generated when the
            commitment is private and no salt is supplied.
        valid_from: Commitment time (defaults to now, UTC).
        credential_id: Optional credential id (defaults to a ``urn:uuid``).

    Returns:
        ``(credential, secret)`` where ``secret`` is ``{"claim": ..., "salt": ...}``
        and must be retained to settle the commitment later (mandatory when
        private; the salt is multibase-encoded or None).
    """
    if not isinstance(claim, dict):
        raise AccountabilityError("claim must be a JSON object")
    if not isinstance(settlement, dict):
        raise AccountabilityError("settlement must be a JSON object")
    for required in ("method", "resolutionCriteria"):
        if not settlement.get(required):
            raise AccountabilityError(f"settlement.{required} is required")

    if salt is None and private:
        salt = secrets.token_bytes(32)
    digest = commitment_digest(claim, salt)

    issuer = signer.get_did()
    issued = (valid_from or datetime.now(timezone.utc)).astimezone(timezone.utc)

    subject_block: Dict[str, Any] = {
        "id": subject or issuer,
        "claimType": claim_type,
        "commitment": {
            "algorithm": COMMITMENT_ALGORITHM,
            "digest": _mb64(digest),
            "salted": salt is not None,
        },
        "settlement": dict(settlement),
    }
    if not private:
        subject_block["claim"] = claim

    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", OUTCOME_COMMITMENT_TYPE],
        "id": credential_id or f"urn:uuid:{uuid.uuid4()}",
        "issuer": issuer,
        "validFrom": _iso(issued),
        "credentialSubject": subject_block,
    }
    _attach_proof(credential, signer)

    secret = {"claim": claim, "salt": _mb64(salt) if salt is not None else None}
    return credential, secret


def verify_commitment(
    credential: Dict[str, Any],
    public_key: Any,
) -> "Tuple[bool, Optional[Dict[str, Any]]]":
    """
    Verify an OutcomeCommitmentCredential's Data Integrity proof and structure.

    When the commitment is public (the cleartext claim is present and unsalted),
    the published digest is recomputed and checked against the claim. Returns
    ``(ok, credentialSubject)``.
    """
    from vouch.verifier import _coerce_ed25519_public_key

    if OUTCOME_COMMITMENT_TYPE not in _type_list(credential):
        return False, None

    resolved = _coerce_ed25519_public_key(public_key) if public_key is not None else None
    if resolved is None:
        return False, None
    try:
        if not data_integrity.verify_proof(credential, resolved):
            return False, None
    except ValueError:
        return False, None

    subject = credential.get("credentialSubject") or {}
    commitment = subject.get("commitment") or {}
    if not commitment.get("digest"):
        return False, None

    claim = subject.get("claim")
    if claim is not None and not commitment.get("salted"):
        try:
            recomputed = _mb64(commitment_digest(claim, None))
        except AccountabilityError:
            return False, None
        if recomputed != commitment.get("digest"):
            return False, None

    return True, subject


# ---------------------------------------------------------------------------
# Attestation: bind the observed outcome back to the commitment
# ---------------------------------------------------------------------------


def attest_outcome(
    signer: Any,
    *,
    commitment: Dict[str, Any],
    outcome: Dict[str, Any],
    secret: Optional[Dict[str, Any]] = None,
    claim: Optional[Dict[str, Any]] = None,
    salt: Optional[bytes] = None,
    matches: Optional[bool] = None,
    valid_from: Optional[datetime] = None,
    credential_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Issue an OutcomeAttestationCredential settling a prior commitment.

    The attestation reveals the claim and salt (so any verifier recomputes the
    committed digest), records the observed `outcome`, and is signed by the settler
    (who may differ from the committer). The revealed claim is checked against the
    committed digest before signing, so a settler cannot attach a reveal that does
    not match the commitment.

    Args:
        signer: A Vouch ``Signer`` (the settler).
        commitment: The OutcomeCommitmentCredential being settled.
        outcome: The observed result as a JSON object (e.g.
            ``{"result": ..., "evidence": ..., "observedAt": ...}``).
        secret: The ``{"claim", "salt"}`` returned by :func:`commit_outcome`.
            Required when the commitment was private.
        claim: The revealed claim, if not supplied via ``secret`` or already
            public in the commitment.
        salt: The raw salt bytes, if not supplied via ``secret``.
        matches: Optional explicit verdict on whether the claim proved correct;
            recorded as ``outcome.matchesCommitment``.
        valid_from: Settlement time (defaults to now, UTC).
        credential_id: Optional credential id (defaults to a ``urn:uuid``).

    Returns:
        The signed OutcomeAttestationCredential.
    """
    if not isinstance(outcome, dict):
        raise AccountabilityError("outcome must be a JSON object")

    csubject = commitment.get("credentialSubject") or {}
    ccommit = csubject.get("commitment") or {}
    committed_digest = ccommit.get("digest")
    if not committed_digest:
        raise AccountabilityError("commitment carries no digest")

    revealed_claim = claim
    if revealed_claim is None and secret is not None:
        revealed_claim = secret.get("claim")
    if revealed_claim is None:
        revealed_claim = csubject.get("claim")
    if revealed_claim is None:
        raise AccountabilityError("the revealed claim is required to settle a commitment")

    revealed_salt = salt
    if revealed_salt is None and secret is not None and secret.get("salt"):
        revealed_salt = _unmb64(secret["salt"])
    if revealed_salt is None and ccommit.get("salted"):
        raise AccountabilityError("the salt is required to settle a salted commitment")

    if _mb64(commitment_digest(revealed_claim, revealed_salt)) != committed_digest:
        raise AccountabilityError("revealed claim does not match the commitment digest")

    settled = (valid_from or datetime.now(timezone.utc)).astimezone(timezone.utc)

    reveal: Dict[str, Any] = {"claim": revealed_claim}
    if revealed_salt is not None:
        reveal["salt"] = _mb64(revealed_salt)

    outcome_block = dict(outcome)
    if matches is not None:
        outcome_block["matchesCommitment"] = matches

    subject_block: Dict[str, Any] = {
        "id": csubject.get("id", commitment.get("issuer")),
        "commitment": {
            "credentialId": commitment.get("id"),
            "issuer": commitment.get("issuer"),
            "digest": committed_digest,
            "committedAt": commitment.get("validFrom"),
        },
        "reveal": reveal,
        "outcome": outcome_block,
    }

    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", OUTCOME_ATTESTATION_TYPE],
        "id": credential_id or f"urn:uuid:{uuid.uuid4()}",
        "issuer": signer.get_did(),
        "validFrom": _iso(settled),
        "credentialSubject": subject_block,
    }
    return _attach_proof(credential, signer)


def verify_attestation(
    attestation: Dict[str, Any],
    public_key: Any,
    *,
    commitment: Optional[Dict[str, Any]] = None,
    committer_public_key: Any = None,
) -> "Tuple[bool, Optional[Dict[str, Any]]]":
    """
    Verify an OutcomeAttestationCredential.

    Always checks the settler's Data Integrity proof and that the revealed claim
    (with salt) recomputes to the digest the attestation cites. When the original
    `commitment` is supplied, additionally checks that the two digests agree, that
    the subject is the same, and that settlement did not precede the commitment;
    when `committer_public_key` is supplied, the commitment's own proof is verified
    too. Returns ``(ok, credentialSubject)``.
    """
    from vouch.verifier import _coerce_ed25519_public_key

    if OUTCOME_ATTESTATION_TYPE not in _type_list(attestation):
        return False, None

    resolved = _coerce_ed25519_public_key(public_key) if public_key is not None else None
    if resolved is None:
        return False, None
    try:
        if not data_integrity.verify_proof(attestation, resolved):
            return False, None
    except ValueError:
        return False, None

    subject = attestation.get("credentialSubject") or {}
    reveal = subject.get("reveal") or {}
    cited = subject.get("commitment") or {}
    cited_digest = cited.get("digest")
    claim = reveal.get("claim")
    if claim is None or not cited_digest:
        return False, None

    try:
        salt = _unmb64(reveal["salt"]) if reveal.get("salt") else None
        if _mb64(commitment_digest(claim, salt)) != cited_digest:
            return False, None
    except AccountabilityError:
        return False, None

    if commitment is not None:
        if committer_public_key is not None:
            ok, _ = verify_commitment(commitment, committer_public_key)
            if not ok:
                return False, None
        csubject = commitment.get("credentialSubject") or {}
        ccommit = csubject.get("commitment") or {}
        if ccommit.get("digest") != cited_digest:
            return False, None
        if csubject.get("id") != subject.get("id"):
            return False, None
        try:
            if _parse_iso(attestation.get("validFrom")) < _parse_iso(commitment.get("validFrom")):
                return False, None
        except AccountabilityError:
            return False, None

    return True, subject


# ---------------------------------------------------------------------------
# Accountability pointer: reference a track record from another credential
# ---------------------------------------------------------------------------


def accountability_pointer(
    *,
    ledger: str,
    record: Optional[str] = None,
    subject: Optional[str] = None,
    digest: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build a vendor-neutral ``AccountabilityRecord`` pointer that another credential
    can embed in its subject to reference an agent's settled track record.

    Args:
        ledger: Where the record lives (transport-agnostic locator).
        record: Optional anchor or id of the specific record within the ledger.
        subject: Optional DID the record is about.
        digest: Optional commitment digest the pointer references.
    """
    if not ledger:
        raise AccountabilityError("ledger is required")
    pointer: Dict[str, Any] = {"type": ACCOUNTABILITY_RECORD_TYPE, "ledger": ledger}
    if record is not None:
        pointer["record"] = record
    if subject is not None:
        pointer["subject"] = subject
    if digest is not None:
        pointer["digest"] = digest
    return pointer


__all__ = [
    "OUTCOME_COMMITMENT_TYPE",
    "OUTCOME_ATTESTATION_TYPE",
    "ACCOUNTABILITY_RECORD_TYPE",
    "COMMITMENT_ALGORITHM",
    "AccountabilityError",
    "commitment_digest",
    "commit_outcome",
    "verify_commitment",
    "attest_outcome",
    "verify_attestation",
    "accountability_pointer",
]
