"""
Authority Freshness: state change as a first-class input to trust freshness.

Time-decay trust (`vouch.trust_entropy`, Specification §11.5) answers the
question "how long ago was this trust established". That is necessary but not
sufficient for a high-consequence agent. A treasury or trading agent can hold a
SessionVoucher whose decayed trust is still comfortably above threshold at the
instant its mandate is suspended for fraud. Pure elapsed-time freshness keeps
accepting that voucher until it decays or its ~5 minute revocation cache
refreshes. Authority Freshness closes that window.

The freshness of an action is treated as a function of three inputs, not one:

    freshness(action) = f(elapsed_time, authority_state_version, consequence)

- elapsed_time is the existing time-decay computation.
- authority_state_version is a monotonic `authorityEpoch` published by the
  principal or issuer. Any authority-relevant transition (a fraud signal, a
  mandate suspension, an exposure breach, an incident) bumps the epoch and is
  signed with the same `eddsa-jcs-2022` Data Integrity path as every other Vouch
  credential.
- consequence reuses the tiers already defined for bounded-staleness revocation
  in `vouch.status_list` (`routine`, `sensitive`, `critical`), so a deployment
  has one consequence vocabulary, not two.

This module ships three pieces:

1. The `AuthorityState` credential: `build_authority_state` /
   `verify_authority_state`. It carries `authorityEpoch` and `status`, signed by
   the authority's DID.
2. The collapse rule: `evaluate_authority_freshness`. For a consequence tier
   that requires state-freshness, a voucher minted under an epoch older than the
   highest epoch the verifier has seen for that authority is REJECTED, even when
   its time-decay trust still passes. The window has collapsed to now.
3. The zero-tolerance tier: for `critical` actions the verifier does not trust
   any cached epoch at all. It requires a live M-of-N co-sign
   (`verify_live_authority_cosign`) produced at action time via
   `vouch.threshold`, so the authority's current state is read at the moment of
   the action.

What is enforced locally vs. what needs a live check:

- `routine`  : time-decay only. Authority Freshness adds nothing. Enforced locally.
- `sensitive`: the epoch-collapse rule. Enforced locally against the highest epoch
  the verifier has already learned (via a status-list refresh or the heartbeat
  channel). No network call at action time.
- `critical` : the epoch-collapse rule AND a live co-sign read at action time. The
  co-sign is the only part that requires reaching a live quorum; everything else
  is a local comparison.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import data_integrity, jcs
from .multikey import _b58decode
from .status_list import (
    CONSEQUENCE_CRITICAL,
    CONSEQUENCE_ROUTINE,
    CONSEQUENCE_SENSITIVE,
    VALID_CONSEQUENCE_TIERS,
)

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"

VC_TYPE = "VerifiableCredential"
AUTHORITY_STATE_TYPE = "AuthorityState"

# Authority status vocabulary. `active` is the only value under which a
# state-freshness-requiring action may proceed; every other value is an
# authority-relevant transition that MUST bump `authorityEpoch`.
STATUS_ACTIVE = "active"
STATUS_SUSPENDED = "suspended"
STATUS_INCIDENT = "incident"
STATUS_EXPOSURE_BREACHED = "exposure_breached"
STATUS_REVOKED = "revoked"

VALID_AUTHORITY_STATUSES = (
    STATUS_ACTIVE,
    STATUS_SUSPENDED,
    STATUS_INCIDENT,
    STATUS_EXPOSURE_BREACHED,
    STATUS_REVOKED,
)

# The label a live co-sign payload is domain-separated under, so a co-sign can
# never be replayed as some other kind of signed object.
LIVE_COSIGN_TYPE = "AuthorityStateCosign"

# Default freshness window for a live co-sign. A co-sign older than this is
# treated as not "read at action time" and rejected. Policy default, not a
# protocol constant.
DEFAULT_COSIGN_MAX_AGE_SECONDS = 30


class AuthorityStateError(Exception):
    """Raised when an AuthorityState credential is malformed."""


# --------------------------------------------------------------------------- #
# The AuthorityState credential
# --------------------------------------------------------------------------- #


def build_authority_state(
    issuer_did: str,
    authority_epoch: int,
    *,
    status: str = STATUS_ACTIVE,
    valid_seconds: int = 300,
    valid_from: Optional[datetime] = None,
    subject_did: Optional[str] = None,
    credential_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Construct an unsigned AuthorityState credential.

    The caller attaches a Data Integrity proof (`data_integrity.build_proof`)
    signed by the authority's key before publishing it. The wire shape is a
    plain VC Data Model 2.0 credential so it canonicalizes byte-identically
    across every language binding.

    Args:
      issuer_did: DID of the authority publishing its state
        (e.g., "did:web:treasury.example.com").
      authority_epoch: Monotonic epoch counter. MUST strictly increase on every
        authority-relevant transition. A non-negative integer.
      status: One of VALID_AUTHORITY_STATUSES. Defaults to "active".
      valid_seconds: Validity window in seconds. Default 300.
      valid_from: Optional override for `validFrom`. Defaults to current UTC.
      subject_did: The DID the state is about. Defaults to `issuer_did` (an
        authority publishing its own state).
      credential_id: Optional credential id. Defaults to a fresh UUID URN.

    Returns:
      A dict suitable for proof attachment.
    """
    if not isinstance(authority_epoch, int) or isinstance(authority_epoch, bool):
        raise AuthorityStateError("authorityEpoch must be an integer")
    if authority_epoch < 0:
        raise AuthorityStateError(f"authorityEpoch must be non-negative, got {authority_epoch}")
    if status not in VALID_AUTHORITY_STATUSES:
        raise AuthorityStateError(
            f"status must be one of {VALID_AUTHORITY_STATUSES}, got {status!r}"
        )
    if not issuer_did:
        raise AuthorityStateError("issuer_did is required")

    issued_at = (valid_from or datetime.now(timezone.utc)).astimezone(timezone.utc)
    expires_at = issued_at + timedelta(seconds=valid_seconds)

    return {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "id": credential_id or f"urn:uuid:{uuid.uuid4()}",
        "type": [VC_TYPE, AUTHORITY_STATE_TYPE],
        "issuer": issuer_did,
        "validFrom": _iso(issued_at),
        "validUntil": _iso(expires_at),
        "credentialSubject": {
            "id": subject_did or issuer_did,
            "authorityEpoch": authority_epoch,
            "status": status,
        },
    }


def sign_authority_state(
    signer: Any,
    authority_epoch: int,
    *,
    status: str = STATUS_ACTIVE,
    valid_seconds: int = 300,
    valid_from: Optional[datetime] = None,
    subject_did: Optional[str] = None,
    credential_id: Optional[str] = None,
    created: Optional[datetime] = None,
) -> Dict[str, Any]:
    """
    Build an AuthorityState credential and attach the authority's proof.

    The one-call form, mirroring `root_of_trust.build_root_of_trust`. Works with
    an in-process Signer (raw Ed25519 key) and with a backend Signer whose key
    lives outside the process (a secure element, a sidecar, a KMS, or a quorum).

    Args:
      signer: The authority's Signer. Its DID becomes the issuer.
      authority_epoch: Monotonic epoch counter for this state.
      status: One of VALID_AUTHORITY_STATUSES. Defaults to "active".
      created: Optional override for the proof timestamp, used to produce
        reproducible test vectors.
    """
    credential = build_authority_state(
        signer.did,
        authority_epoch,
        status=status,
        valid_seconds=valid_seconds,
        valid_from=valid_from,
        subject_did=subject_did,
        credential_id=credential_id,
    )
    if getattr(signer, "_raw_priv", None) is not None:
        key = signer._raw_priv
    elif getattr(signer, "_sign_func", None) is not None:
        key = signer._sign_func
    else:
        raise AuthorityStateError("signer cannot sign: no private key or sign callback available")
    credential["proof"] = data_integrity.build_proof(
        credential, key, signer.verification_method_id(), created=created
    )
    return credential


@dataclass(frozen=True)
class AuthorityStatePassport:
    """The verified content of an AuthorityState credential."""

    issuer_did: str
    subject_did: str
    authority_epoch: int
    status: str
    valid_from: datetime
    valid_until: datetime

    @property
    def is_active(self) -> bool:
        return self.status == STATUS_ACTIVE


def read_authority_epoch(credential: Dict[str, Any]) -> int:
    """
    Read `credentialSubject.authorityEpoch` from an AuthorityState credential
    without verifying its proof. For deciding which of two credentials is newer;
    never a substitute for `verify_authority_state`.
    """
    subject = credential.get("credentialSubject")
    if not isinstance(subject, dict) or "authorityEpoch" not in subject:
        raise AuthorityStateError("credentialSubject.authorityEpoch is required")
    epoch = subject["authorityEpoch"]
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 0:
        raise AuthorityStateError("authorityEpoch must be a non-negative integer")
    return epoch


def verify_authority_state(
    credential: Union[Dict[str, Any], str],
    public_key: Union[Ed25519PublicKey, str, Dict[str, Any]],
    *,
    clock_skew_seconds: int = 30,
    at_time: Optional[datetime] = None,
) -> Tuple[bool, Optional[AuthorityStatePassport]]:
    """
    Verify an AuthorityState credential's Data Integrity proof, timing, and shape.

    Unlike a VouchCredential, an AuthorityState carries no `intent.resource`
    binding, so the generic `Verifier.verify` (which requires one) does not
    apply. This performs the AuthorityState-specific flow:

      1. Verify the `eddsa-jcs-2022` proof against `public_key`.
      2. Bind the proof to the issuer and require proofPurpose=assertionMethod.
      3. Validate temporal claims (validFrom, validUntil).
      4. Validate the epoch and status shape.

    Returns (True, passport) on success, (False, None) otherwise.
    """
    import json

    if not credential:
        return False, None
    try:
        cred = json.loads(credential) if isinstance(credential, str) else credential
    except json.JSONDecodeError:
        return False, None
    if not isinstance(cred, dict):
        return False, None

    type_field = cred.get("type") or []
    if isinstance(type_field, str):
        type_field = [type_field]
    if AUTHORITY_STATE_TYPE not in type_field:
        return False, None

    from .verifier import _coerce_ed25519_public_key

    resolved = _coerce_ed25519_public_key(public_key)
    if resolved is None:
        return False, None
    try:
        if not data_integrity.verify_proof(cred, resolved):
            return False, None
    except (ValueError, InvalidSignature):
        return False, None

    # Bind the proof to the issuer and enforce its purpose, mirroring
    # Verifier.verify: a signature is only meaningful if the key that made it is
    # the issuer's, used for the assertion purpose.
    proof = cred.get("proof")
    if not isinstance(proof, dict):
        return False, None
    if proof.get("proofPurpose") != "assertionMethod":
        return False, None
    issuer = cred.get("issuer")
    issuer_did = issuer[0] if isinstance(issuer, list) and issuer else issuer
    vm = proof.get("verificationMethod")
    if not isinstance(issuer_did, str) or not issuer_did:
        return False, None
    if not isinstance(vm, str) or vm.split("#", 1)[0] != issuer_did:
        return False, None

    now = (at_time or datetime.now(timezone.utc)).astimezone(timezone.utc)
    valid_from = _parse_iso_opt(cred.get("validFrom"))
    valid_until = _parse_iso_opt(cred.get("validUntil"))
    if valid_from is None or valid_until is None:
        return False, None
    if (now - valid_until).total_seconds() > clock_skew_seconds:
        return False, None
    if (valid_from - now).total_seconds() > clock_skew_seconds:
        return False, None

    subject = cred.get("credentialSubject")
    if not isinstance(subject, dict):
        return False, None
    try:
        epoch = read_authority_epoch(cred)
    except AuthorityStateError:
        return False, None
    status = subject.get("status")
    if status not in VALID_AUTHORITY_STATUSES:
        return False, None

    return True, AuthorityStatePassport(
        issuer_did=issuer_did,
        subject_did=subject.get("id") or issuer_did,
        authority_epoch=epoch,
        status=status,
        valid_from=valid_from,
        valid_until=valid_until,
    )


# --------------------------------------------------------------------------- #
# The collapse rule: consequence -> freshness policy
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class FreshnessRule:
    """How a consequence tier treats authority state.

    Attributes:
      enforce_epoch: Reject a voucher minted under an epoch older than the
        highest epoch the verifier has learned for the authority.
      require_live_cosign: Do not trust any cached epoch; require a live M-of-N
        co-sign read at action time.
    """

    enforce_epoch: bool
    require_live_cosign: bool


# The consequence -> policy map. `routine` gets time-decay only; `sensitive`
# collapses the window on a stale epoch; `critical` additionally demands a live
# co-sign. Deployments MAY substitute their own map; the tier ordering is the
# normative part.
AUTHORITY_FRESHNESS_POLICY: Dict[str, FreshnessRule] = {
    CONSEQUENCE_ROUTINE: FreshnessRule(enforce_epoch=False, require_live_cosign=False),
    CONSEQUENCE_SENSITIVE: FreshnessRule(enforce_epoch=True, require_live_cosign=False),
    CONSEQUENCE_CRITICAL: FreshnessRule(enforce_epoch=True, require_live_cosign=True),
}


@dataclass(frozen=True)
class AuthorityFreshnessVerdict:
    """
    Outcome of an Authority Freshness evaluation.

    Attributes:
      allow: Whether the action passes the authority-state gate. This is the
        state-freshness judgement only; a caller still folds in identity,
        revocation, and time-decay trust.
      tier: The consequence tier evaluated against (unknown tiers coerce to
        `critical`).
      reason: A structured, stable reason code, suitable for an audit log
        (e.g., "authority_epoch_stale:seen=7,voucher=5").
    """

    allow: bool
    tier: str
    reason: str


def evaluate_authority_freshness(
    *,
    tier: str,
    voucher_epoch: Optional[int],
    last_seen_epoch: Optional[int],
    current_status: Optional[str] = None,
    live_cosign_ok: Optional[bool] = None,
    policy: Optional[Dict[str, FreshnessRule]] = None,
) -> AuthorityFreshnessVerdict:
    """
    Decide whether an action passes the Authority Freshness gate.

    Args:
      tier: One of `routine`, `sensitive`, `critical`. An unknown tier coerces
        to `critical` (fail-closed).
      voucher_epoch: The `authorityEpoch` the caller's SessionVoucher (or
        heartbeat) was minted under, or None if the voucher carries no epoch.
      last_seen_epoch: The highest epoch the verifier has learned for this
        authority, via a status-list refresh or the heartbeat channel. None if
        the verifier has never seen an epoch for this authority.
      current_status: The authority's current status if known (from a verified
        AuthorityState). When present and not `active`, a state-freshness tier
        fails closed regardless of epochs.
      live_cosign_ok: For the `critical` tier only: whether a live co-sign was
        supplied AND verified fresh (see `verify_live_authority_cosign`). None or
        False on a tier that requires it fails closed.
      policy: Optional consequence -> FreshnessRule map overriding
        AUTHORITY_FRESHNESS_POLICY.

    Decision order (first failure wins):

        tier == routine                               -> ALLOW (time-decay only)
        current_status known and not active           -> DENY  authority_status_not_active
        require_live_cosign and not live_cosign_ok    -> DENY  live_cosign_required
        enforce_epoch, voucher_epoch < last_seen      -> DENY  authority_epoch_stale
        enforce_epoch, epoch unavailable              -> DENY  authority_epoch_unknown
        otherwise                                     -> ALLOW
    """
    rules = policy or AUTHORITY_FRESHNESS_POLICY
    if tier not in VALID_CONSEQUENCE_TIERS:
        tier = CONSEQUENCE_CRITICAL
    rule = rules.get(tier, FreshnessRule(enforce_epoch=True, require_live_cosign=True))

    if not rule.enforce_epoch and not rule.require_live_cosign:
        return AuthorityFreshnessVerdict(True, tier, "routine tier: time-decay only")

    if current_status is not None and current_status != STATUS_ACTIVE:
        return AuthorityFreshnessVerdict(
            False, tier, f"authority_status_not_active:status={current_status}"
        )

    if rule.require_live_cosign and not live_cosign_ok:
        return AuthorityFreshnessVerdict(False, tier, f"live_cosign_required:tier={tier}")

    if rule.enforce_epoch:
        # Why an epoch and not a fresher timestamp: a timestamp says when the
        # voucher was minted, never whether authority has changed since, so time
        # alone forces the verifier to guess a safe staleness window. A new epoch
        # is proof that a real transition happened, published and signed by the
        # authority. A voucher minted under epoch 7 is refused once this verifier
        # has seen epoch 8, even six seconds later with time-decay trust still
        # passing. The limit: this only bites once the verifier has learned of the
        # newer epoch, which is why the critical tier falls back to a live co-sign.
        if voucher_epoch is None or last_seen_epoch is None:
            # An absent epoch renders as "?" so the reason code is identical in
            # every language binding (Python None, Rust None, Go nil, and TS
            # null would otherwise each print differently). Pinned by the
            # interop vector.
            return AuthorityFreshnessVerdict(
                False,
                tier,
                f"authority_epoch_unknown:voucher={_epoch_str(voucher_epoch)},"
                f"seen={_epoch_str(last_seen_epoch)}",
            )
        if voucher_epoch < last_seen_epoch:
            return AuthorityFreshnessVerdict(
                False,
                tier,
                f"authority_epoch_stale:seen={last_seen_epoch},voucher={voucher_epoch}",
            )

    return AuthorityFreshnessVerdict(True, tier, f"{tier} tier: authority state fresh")


# --------------------------------------------------------------------------- #
# The zero-tolerance tier: live M-of-N co-sign, read at action time
# --------------------------------------------------------------------------- #


def cosign_signing_input(
    *,
    authority_did: str,
    authority_epoch: int,
    status: str,
    nonce: str,
    created: datetime,
) -> bytes:
    """
    The canonical bytes an authority quorum co-signs to attest its CURRENT state
    at action time. Domain-separated by `type` so the signature cannot be
    replayed as any other signed object. JCS-canonicalized so every language
    produces identical bytes.
    """
    payload = {
        "type": LIVE_COSIGN_TYPE,
        "authority": authority_did,
        "authorityEpoch": authority_epoch,
        "status": status,
        "nonce": nonce,
        "created": _iso(created.astimezone(timezone.utc)),
    }
    return jcs.canonicalize(payload)


def build_live_authority_cosign(
    *,
    authority_did: str,
    authority_epoch: int,
    sign: Any,
    status: str = STATUS_ACTIVE,
    nonce: Optional[str] = None,
    created: Optional[datetime] = None,
) -> Dict[str, Any]:
    """
    Produce a live authority co-sign object.

    `sign` is a callable `sign(signing_input: bytes) -> bytes` returning a
    64-byte Ed25519 signature. Wire a `vouch.threshold.ThresholdSigner.sign`
    here so the signature is an M-of-N FROST aggregate: the group's current
    quorum has to be reachable and willing at this instant to produce it, which
    is the whole point of the zero-tolerance tier. The aggregate is a STANDARD
    Ed25519 signature, so `verify_live_authority_cosign` needs no FROST code.

    `nonce` binds the co-sign to one action; the verifier supplies the nonce it
    challenged with and rejects any co-sign that does not carry it.
    """
    if status not in VALID_AUTHORITY_STATUSES:
        raise AuthorityStateError(f"status must be one of {VALID_AUTHORITY_STATUSES}")
    created = (created or datetime.now(timezone.utc)).astimezone(timezone.utc)
    nonce = nonce or uuid.uuid4().hex
    signing_input = cosign_signing_input(
        authority_did=authority_did,
        authority_epoch=authority_epoch,
        status=status,
        nonce=nonce,
        created=created,
    )
    signature = sign(signing_input)
    return {
        "type": LIVE_COSIGN_TYPE,
        "authority": authority_did,
        "authorityEpoch": authority_epoch,
        "status": status,
        "nonce": nonce,
        "created": _iso(created),
        "proofValue": "z" + _b58encode(signature),
    }


@dataclass(frozen=True)
class LiveCosignResult:
    """Outcome of verifying a live authority co-sign."""

    ok: bool
    reason: str
    authority_epoch: Optional[int] = None
    status: Optional[str] = None


def verify_live_authority_cosign(
    cosign: Dict[str, Any],
    group_public_key: Union[Ed25519PublicKey, str],
    *,
    expected_nonce: str,
    max_age_seconds: int = DEFAULT_COSIGN_MAX_AGE_SECONDS,
    now: Optional[datetime] = None,
) -> LiveCosignResult:
    """
    Verify a live authority co-sign for the `critical` tier.

    Checks, in order: the object shape, the nonce matches the one the verifier
    challenged with (anti-replay), the co-sign was produced within
    `max_age_seconds` of now (read at action time, not cached), and the
    aggregated Ed25519 signature verifies against `group_public_key`.

    The signature check uses the standard Ed25519 verifier; the M-of-N ceremony
    that produced it lives entirely on the signing side. Returns a
    LiveCosignResult; feed `.ok` to `evaluate_authority_freshness(live_cosign_ok=...)`.
    """
    from .verifier import _coerce_ed25519_public_key

    if not isinstance(cosign, dict):
        return LiveCosignResult(False, "cosign_malformed")
    if cosign.get("type") != LIVE_COSIGN_TYPE:
        return LiveCosignResult(False, "cosign_wrong_type")
    if cosign.get("nonce") != expected_nonce:
        return LiveCosignResult(False, "cosign_nonce_mismatch")

    status = cosign.get("status")
    if status not in VALID_AUTHORITY_STATUSES:
        return LiveCosignResult(False, "cosign_bad_status")
    epoch = cosign.get("authorityEpoch")
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 0:
        return LiveCosignResult(False, "cosign_bad_epoch")

    created = _parse_iso_opt(cosign.get("created"))
    if created is None:
        return LiveCosignResult(False, "cosign_bad_created")
    moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    age = (moment - created).total_seconds()
    if age > max_age_seconds:
        return LiveCosignResult(False, f"cosign_stale:age={int(age)}s>{max_age_seconds}s")
    # A co-sign dated in the future beyond skew is not trustworthy either.
    if age < -max_age_seconds:
        return LiveCosignResult(False, "cosign_future_dated")

    proof_value = cosign.get("proofValue")
    if not isinstance(proof_value, str) or not proof_value.startswith("z"):
        return LiveCosignResult(False, "cosign_bad_proof_value")

    key = _coerce_ed25519_public_key(group_public_key)
    if key is None:
        return LiveCosignResult(False, "cosign_bad_key")

    signing_input = cosign_signing_input(
        authority_did=cosign.get("authority", ""),
        authority_epoch=epoch,
        status=status,
        nonce=cosign["nonce"],
        created=created,
    )
    try:
        key.verify(_b58decode(proof_value[1:]), signing_input)
    except InvalidSignature:
        return LiveCosignResult(False, "cosign_signature_invalid")

    if status != STATUS_ACTIVE:
        return LiveCosignResult(False, f"cosign_status_not_active:status={status}", epoch, status)

    return LiveCosignResult(True, "live co-sign fresh and valid", epoch, status)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def _epoch_str(epoch: Optional[int]) -> str:
    """Render an epoch for a reason code; "?" when absent, so the string is
    identical across every language binding."""
    return "?" if epoch is None else str(epoch)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso_opt(value: Optional[str]) -> Optional[datetime]:
    if not value or not isinstance(value, str):
        return None
    try:
        if value.endswith("Z"):
            return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        return datetime.fromisoformat(value).astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def _b58encode(data: bytes) -> str:
    from .multikey import _b58encode as _enc

    return _enc(data)


__all__ = [
    "AUTHORITY_STATE_TYPE",
    "STATUS_ACTIVE",
    "STATUS_SUSPENDED",
    "STATUS_INCIDENT",
    "STATUS_EXPOSURE_BREACHED",
    "STATUS_REVOKED",
    "VALID_AUTHORITY_STATUSES",
    "LIVE_COSIGN_TYPE",
    "DEFAULT_COSIGN_MAX_AGE_SECONDS",
    "AuthorityStateError",
    "AuthorityStatePassport",
    "FreshnessRule",
    "AUTHORITY_FRESHNESS_POLICY",
    "AuthorityFreshnessVerdict",
    "LiveCosignResult",
    "build_authority_state",
    "sign_authority_state",
    "verify_authority_state",
    "read_authority_epoch",
    "evaluate_authority_freshness",
    "cosign_signing_input",
    "build_live_authority_cosign",
    "verify_live_authority_cosign",
]
