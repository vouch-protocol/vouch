"""
Heartbeat Protocol orchestration for Vouch Protocol.

Implements the renewal protocol described in Specification §11. A
long-running agent submits a heartbeat request to a validator (or
validator quorum) at regular intervals; the validator confirms the
request and issues a fresh SessionVoucher VC valid for the next
interval. If the agent stops heartbeating, the SessionVoucher expires
naturally and downstream verifiers stop accepting actions.

The protocol assembles three primitives from sibling modules:

- canary.py: commit/reveal chain that makes a skipped heartbeat
 cryptographically detectable.
- behavioral_attestation.py: per-interval signal collection
 (api calls, tokens, resources, intent drift).
- merkle.py: actionMerkleRoot over the agent's actions in the interval.
- trust_entropy.py: decay parameters consumed by verifiers.

Wire format (Specification §11.3):

  {
   "version": "1.0",
   "type": "heartbeat_request",
   "subject_did": "<agent DID>",
   "session_id": "<UUID-URN>",
   "interval_index": <int>,
   "issued_at": "<ISO-8601 UTC>",
   "actionMerkleRoot": "u<multibase>",
   "canaryCommitment": "u<multibase>",
   "canaryReveal": "u<multibase>" (optional on first heartbeat),
   "behavioralDigest": { ... per §11.3 ... },
   "actionLeafHashes": ["u<multibase>", ...],
   "proof": { eddsa-jcs-2022 Data Integrity proof by subject_did }
  }

`actionLeafHashes` carries the per-action leaf hashes (never the actions), so
the validator recomputes `actionMerkleRoot` itself. The `proof` is made by the
agent's own key (`HeartbeatSession(signer=...)`); the validator requires it by
default.

Validator policy (HeartbeatValidator):

- the request must be signed by `subject_did`;
- `issued_at` must be within `max_request_age_seconds` of the validator's clock
  and no more than `max_clock_skew_seconds` ahead of it;
- `actionMerkleRoot` must equal the root of `actionLeafHashes`;
- `interval_index` must be strictly greater than the last accepted one;
- missed beats: if more than `max_missed_intervals` intervals pass (by the
  validator's clock or by `interval_index`) since the last accepted beat, the
  session lapses. No voucher is issued, so the agent's trust decays out, and
  every later beat is refused until `reset_session` is called.
"""

from __future__ import annotations

import asyncio
import threading
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Dict, List, Optional, Sequence

from .behavioral_attestation import (
    BehavioralAttestationError,
    BehavioralCollector,
    validate_behavioral_digest,
)
from . import data_integrity
from .canary import CanaryChain, CanaryChainError, CanaryVerifier
from .merkle import (
    MerkleError,
    _decode_multibase,
    _encode_multibase,
    compute_action_merkle_root,
    hash_leaf,
    root_from_leaf_hashes,
)
from .vc import build_session_voucher


HEARTBEAT_PROTOCOL_VERSION = "1.0"
HEARTBEAT_REQUEST_TYPE = "heartbeat_request"


class HeartbeatError(Exception):
    """Raised on heartbeat protocol failures."""


# ---------------------------------------------------------------------------
# Wire format
# ---------------------------------------------------------------------------


@dataclass
class HeartbeatRequest:
    """The §11.3 wire-format object an agent submits to a validator."""

    subject_did: str
    session_id: str
    interval_index: int
    issued_at: datetime
    action_merkle_root: str
    canary_commitment: str
    behavioral_digest: Dict[str, Any]
    canary_reveal: Optional[str] = None
    authority_epoch: Optional[int] = None
    action_leaf_hashes: Optional[List[str]] = None
    proof: Optional[Dict[str, Any]] = None

    def unsigned_dict(self) -> Dict[str, Any]:
        """The wire object without its proof (what the proof signs)."""
        d: Dict[str, Any] = {
            "version": HEARTBEAT_PROTOCOL_VERSION,
            "type": HEARTBEAT_REQUEST_TYPE,
            "subject_did": self.subject_did,
            "session_id": self.session_id,
            "interval_index": self.interval_index,
            "issued_at": _iso(self.issued_at),
            "actionMerkleRoot": self.action_merkle_root,
            "canaryCommitment": self.canary_commitment,
            "behavioralDigest": self.behavioral_digest,
        }
        if self.canary_reveal is not None:
            d["canaryReveal"] = self.canary_reveal
        if self.authority_epoch is not None:
            d["authorityEpoch"] = self.authority_epoch
        if self.action_leaf_hashes is not None:
            d["actionLeafHashes"] = list(self.action_leaf_hashes)
        return d

    def sign(self, signer: Any) -> None:
        """Attach an eddsa-jcs-2022 proof made by `signer` over the request."""
        key = getattr(signer, "_raw_priv", None) or getattr(signer, "_sign_func", None)
        if key is None:
            raise HeartbeatError("signer cannot sign: no private key or sign callback available")
        self.proof = data_integrity.build_proof(
            self.unsigned_dict(), key, signer.verification_method_id(), created=self.issued_at
        )

    def to_dict(self, *, resign: Any = None) -> Dict[str, Any]:
        """The wire object. With `resign`, re-sign it first (after an edit)."""
        if resign is not None:
            self.sign(resign)
        d = self.unsigned_dict()
        if self.proof is not None:
            d["proof"] = self.proof
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "HeartbeatRequest":
        _validate_request_shape(d)
        return cls(
            subject_did=d["subject_did"],
            session_id=d["session_id"],
            interval_index=int(d["interval_index"]),
            issued_at=_parse_iso(d["issued_at"]),
            action_merkle_root=d["actionMerkleRoot"],
            canary_commitment=d["canaryCommitment"],
            behavioral_digest=d["behavioralDigest"],
            canary_reveal=d.get("canaryReveal"),
            authority_epoch=d.get("authorityEpoch"),
            action_leaf_hashes=d.get("actionLeafHashes"),
            proof=d.get("proof"),
        )


def _validate_request_shape(d: Dict[str, Any]) -> None:
    if not isinstance(d, dict):
        raise HeartbeatError("heartbeat request must be a dict")
    if d.get("version") != HEARTBEAT_PROTOCOL_VERSION:
        raise HeartbeatError(
            f"version must be {HEARTBEAT_PROTOCOL_VERSION!r}, got {d.get('version')!r}"
        )
    if d.get("type") != HEARTBEAT_REQUEST_TYPE:
        raise HeartbeatError(f"type must be {HEARTBEAT_REQUEST_TYPE!r}, got {d.get('type')!r}")
    for required in (
        "subject_did",
        "session_id",
        "interval_index",
        "issued_at",
        "actionMerkleRoot",
        "canaryCommitment",
        "behavioralDigest",
    ):
        if required not in d:
            raise HeartbeatError(f"{required} is required")
    if not isinstance(d["interval_index"], int) or d["interval_index"] < 0:
        raise HeartbeatError("interval_index must be a non-negative integer")
    if "authorityEpoch" in d:
        epoch = d["authorityEpoch"]
        if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 0:
            raise HeartbeatError("authorityEpoch must be a non-negative integer")
    if "actionLeafHashes" in d:
        hashes = d["actionLeafHashes"]
        if not isinstance(hashes, list) or not all(isinstance(h, str) for h in hashes):
            raise HeartbeatError("actionLeafHashes must be a list of multibase strings")
    if "proof" in d and not isinstance(d["proof"], dict):
        raise HeartbeatError("proof must be an object")
    try:
        _parse_iso(d["issued_at"])
    except (TypeError, ValueError) as exc:
        raise HeartbeatError(f"issued_at must be an ISO-8601 UTC timestamp: {exc}") from exc


# ---------------------------------------------------------------------------
# Agent side: HeartbeatSession + HeartbeatScheduler
# ---------------------------------------------------------------------------


@dataclass
class HeartbeatSession:
    """
    Stateful session on the agent side. Bundles the canary chain, the
    behavioral collector, and an action tracker for the current interval.

    Typical lifecycle:

      session = HeartbeatSession(subject_did="did:web:agent.example.com")
      # ... agent records actions and signals as it runs ...
      session.record_action(b"submit_claim:HC-001")
      session.collector.record_api_call(...)
      # ... heartbeat time ...
      req = session.build_request()
      # Submit req.to_dict() to validator; on success, session continues.

    Attributes:
      subject_did: The agent's DID.
      session_id: A stable identifier for this run of the agent.
      collector: Behavioral signal collector (created if not supplied).
      chain: Canary commit/reveal chain (created if not supplied).
    """

    subject_did: str
    session_id: str = field(default_factory=lambda: f"urn:uuid:{uuid.uuid4()}")
    collector: BehavioralCollector = field(default_factory=BehavioralCollector)
    chain: CanaryChain = field(default_factory=CanaryChain)
    authority_epoch: Optional[int] = None
    signer: Optional[Any] = None
    allow_foreign_signer: bool = False
    _interval_index: int = field(default=0, init=False)
    _actions: List[bytes] = field(default_factory=list, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def __post_init__(self) -> None:
        if (
            self.signer is not None
            and not self.allow_foreign_signer
            and getattr(self.signer, "did", None) != self.subject_did
        ):
            raise HeartbeatError("the heartbeat signer's DID must be the session's subject_did")

    @property
    def interval_index(self) -> int:
        return self._interval_index

    def record_action(self, action_bytes: bytes) -> None:
        """
        Record one action taken by the agent in the current interval.

        The action is hashed into the actionMerkleRoot when the heartbeat
        is built. Callers serialize each action to a deterministic byte
        string (typically JCS canonical bytes of the action payload).
        """
        if not isinstance(action_bytes, (bytes, bytearray)):
            raise HeartbeatError("action_bytes must be bytes")
        with self._lock:
            self._actions.append(bytes(action_bytes))

    def build_request(self, *, now: Optional[datetime] = None) -> HeartbeatRequest:
        """
        Build and return the heartbeat request for the current interval.

        After this call:
        - The canary chain advances (a fresh secret is generated, the
         previous one is revealed).
        - The behavioral collector and action list are reset, ready for
         the next interval.
        - `interval_index` is incremented.

        Callers MUST submit the returned request to the validator before
        the next call to `build_request`, otherwise the canary reveal is
        lost and the chain breaks.
        """
        with self._lock:
            issued_at = now or datetime.now(timezone.utc)
            cm = self.chain.next_heartbeat()
            action_root = compute_action_merkle_root(self._actions)
            digest = self.collector.digest()
            req = HeartbeatRequest(
                subject_did=self.subject_did,
                session_id=self.session_id,
                interval_index=self._interval_index,
                issued_at=issued_at,
                action_merkle_root=action_root,
                canary_commitment=cm.commitment,
                canary_reveal=cm.reveal,
                behavioral_digest=digest,
                authority_epoch=self.authority_epoch,
                action_leaf_hashes=[_encode_multibase(hash_leaf(a)) for a in self._actions],
            )
            if self.signer is not None:
                req.sign(self.signer)
            self._interval_index += 1
            self._actions.clear()
            self.collector.reset()
            return req


@dataclass
class HeartbeatScheduler:
    """
    Asyncio-based scheduler that fires `submit_callback` every
    `interval_seconds` with the next HeartbeatRequest.

    The scheduler does NOT itself sign or transport the request; it
    invokes the callback so the caller can perform signing, HTTP
    submission, retry handling, and SessionVoucher consumption.

    Example:

      async def submit(req):
        signed = signer.sign(req.to_dict())
        result = await http.post(validator_url, json=signed)
        return result

      scheduler = HeartbeatScheduler(
        session=session,
        interval_seconds=60,
        submit_callback=submit,
      )
      scheduler.start()
      # ...
      await scheduler.stop()

    Attributes:
      session: The HeartbeatSession that produces requests.
      interval_seconds: Seconds between heartbeats. SHOULD be less than
        the SessionVoucher half-life so renewal stays ahead of decay.
      submit_callback: Async callable invoked with each HeartbeatRequest.
      on_failure: Optional async callable invoked on submission error;
        receives the exception. Defaults to logging via the standard
        library `logging` module.
    """

    session: HeartbeatSession
    interval_seconds: float
    submit_callback: Callable[[HeartbeatRequest], Awaitable[Any]]
    on_failure: Optional[Callable[[Exception], Awaitable[None]]] = None
    _task: Optional[asyncio.Task] = field(default=None, init=False, repr=False)
    _stop_event: Optional[asyncio.Event] = field(default=None, init=False, repr=False)

    def start(self) -> None:
        """Begin firing heartbeats on the current event loop."""
        if self._task is not None and not self._task.done():
            raise HeartbeatError("scheduler is already running")
        if self.interval_seconds <= 0:
            raise HeartbeatError(f"interval_seconds must be positive, got {self.interval_seconds}")
        self._stop_event = asyncio.Event()
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        """Stop the scheduler. Awaits the in-flight callback to settle."""
        if self._stop_event is not None:
            self._stop_event.set()
        if self._task is not None:
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
            self._stop_event = None

    async def _run(self) -> None:
        assert self._stop_event is not None
        try:
            while not self._stop_event.is_set():
                try:
                    req = self.session.build_request()
                    await self.submit_callback(req)
                except Exception as exc:  # pylint: disable=broad-except
                    await self._handle_failure(exc)
                try:
                    await asyncio.wait_for(self._stop_event.wait(), timeout=self.interval_seconds)
                except asyncio.TimeoutError:
                    continue
        except asyncio.CancelledError:
            pass

    async def _handle_failure(self, exc: Exception) -> None:
        if self.on_failure is not None:
            await self.on_failure(exc)
        else:
            import logging

            logging.getLogger("vouch.heartbeat").warning(
                "heartbeat submission failed: %s: %s", type(exc).__name__, exc
            )


# ---------------------------------------------------------------------------
# Pluggable storage for validator state
# ---------------------------------------------------------------------------


class HeartbeatStoreInterface(ABC):
    """
    Abstract storage backend for HeartbeatValidator per-session state.

    Implementations persist a small JSON-serializable state dict per
    (subject_did, session_id) key. The state dict has the shape:

      {
        "last_commitment": <multibase str or None>,
        "expecting_reveal": <bool>,
        "last_interval": <int or None>,
        "last_seen_at": <ISO-8601 UTC str or None>,
        "lapsed": <bool>
      }

    The reference MemoryHeartbeatStore (in this module) keeps state in
    a process-local dict, suitable for development and single-process
    deployments. Production deployments substitute a Redis, Postgres,
    Kafka, or S3 store via this interface; concrete backends ship in
    the commercial `vouch.pro` layer.

    Implementations MUST be thread-safe. Validators typically hold a
    single Store instance and dispatch concurrent heartbeat requests
    against it.
    """

    @abstractmethod
    def get(self, session_key: str) -> Optional[Dict[str, Any]]:
        """Return the state dict for `session_key`, or None if absent."""

    @abstractmethod
    def put(self, session_key: str, state: Dict[str, Any]) -> None:
        """Atomically replace the state dict for `session_key`."""

    @abstractmethod
    def delete(self, session_key: str) -> None:
        """Drop all state for `session_key`. Idempotent."""

    @abstractmethod
    def known_sessions(self) -> List[str]:
        """Return the list of session keys currently tracked."""


class MemoryHeartbeatStore(HeartbeatStoreInterface):
    """
    Reference in-memory store. Thread-safe via an internal lock.

    Loses all state on process restart, by design; production
    deployments swap in a durable store. The state-dict shape is the
    contract; subclasses MUST keep the same shape so verifier logic
    is backend-agnostic.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._data: Dict[str, Dict[str, Any]] = {}

    def get(self, session_key: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            state = self._data.get(session_key)
            return dict(state) if state is not None else None

    def put(self, session_key: str, state: Dict[str, Any]) -> None:
        with self._lock:
            self._data[session_key] = dict(state)

    def delete(self, session_key: str) -> None:
        with self._lock:
            self._data.pop(session_key, None)

    def known_sessions(self) -> List[str]:
        with self._lock:
            return list(self._data.keys())


# ---------------------------------------------------------------------------
# Validator side: HeartbeatValidator
# ---------------------------------------------------------------------------


@dataclass
class HeartbeatValidationResult:
    """
    Outcome of validating a single heartbeat request.

    Attributes:
      ok: True if the request is structurally valid AND the canary chain
        remains intact.
      reasons: Empty when ok=True. When ok=False, a list of structured
        failure reasons (e.g., "canary_chain_broken", "schema_invalid",
        "behavioral_digest_invalid", "stale_interval_index").
      session_voucher: If ok=True, an unsigned SessionVoucher VC ready
        for the validator to sign and return to the agent. None when
        ok=False.
    """

    ok: bool
    reasons: List[str] = field(default_factory=list)
    session_voucher: Optional[Dict[str, Any]] = None


@dataclass
class HeartbeatValidator:
    """
    Single-validator implementation of the Heartbeat Protocol verifier side.

    Maintains per-(subject_did, session_id) canary chain state. On each
    heartbeat:

    1. Validates request shape (Specification §11.3 schema).
    2. Verifies the request's proof was made by `subject_did`
      (`require_signature`, on by default).
    3. Checks `issued_at` against the validator's clock.
    4. Recomputes `actionMerkleRoot` from `actionLeafHashes`.
    5. Validates behavioral digest structure.
    6. Refuses a lapsed session; validates that interval_index is strictly
      greater than the last accepted one; lapses the session if more than
      `max_missed_intervals` were missed.
    7. Walks the canary chain via CanaryVerifier.
    8. On success, returns an unsigned SessionVoucher VC carrying the
      configured initialTrust and decayLambda, issued at the validator's clock.

    Attributes:
      validator_did: Validator's own DID, used as the SessionVoucher issuer.
      initial_trust: initialTrust value embedded in the SessionVoucher.
      decay_lambda: decayLambda value embedded in the SessionVoucher.
      max_ttl_seconds: max_ttl_seconds in the SessionVoucher.
      voucher_valid_seconds: validity window of the issued voucher.
        SHOULD be slightly longer than the heartbeat interval.
      scope: Scope list embedded in the SessionVoucher.
      require_signature: Refuse a request without a valid proof by its subject.
      key_resolver: `did -> key` for non-did:key subjects (did:key resolves offline).
      require_action_leaf_hashes: Refuse a request that does not carry the
        leaf hashes its actionMerkleRoot was built from.
      interval_seconds: The expected heartbeat interval.
      max_missed_intervals: How many intervals may be missed before the
        session lapses.
      max_request_age_seconds / max_clock_skew_seconds: The issued_at window.
      clock: The validator's clock (injectable for tests and simulations).
    """

    validator_did: str
    initial_trust: float = 1.0
    decay_lambda: float = 0.01
    max_ttl_seconds: int = 3600
    voucher_valid_seconds: int = 120
    scope: List[str] = field(default_factory=lambda: ["agent_actions"])
    store: HeartbeatStoreInterface = field(default_factory=MemoryHeartbeatStore)
    require_signature: bool = True
    key_resolver: Optional[Callable[[str], Any]] = None
    require_action_leaf_hashes: bool = True
    interval_seconds: float = 60.0
    max_missed_intervals: int = 2
    max_request_age_seconds: int = 120
    max_clock_skew_seconds: int = 30
    clock: Callable[[], datetime] = field(default=lambda: datetime.now(timezone.utc), repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)
    _highest_epoch: Dict[str, int] = field(default_factory=dict, init=False, repr=False)

    def _session_key(self, subject_did: str, session_id: str) -> str:
        return f"{subject_did}::{session_id}"

    def highest_authority_epoch(self, subject_did: str) -> Optional[int]:
        """
        Return the highest `authorityEpoch` this validator has seen on the
        heartbeat channel for `subject_did`, or None if it has seen none. This
        is one of the two channels a verifier learns epochs from (the other is a
        status-list refresh); it feeds `last_seen_epoch` in
        `authority_state.evaluate_authority_freshness`.
        """
        with self._lock:
            return self._highest_epoch.get(subject_did)

    def validate(self, request: Dict[str, Any]) -> HeartbeatValidationResult:
        """Validate a heartbeat request dict and emit a (possibly empty) result."""
        reasons: List[str] = []
        try:
            req = HeartbeatRequest.from_dict(request)
        except HeartbeatError as exc:
            return HeartbeatValidationResult(ok=False, reasons=[f"schema_invalid:{exc}"])

        if self.require_signature:
            sig_reason = self._check_signature(request, req.subject_did)
            if sig_reason is not None:
                return HeartbeatValidationResult(ok=False, reasons=[sig_reason])

        now = self.clock().astimezone(timezone.utc)
        age = (now - req.issued_at).total_seconds()
        if age > self.max_request_age_seconds:
            return HeartbeatValidationResult(ok=False, reasons=["issued_at_too_old"])
        if -age > self.max_clock_skew_seconds:
            return HeartbeatValidationResult(ok=False, reasons=["issued_at_in_future"])

        merkle_reason = self._check_action_root(req)
        if merkle_reason is not None:
            return HeartbeatValidationResult(ok=False, reasons=[merkle_reason])

        try:
            validate_behavioral_digest(req.behavioral_digest)
        except BehavioralAttestationError as exc:
            reasons.append(f"behavioral_digest_invalid:{exc}")

        key = self._session_key(req.subject_did, req.session_id)

        with self._lock:
            state = self.store.get(key) or {
                "last_commitment": None,
                "expecting_reveal": False,
                "last_interval": None,
                "last_seen_at": None,
                "lapsed": False,
            }
            if state.get("lapsed"):
                return HeartbeatValidationResult(ok=False, reasons=["session_lapsed"])

            last_interval = state.get("last_interval")
            if last_interval is not None and req.interval_index <= last_interval:
                reasons.append(f"stale_interval_index:{req.interval_index}<= last={last_interval}")

            missed = self._missed_intervals(state, req.interval_index, now)
            if not reasons and missed > self.max_missed_intervals:
                state["lapsed"] = True
                self.store.put(key, state)
                return HeartbeatValidationResult(
                    ok=False,
                    reasons=[f"missed_heartbeats:{missed}>{self.max_missed_intervals}"],
                )

            verifier = CanaryVerifier()
            verifier._last_commitment = state.get("last_commitment")  # noqa: SLF001
            verifier._expecting_reveal = bool(state.get("expecting_reveal"))  # noqa: SLF001
            try:
                chain_ok = verifier.observe(req.canary_commitment, req.canary_reveal)
            except CanaryChainError as exc:
                reasons.append(f"canary_chain_error:{exc}")
                chain_ok = False
            if not chain_ok:
                reasons.append("canary_chain_broken")

            if reasons:
                return HeartbeatValidationResult(ok=False, reasons=reasons)

            new_state = {
                "last_commitment": verifier._last_commitment,  # noqa: SLF001
                "expecting_reveal": verifier._expecting_reveal,  # noqa: SLF001
                "last_interval": req.interval_index,
                "last_seen_at": _iso(now),
                "lapsed": False,
            }
            self.store.put(key, new_state)

            # Learn the authority epoch from the heartbeat channel. Track only the
            # highest seen so a replayed older heartbeat cannot lower it.
            if req.authority_epoch is not None:
                prior = self._highest_epoch.get(req.subject_did)
                if prior is None or req.authority_epoch > prior:
                    self._highest_epoch[req.subject_did] = req.authority_epoch

        voucher = build_session_voucher(
            subject_did=req.subject_did,
            validator_dids=[self.validator_did],
            decay_lambda=self.decay_lambda,
            initial_trust=self.initial_trust,
            max_ttl_seconds=self.max_ttl_seconds,
            scope=list(self.scope),
            valid_seconds=self.voucher_valid_seconds,
            authority_epoch=req.authority_epoch,
            issued_at=now,
        )

        return HeartbeatValidationResult(ok=True, session_voucher=voucher)

    # -- checks ---------------------------------------------------------------

    def _check_signature(self, request: Dict[str, Any], subject_did: str) -> Optional[str]:
        from .verifier import _coerce_any_public_key, _resolve_did_key

        proof = request.get("proof")
        if not isinstance(proof, dict):
            return "signature_missing"
        vm = proof.get("verificationMethod")
        if (
            proof.get("proofPurpose") != "assertionMethod"
            or not isinstance(vm, str)
            or vm.split("#", 1)[0] != subject_did
        ):
            return "signature_invalid"
        key = None
        if self.key_resolver is not None:
            candidate = self.key_resolver(subject_did)
            key = _coerce_any_public_key(candidate) if candidate is not None else None
        if key is None and subject_did.startswith("did:key:"):
            key = _resolve_did_key(subject_did)
        if key is None:
            return "signature_key_unresolved"
        try:
            if not data_integrity.verify_proof(request, key):
                return "signature_invalid"
        except Exception:  # noqa: BLE001 - a malformed proof is an invalid one
            return "signature_invalid"
        return None

    def _check_action_root(self, req: HeartbeatRequest) -> Optional[str]:
        if req.action_leaf_hashes is None:
            return "action_leaf_hashes_missing" if self.require_action_leaf_hashes else None
        try:
            hashes = [_decode_multibase(h) for h in req.action_leaf_hashes]
            if hashes:
                expected = _encode_multibase(root_from_leaf_hashes(hashes))
            else:
                expected = compute_action_merkle_root([])
        except MerkleError:
            return "action_leaf_hashes_invalid"
        if expected != req.action_merkle_root:
            return "action_merkle_root_mismatch"
        return None

    def _missed_intervals(self, state: Dict[str, Any], interval_index: int, now: datetime) -> int:
        """Intervals missed since the last accepted beat, by index and by clock."""
        last_interval = state.get("last_interval")
        last_seen = state.get("last_seen_at")
        missed = 0
        if last_interval is not None:
            missed = max(missed, interval_index - last_interval - 1)
        if last_seen:
            elapsed = (now - _parse_iso(last_seen)).total_seconds()
            if self.interval_seconds > 0:
                missed = max(missed, int(elapsed // self.interval_seconds) - 1)
        return max(missed, 0)

    def known_sessions(self) -> List[str]:
        """Return session keys currently tracked by this validator."""
        return self.store.known_sessions()

    def reset_session(self, subject_did: str, session_id: str) -> None:
        """Drop all state for one session. Useful after a clean shutdown."""
        key = self._session_key(subject_did, session_id)
        with self._lock:
            self.store.delete(key)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(s: str) -> datetime:
    if s.endswith("Z"):
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return datetime.fromisoformat(s).astimezone(timezone.utc)


__all__ = [
    "HEARTBEAT_PROTOCOL_VERSION",
    "HEARTBEAT_REQUEST_TYPE",
    "HeartbeatError",
    "HeartbeatRequest",
    "HeartbeatSession",
    "HeartbeatScheduler",
    "HeartbeatValidator",
    "HeartbeatValidationResult",
    "HeartbeatStoreInterface",
    "MemoryHeartbeatStore",
]
