"""
The Vouch accountability core for a ROS 2 action gate -- plain Python, no ROS.

This module holds every decision the gate makes, so the logic can be unit
tested with pytest alone: no rclpy, no DDS, no physical robot. The ROS node in
``vouch_ros2.node`` is a thin shell that moves messages in and out of this
class and owns nothing else.

The loop mirrors ``examples/robotics_vla_accountability_loop.py``:

  1. Provenance on load: :class:`ActionGateCore` signs a
     ModelProvenanceAttestation for the planner/model in use before it will
     gate anything, and re-verifies it against its own public key.
  2. Pre-actuation scope gate: every proposed action is checked with
     ``check_physical_action`` against a signed PhysicalCapabilityScope. Only
     allowed actions are handed back for republication to the actuators.
  3. Tamper-evident black box: every decision, allowed or denied, is appended
     to a hash-linked, encrypted :class:`BlackBoxLog`.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from vouch import Signer, generate_identity
from vouch.robotics import (
    BlackBoxLog,
    PhysicalAction,
    build_physical_scope_credential,
    build_provenance_attestation,
    check_physical_action,
    verify_blackbox_chain,
    verify_provenance_attestation,
)

ALLOWED_EVENT = "actuation_allowed"
DENIED_EVENT = "actuation_denied"
PROVENANCE_EVENT = "provenance_recorded"

#: Fields a proposed-action payload may carry. Anything else is ignored.
ACTION_FIELDS = ("action_id", "task", "force_n", "speed_mps", "near_humans", "zone", "time_hm")


class ActionGateError(Exception):
    """Raised on malformed gate configuration or an unparsable action payload."""


def multibase_sha256(data: bytes) -> str:
    """Multibase (base64url) SHA-256, the hash form Vouch credentials carry."""
    digest = hashlib.sha256(data).digest()
    return "u" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


@dataclass
class ProposedAction:
    """One action a planner proposes, before the gate has ruled on it."""

    action_id: str = ""
    task: str = ""
    force_n: Optional[float] = None
    speed_mps: Optional[float] = None
    near_humans: bool = False
    zone: Optional[str] = None
    time_hm: Optional[str] = None
    #: The verbatim payload, republished unchanged when the action is allowed.
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_physical_action(self) -> PhysicalAction:
        """The ``PhysicalAction`` the scope gate checks."""
        return PhysicalAction(
            force_n=self.force_n,
            speed_mps=self.speed_mps,
            near_humans=self.near_humans,
            zone=self.zone,
            time_hm=self.time_hm,
        )


@dataclass
class Decision:
    """The gate's ruling on one proposed action, plus its black-box entry."""

    action: ProposedAction
    allowed: bool
    reasons: List[str]
    entry: Dict[str, Any]

    @property
    def event(self) -> str:
        return ALLOWED_EVENT if self.allowed else DENIED_EVENT

    def actuator_payload(self) -> Dict[str, Any]:
        """What to republish on the actuator topic. Allowed actions only."""
        if not self.allowed:
            raise ActionGateError("denied actions are never republished to actuators")
        payload = dict(self.action.raw)
        payload["vouchEntryHash"] = self.entry["entryHash"]
        return payload

    def denial_payload(self) -> Dict[str, Any]:
        """What to publish on the denial topic. Denied actions only."""
        if self.allowed:
            raise ActionGateError("allowed actions carry no denial payload")
        return {
            "actionId": self.action.action_id,
            "task": self.action.task,
            "zone": self.action.zone,
            "speedMps": self.action.speed_mps,
            "forceN": self.action.force_n,
            "nearHumans": self.action.near_humans,
            "reasons": list(self.reasons),
            "vouchEntryHash": self.entry["entryHash"],
        }


def parse_action(payload: Any) -> ProposedAction:
    """
    Parse a proposed-action payload into a :class:`ProposedAction`.

    Accepts a JSON string (what the node receives on a ``std_msgs/String``
    topic) or an already-decoded mapping. Unknown keys are preserved in ``raw``
    so the actuator republication is byte-for-byte the planner's own message
    plus the black-box entry hash.
    """
    if isinstance(payload, (bytes, bytearray)):
        payload = payload.decode("utf-8")
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise ActionGateError(f"proposed action is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ActionGateError(
            f"proposed action must be a JSON object, got {type(payload).__name__}"
        )

    def _num(key: str) -> Optional[float]:
        value = payload.get(key, payload.get(_camel(key)))
        if value is None or value == "":
            return None
        try:
            return float(value)
        except (TypeError, ValueError) as exc:
            raise ActionGateError(f"field {key!r} is not a number: {value!r}") from exc

    def _str(key: str) -> Optional[str]:
        value = payload.get(key, payload.get(_camel(key)))
        return None if value is None else str(value)

    return ProposedAction(
        action_id=_str("action_id") or "",
        task=_str("task") or "",
        force_n=_num("force_n"),
        speed_mps=_num("speed_mps"),
        near_humans=bool(payload.get("near_humans", payload.get("nearHumans", False))),
        zone=_str("zone"),
        time_hm=_str("time_hm"),
        raw=dict(payload),
    )


def _camel(snake: str) -> str:
    head, *rest = snake.split("_")
    return head + "".join(part.title() for part in rest)


def build_scope(
    *,
    max_force_n: Optional[float] = None,
    max_speed_mps: Optional[float] = None,
    max_speed_near_humans_mps: Optional[float] = None,
    allowed_zones: Optional[Sequence[str]] = None,
    shift_windows: Optional[Sequence[Dict[str, str]]] = None,
) -> Dict[str, Any]:
    """
    Build a bare physicalScope object from flat parameters.

    A negative cap means "unset": ROS 2 parameters have no null, so a launch
    file signals "do not bound this dimension" with a negative number.
    """
    scope: Dict[str, Any] = {}
    if max_force_n is not None and max_force_n >= 0:
        scope["maxForceN"] = float(max_force_n)
    if max_speed_mps is not None and max_speed_mps >= 0:
        scope["maxSpeedMps"] = float(max_speed_mps)
    if max_speed_near_humans_mps is not None and max_speed_near_humans_mps >= 0:
        scope["maxSpeedNearHumansMps"] = float(max_speed_near_humans_mps)
    if allowed_zones:
        scope["allowedZones"] = [str(zone) for zone in allowed_zones]
    if shift_windows:
        scope["shiftWindows"] = [dict(window) for window in shift_windows]
    if not scope:
        raise ActionGateError(
            "physical scope is empty: an unbounded gate would allow every action; "
            "set at least one of max_force_n / max_speed_mps / "
            "max_speed_near_humans_mps / allowed_zones / shift_windows"
        )
    return scope


def load_signer(private_key_jwk: str = "", did: str = "") -> Tuple[Signer, str, str]:
    """
    Build the robot's signer. Returns ``(signer, did, public_key_jwk)``.

    With no key material an ephemeral identity is generated so a bench run
    works out of the box; the caller is expected to say so loudly, since an
    ephemeral key makes the attestation unverifiable after the process exits.
    """
    if private_key_jwk and did:
        signer = Signer(private_key=private_key_jwk, did=did)
        try:
            public_key_jwk = signer.get_public_key_jwk()
        except Exception:  # noqa: BLE001 - a backend may not expose the public JWK
            public_key_jwk = ""
        if not isinstance(public_key_jwk, str):
            public_key_jwk = json.dumps(public_key_jwk)
        return signer, did, public_key_jwk
    if private_key_jwk or did:
        raise ActionGateError("identity.private_key_jwk and identity.did must be set together")
    keypair = generate_identity(domain="robot.local")
    return (
        Signer(private_key=keypair.private_key_jwk, did=keypair.did),
        keypair.did,
        keypair.public_key_jwk,
    )


def load_blackbox_key(key_hex: str = "", key_file: str = "") -> bytes:
    """
    Resolve the 32-byte AES-256 black-box key from a hex parameter or a file.

    With neither set an ephemeral key is generated: the chain is still
    tamper-evident to anyone, but nobody can decrypt the payloads afterwards.
    """
    if key_hex and key_file:
        raise ActionGateError("set blackbox.key_hex or blackbox.key_file, not both")
    if key_file:
        with open(key_file, "rb") as handle:
            raw = handle.read().strip()
        key_hex = raw.decode("ascii")
    if not key_hex:
        return os.urandom(32)
    try:
        key = binascii.unhexlify(key_hex)
    except (binascii.Error, ValueError) as exc:
        raise ActionGateError(f"black-box key is not valid hex: {exc}") from exc
    if len(key) != 32:
        raise ActionGateError(f"black-box key must be 32 bytes (64 hex chars), got {len(key)}")
    return key


class ActionGateCore:
    """
    The accountability loop, with no ROS in it.

    On construction it signs (and re-verifies) a ModelProvenanceAttestation for
    the planner in use and opens a black box. :meth:`evaluate` then gates one
    proposed action, records the decision, and reports whether the action may
    reach the actuators.
    """

    def __init__(
        self,
        *,
        signer: Signer,
        robot_did: str,
        scope: Dict[str, Any],
        model_name: str,
        weights_hash: str,
        safety_policy: str,
        model_config: Optional[Dict[str, Any]] = None,
        model_version: Optional[str] = None,
        public_key_jwk: Any = None,
        blackbox_key: Optional[bytes] = None,
        blackbox_path: str = "",
        clock: Optional[Callable[[], str]] = None,
    ) -> None:
        if not scope:
            raise ActionGateError("refusing to gate against an empty physical scope")
        self.signer = signer
        self.robot_did = robot_did
        self.scope = dict(scope)
        self.model_config = dict(model_config) if model_config is not None else None
        self._clock = clock
        self._blackbox_path = blackbox_path

        self.provenance = build_provenance_attestation(
            signer,
            robot_did=robot_did,
            model_name=model_name,
            weights_hash=weights_hash,
            safety_policy=safety_policy,
            config=self.model_config,
            version=model_version,
        )
        self.provenance_verified = False
        if public_key_jwk:
            self.provenance_verified, _subject = verify_provenance_attestation(
                self.provenance, public_key_jwk, config=self.model_config
            )

        self.blackbox = BlackBoxLog(key=blackbox_key or os.urandom(32))
        self._decisions: List[Decision] = []
        self._append(
            PROVENANCE_EVENT,
            {
                "robotDid": robot_did,
                "modelName": model_name,
                "weightsHash": weights_hash,
                "safetyPolicy": safety_policy,
                "provenanceVerified": self.provenance_verified,
                "scope": self.scope,
            },
        )

    # -- gating ------------------------------------------------------------

    def evaluate(self, payload: Any) -> Decision:
        """
        Gate one proposed action and record the decision in the black box.

        ``payload`` is a JSON string, a mapping, or a :class:`ProposedAction`.
        """
        action = payload if isinstance(payload, ProposedAction) else parse_action(payload)
        if action.time_hm is None and self._clock is not None:
            action.time_hm = self._clock()

        result = check_physical_action(self.scope, action.to_physical_action())
        entry = self._append(
            ALLOWED_EVENT if result.ok else DENIED_EVENT,
            {
                "actionId": action.action_id,
                "task": action.task,
                "zone": action.zone,
                "forceN": action.force_n,
                "speedMps": action.speed_mps,
                "nearHumans": action.near_humans,
                "timeHm": action.time_hm,
                "reasons": list(result.reasons),
            },
        )
        decision = Decision(
            action=action, allowed=result.ok, reasons=list(result.reasons), entry=entry
        )
        self._decisions.append(decision)
        return decision

    # -- black box ---------------------------------------------------------

    def _append(self, event: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        entry = self.blackbox.append(event, payload)
        if self._blackbox_path:
            with open(self._blackbox_path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry

    def entries(self) -> List[Dict[str, Any]]:
        return self.blackbox.entries()

    def head(self) -> str:
        return self.blackbox.head()

    def verify_chain(self) -> Tuple[bool, Optional[str]]:
        """Verify the black-box hash chain. Needs no key: tamper-evidence is public."""
        return verify_blackbox_chain(self.blackbox.entries())

    def decisions(self) -> List[Decision]:
        return list(self._decisions)

    def counts(self) -> Dict[str, int]:
        allowed = sum(1 for d in self._decisions if d.allowed)
        return {"allowed": allowed, "denied": len(self._decisions) - allowed}


def build_scope_credential(
    signer: Signer, *, subject_did: str, scope: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Self-issue a signed PhysicalCapabilityScope credential from a scope object.

    A fleet deployment loads a scope credential issued by the fleet authority
    instead; this exists so a bench or launch-file run still has a signed,
    publishable scope rather than a bare dict.
    """
    return build_physical_scope_credential(
        signer,
        subject_did=subject_did,
        max_force_n=scope.get("maxForceN"),
        max_speed_mps=scope.get("maxSpeedMps"),
        max_speed_near_humans_mps=scope.get("maxSpeedNearHumansMps"),
        allowed_zones=scope.get("allowedZones"),
        shift_windows=scope.get("shiftWindows"),
    )


def scope_from_credential(credential: Dict[str, Any]) -> Dict[str, Any]:
    """Pull the physicalScope object out of a PhysicalCapabilityScope credential."""
    try:
        return dict(credential["credentialSubject"]["physicalScope"])
    except (KeyError, TypeError) as exc:
        raise ActionGateError("credential has no credentialSubject.physicalScope") from exc


__all__ = [
    "ALLOWED_EVENT",
    "DENIED_EVENT",
    "PROVENANCE_EVENT",
    "ActionGateCore",
    "ActionGateError",
    "Decision",
    "ProposedAction",
    "build_scope",
    "build_scope_credential",
    "load_blackbox_key",
    "load_signer",
    "multibase_sha256",
    "parse_action",
    "scope_from_credential",
]
