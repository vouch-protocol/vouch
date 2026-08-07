"""
The node's ROS parameter table, and the parameters-to-core factory.

Kept free of rclpy so the whole configuration path -- scope, key material,
topic names -- is unit testable without ROS installed. ``PARAMETERS`` is the
single source of truth: the node declares exactly these, and
:func:`core_from_params` consumes exactly these.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

from .core import (
    ActionGateCore,
    ActionGateError,
    build_scope,
    load_blackbox_key,
    load_signer,
    multibase_sha256,
)

#: (name, default) for every parameter the node declares. Order is declaration
#: order. A negative numeric default means "this dimension is unbounded".
PARAMETERS: Tuple[Tuple[str, Any], ...] = (
    # Topics
    ("proposed_action_topic", "planner/proposed_action"),
    ("allowed_action_topic", "actuator/action"),
    ("denial_topic", "vouch/denials"),
    ("provenance_topic", "vouch/provenance"),
    ("blackbox_head_topic", "vouch/blackbox_head"),
    ("queue_depth", 10),
    # Physical capability scope
    ("scope.max_force_n", 80.0),
    ("scope.max_speed_mps", 1.5),
    ("scope.max_speed_near_humans_mps", 0.5),
    ("scope.allowed_zones", ["cell-3"]),
    ("scope.shift_windows_json", ""),
    # Robot key material
    ("identity.did", ""),
    ("identity.private_key_jwk", ""),
    # Black box
    ("blackbox.key_hex", ""),
    ("blackbox.key_file", ""),
    ("blackbox.log_path", ""),
    # Planner / model provenance
    ("model.name", "unnamed-planner"),
    ("model.version", ""),
    ("model.weights_hash", ""),
    ("model.weights_file", ""),
    ("model.safety_policy", ""),
    ("model.config_json", "{}"),
    # Behaviour
    ("stamp_time_from_clock", False),
)

PARAMETER_DEFAULTS: Dict[str, Any] = dict(PARAMETERS)


def defaults() -> Dict[str, Any]:
    """A fresh copy of the default parameter set."""
    return {name: (list(value) if isinstance(value, list) else value) for name, value in PARAMETERS}


def _json_param(params: Dict[str, Any], name: str, fallback: Any) -> Any:
    raw = params.get(name, PARAMETER_DEFAULTS.get(name, ""))
    if raw in ("", None):
        return fallback
    try:
        return json.loads(raw) if isinstance(raw, str) else raw
    except json.JSONDecodeError as exc:
        raise ActionGateError(f"parameter {name!r} is not valid JSON: {exc}") from exc


def _shift_windows(params: Dict[str, Any]) -> Optional[List[Dict[str, str]]]:
    windows = _json_param(params, "scope.shift_windows_json", None)
    if windows is None:
        return None
    if not isinstance(windows, list) or not all(isinstance(w, dict) for w in windows):
        raise ActionGateError(
            "scope.shift_windows_json must be a JSON list of "
            '{"start": "HH:MM", "end": "HH:MM"} objects'
        )
    return [{str(k): str(v) for k, v in w.items()} for w in windows]


def scope_from_params(params: Dict[str, Any]) -> Dict[str, Any]:
    """Build the physicalScope object the gate checks against."""
    return build_scope(
        max_force_n=params.get("scope.max_force_n"),
        max_speed_mps=params.get("scope.max_speed_mps"),
        max_speed_near_humans_mps=params.get("scope.max_speed_near_humans_mps"),
        allowed_zones=params.get("scope.allowed_zones"),
        shift_windows=_shift_windows(params),
    )


def weights_hash_from_params(params: Dict[str, Any]) -> str:
    """
    Resolve the model weights hash.

    ``model.weights_hash`` wins when set. Otherwise ``model.weights_file`` is
    hashed here, so the attestation covers the bytes actually on disk. With
    neither, the model name is hashed as a placeholder -- enough to make the
    attestation well formed, not enough to prove which weights ran, so the node
    warns.
    """
    recorded = params.get("model.weights_hash") or ""
    if recorded:
        return str(recorded)
    weights_file = params.get("model.weights_file") or ""
    if weights_file:
        import hashlib

        digest = hashlib.sha256()
        with open(weights_file, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        import base64

        return "u" + base64.urlsafe_b64encode(digest.digest()).rstrip(b"=").decode("ascii")
    return multibase_sha256(f"unverified-weights:{params.get('model.name', '')}".encode("utf-8"))


def warnings_for(params: Dict[str, Any]) -> List[str]:
    """Operational warnings the node should log at startup. Never fatal."""
    notes: List[str] = []
    if not params.get("identity.private_key_jwk") or not params.get("identity.did"):
        notes.append(
            "no identity.did / identity.private_key_jwk set: signing the provenance "
            "attestation with an ephemeral key, which nobody can verify after this "
            "process exits"
        )
    if not params.get("blackbox.key_hex") and not params.get("blackbox.key_file"):
        notes.append(
            "no blackbox.key_hex / blackbox.key_file set: the black box is sealed with "
            "an ephemeral key, so the chain stays verifiable but the payloads become "
            "unreadable after this process exits"
        )
    if not params.get("model.weights_hash") and not params.get("model.weights_file"):
        notes.append(
            "no model.weights_hash / model.weights_file set: the provenance attestation "
            "records a placeholder digest and does not bind the weights actually loaded"
        )
    if not params.get("model.safety_policy"):
        notes.append("no model.safety_policy set: recording a placeholder policy identifier")
    if not params.get("blackbox.log_path"):
        notes.append("no blackbox.log_path set: black-box entries are held in memory only")
    return notes


def core_from_params(
    params: Dict[str, Any], *, clock: Any = None
) -> Tuple[ActionGateCore, Dict[str, Any]]:
    """
    Build an :class:`ActionGateCore` from a flat parameter mapping.

    Returns ``(core, info)`` where ``info`` carries the resolved DID, scope,
    and startup warnings the node logs.
    """
    merged = defaults()
    merged.update({k: v for k, v in params.items() if v is not None})

    scope = scope_from_params(merged)
    signer, did, public_key_jwk = load_signer(
        str(merged.get("identity.private_key_jwk") or ""),
        str(merged.get("identity.did") or ""),
    )
    blackbox_key = load_blackbox_key(
        str(merged.get("blackbox.key_hex") or ""),
        str(merged.get("blackbox.key_file") or ""),
    )
    model_config = _json_param(merged, "model.config_json", {})
    if not isinstance(model_config, dict):
        raise ActionGateError("model.config_json must be a JSON object")

    safety_policy = str(merged.get("model.safety_policy") or "") or multibase_sha256(
        b"unspecified-safety-policy"
    )

    core = ActionGateCore(
        signer=signer,
        robot_did=did,
        scope=scope,
        model_name=str(merged.get("model.name") or "unnamed-planner"),
        weights_hash=weights_hash_from_params(merged),
        safety_policy=safety_policy,
        model_config=model_config,
        model_version=str(merged.get("model.version") or "") or None,
        public_key_jwk=public_key_jwk,
        blackbox_key=blackbox_key,
        blackbox_path=str(merged.get("blackbox.log_path") or ""),
        clock=clock if merged.get("stamp_time_from_clock") else None,
    )
    info = {
        "did": did,
        "scope": scope,
        "warnings": warnings_for(merged),
        "params": merged,
    }
    return core, info


__all__ = [
    "PARAMETERS",
    "PARAMETER_DEFAULTS",
    "core_from_params",
    "defaults",
    "scope_from_params",
    "warnings_for",
    "weights_hash_from_params",
]
