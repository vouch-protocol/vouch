"""Append-only audit log of credentials emitted by the agent.

Each line is one JSON record. We persist a credential summary (id, issuer,
intent, validFrom, proofType) and a digest of the full credential. The
full credential is also written to a sidecar file keyed by id so it can
be retrieved on demand, but the main log is small enough to tail.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import CONFIG


def _summary(credential: dict[str, Any]) -> dict[str, Any]:
    proof = credential.get("proof", {})
    return {
        "id": credential.get("id"),
        "issuer": credential.get("issuer"),
        "validFrom": credential.get("validFrom"),
        "validUntil": credential.get("validUntil"),
        "intent": credential.get("credentialSubject", {}).get("intent"),
        "cryptosuite": proof.get("cryptosuite"),
        "verificationMethod": proof.get("verificationMethod"),
        "digest": hashlib.sha256(json.dumps(credential, sort_keys=True).encode()).hexdigest(),
        "recorded_at": datetime.now(timezone.utc).isoformat(),
    }


def record(credential: dict[str, Any]) -> dict[str, Any]:
    log_path = CONFIG.audit_log_path
    log_path.parent.mkdir(parents=True, exist_ok=True)
    entry = _summary(credential)
    with log_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


def recent(limit: int = 50) -> list[dict[str, Any]]:
    log_path = CONFIG.audit_log_path
    if not log_path.exists():
        return []
    lines = log_path.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines[-limit:]]


def clear() -> None:
    if CONFIG.audit_log_path.exists():
        CONFIG.audit_log_path.unlink()
