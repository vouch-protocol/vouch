"""
Vouch Protocol MLflow Integration.

Sign a model artifact with a Vouch Credential at log or registration time, so a
registered model carries verifiable lineage: who registered it, on whose
authority, and a content digest that breaks if the weights are tampered with.

This module has no hard dependency on MLflow. The core helpers operate on a file
or directory path, so they work with any artifact store. If MLflow is installed,
log the returned credential as a tag or artifact on the run.
"""

from __future__ import annotations

import hashlib
import os
from typing import Any, Dict, Optional, Tuple

from vouch import Signer, Verifier

_RESOURCE_PREFIX = "model:sha256:"


def compute_model_digest(path: str) -> str:
    """Return a SHA-256 hex digest over a model file, or a directory of files.

    For a directory, every file is hashed in sorted relative-path order, and the
    relative path is mixed in, so the digest is stable and order-independent.
    """
    h = hashlib.sha256()
    if os.path.isdir(path):
        for root, _dirs, files in os.walk(path):
            for name in sorted(files):
                fp = os.path.join(root, name)
                rel = os.path.relpath(fp, path).replace(os.sep, "/")
                h.update(rel.encode("utf-8"))
                h.update(b"\x00")
                with open(fp, "rb") as f:
                    for chunk in iter(lambda: f.read(65536), b""):
                        h.update(chunk)
    else:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    return h.hexdigest()


def sign_model(
    signer: Signer,
    path: str,
    *,
    name: Optional[str] = None,
    parent_credential: Optional[Dict[str, Any]] = None,
    hybrid: bool = False,
    valid_seconds: Optional[int] = None,
) -> Dict[str, Any]:
    """Issue a Vouch Credential binding the model at ``path`` to the signer.

    The credential's ``resource`` is the model's content digest, so any change to
    the weights breaks verification.

    Args:
        signer: The registering principal's Signer.
        path: Path to the model file or directory.
        name: Human label for the model. Defaults to the basename of ``path``.
        parent_credential: Optional parent credential to extend (delegation).
        hybrid: Issue under the post-quantum hybrid profile when True.
        valid_seconds: Optional validity window override.

    Returns:
        A signed Vouch Credential dict. Log it as an MLflow tag or artifact.
    """
    digest = compute_model_digest(path)
    target = name or os.path.basename(os.path.normpath(path)) or "model"
    intent = {"action": "register", "target": target, "resource": f"{_RESOURCE_PREFIX}{digest}"}
    issue = signer.sign_hybrid if hybrid else signer.sign
    return issue(
        intent=intent,
        parent_credential=parent_credential,
        valid_seconds=valid_seconds,
    )


def verify_model(
    path: str,
    credential: Dict[str, Any],
    public_key: Optional[Any] = None,
) -> Tuple[bool, Optional[Any]]:
    """Verify a model credential AND that the on-disk content still matches.

    Returns ``(is_valid, passport)``. ``is_valid`` is False if the signature
    fails OR the recomputed digest does not match the credential's bound digest.
    """
    ok, passport = Verifier.verify(credential, public_key=public_key)
    if not ok:
        return False, passport
    intent = (credential.get("credentialSubject") or {}).get("intent") or {}
    bound = intent.get("resource")
    if bound != f"{_RESOURCE_PREFIX}{compute_model_digest(path)}":
        return False, passport
    return True, passport
