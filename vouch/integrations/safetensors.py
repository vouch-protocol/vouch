"""
Vouch Protocol safetensors Integration.

Embed a Vouch Credential in a .safetensors file's existing ``__metadata__``
header field, with zero changes to the safetensors format or its Rust core.

This is deliberately complementary to OpenSSF Model Signing (OMS). OMS proves an
artifact is intact and signed by a key. Vouch adds the agent and delegation
dimension: which principal or pipeline produced the weights, traceable back to an
accountable human. The credential is bound to a SHA-256 of the tensor data
buffer, so any change to the weights breaks verification. Standard loaders
(including Hugging Face) ignore the extra metadata key, so signed files load
normally.
"""

from __future__ import annotations

import hashlib
import json
import struct
from typing import Any, Dict, Optional, Tuple

from vouch import Signer, Verifier

_META_KEY = "vouch_credential"
_RESOURCE_PREFIX = "model:safetensors:sha256:"


def _read(path: str) -> Tuple[Dict[str, Any], bytes]:
    """Return (header_dict, tensor_data_bytes) from a safetensors file."""
    with open(path, "rb") as f:
        header_len = struct.unpack("<Q", f.read(8))[0]
        header = json.loads(f.read(header_len).decode("utf-8"))
        data = f.read()
    return header, data


def _write(path: str, header: Dict[str, Any], data: bytes) -> None:
    """Write a safetensors file from a header dict and the tensor data buffer."""
    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    with open(path, "wb") as f:
        f.write(struct.pack("<Q", len(header_bytes)))
        f.write(header_bytes)
        f.write(data)


def tensor_data_digest(path: str) -> str:
    """Return the SHA-256 hex digest of the tensor data buffer (excludes header)."""
    _header, data = _read(path)
    return hashlib.sha256(data).hexdigest()


def sign_safetensors(
    signer: Signer,
    path: str,
    *,
    out_path: Optional[str] = None,
    name: Optional[str] = None,
    parent_credential: Optional[Dict[str, Any]] = None,
    hybrid: bool = False,
    valid_seconds: Optional[int] = None,
) -> Dict[str, Any]:
    """Embed a Vouch Credential in a safetensors file's ``__metadata__``.

    The credential binds to a digest of the tensor data buffer. The header gains
    one string key; the tensor bytes are untouched.

    Args:
        signer: The producing principal's Signer.
        path: Path to the input .safetensors file.
        out_path: Where to write the signed file. Defaults to ``path`` (in place).
        name: Human label for the model.
        parent_credential: Optional parent credential to extend (delegation).
        hybrid: Issue under the post-quantum hybrid profile when True.
        valid_seconds: Optional validity window override.

    Returns:
        The signed Vouch Credential dict (also embedded in the file).
    """
    header, data = _read(path)
    digest = hashlib.sha256(data).hexdigest()
    intent = {
        "action": "register",
        "target": name or "safetensors-model",
        "resource": f"{_RESOURCE_PREFIX}{digest}",
    }
    issue = signer.sign_hybrid if hybrid else signer.sign
    credential = issue(
        intent=intent,
        parent_credential=parent_credential,
        valid_seconds=valid_seconds,
    )
    metadata = dict(header.get("__metadata__") or {})
    metadata[_META_KEY] = json.dumps(credential, separators=(",", ":"))
    header["__metadata__"] = metadata
    _write(out_path or path, header, data)
    return credential


def read_embedded_credential(path: str) -> Optional[Dict[str, Any]]:
    """Return the embedded Vouch Credential, or None if the file is unsigned."""
    header, _data = _read(path)
    raw = (header.get("__metadata__") or {}).get(_META_KEY)
    return json.loads(raw) if raw else None


def verify_safetensors(
    path: str,
    public_key: Optional[Any] = None,
) -> Tuple[bool, Optional[Any]]:
    """Verify a signed safetensors file: signature AND tensor-data integrity.

    Returns ``(is_valid, passport)``. ``is_valid`` is False if the file is
    unsigned, the signature fails, or the tensor data no longer matches the
    bound digest.
    """
    credential = read_embedded_credential(path)
    if not credential:
        return False, None
    ok, passport = Verifier.verify(credential, public_key=public_key)
    if not ok:
        return False, passport
    bound = (credential.get("credentialSubject") or {}).get("intent", {}).get("resource")
    if bound != f"{_RESOURCE_PREFIX}{tensor_data_digest(path)}":
        return False, passport
    return True, passport
