"""Load and verify an AAT delegation chain.

This module is a thin wrapper around the AAT reference implementation
(``tenuo``, Apache-2.0, https://github.com/tenuo-ai/tenuo). Chain verification
and token derivation are the reference implementation's job -- see
``draft-niyikiza-oauth-attenuating-agent-tokens-01`` Section 6 (derivation) and
Section 7 (the seven-step verification algorithm). Nothing here reimplements
either. What this module adds is:

- a file format for carrying a chain plus its root trust anchor;
- typed, fail-closed failures a caller can branch on;
- an explicit expiry check, because the reference implementation's
  ``Authorizer.verify_chain()`` does not enforce expiry on its own (see
  ``INTEROP-NOTES.md``).

Wire format note: the reference implementation serialises warrants as CBOR, not
as the draft's JWT/JWS encoding. See ``DESIGN.md`` Section 3.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

try:
    from tenuo import Authorizer, PublicKey, Warrant
    from tenuo import exceptions as _tex
except ImportError as exc:  # pragma: no cover - exercised only without the dep
    raise ImportError(
        "The AAT adapter needs the AAT reference implementation. Install it with: pip install tenuo"
    ) from exc


CHAIN_FORMAT_VERSION = 1

__all__ = [
    "AatError",
    "AatMalformedChain",
    "AatBadSignature",
    "AatBrokenChain",
    "AatWidenedScope",
    "AatExpired",
    "AatUntrustedRoot",
    "AatPopMismatch",
    "ChainDocument",
    "VerifiedChain",
    "load_chain_document",
    "verify_chain",
    "verify_chain_file",
]


# ---------------------------------------------------------------------------
# Typed failures
# ---------------------------------------------------------------------------


class AatError(Exception):
    """Base class for every AAT adapter failure.

    Callers that only care 'did this fail' should catch this. Every failure
    path is fail-closed: no rules are produced and no tool runs.
    """


class AatMalformedChain(AatError):
    """The chain file itself is unusable -- missing, bad JSON, wrong shape."""


class AatBadSignature(AatError):
    """A token in the chain is not authentic.

    Covers both a failed signature check and a payload that will not decode.
    The reference implementation rejects a tampered token at CBOR decode,
    before signature verification, so a single flipped byte surfaces here as a
    deserialization failure rather than a signature failure. Both mean the same
    thing to a caller -- these bytes are not the bytes that were signed -- so
    they share one type.
    """


class AatBrokenChain(AatError):
    """Chain structure is invalid: linkage, depth, cycle, or ordering."""


class AatWidenedScope(AatError):
    """A derived token broadens its parent. The narrow-only invariant failed."""


class AatExpired(AatError):
    """A token in the chain has expired."""


class AatUntrustedRoot(AatError):
    """The chain does not anchor to the expected root trust anchor."""


class AatPopMismatch(AatError):
    """Proof-of-possession missing or not valid for this call."""


def _classify(exc: Exception) -> AatError:
    """Translate a reference-implementation exception into a typed failure.

    Ordered most specific first. Anything unrecognised becomes a generic
    ``AatError`` rather than being allowed through -- unknown means deny.
    """
    if isinstance(exc, _tex.UntrustedRoot):
        return AatUntrustedRoot(str(exc))
    if isinstance(exc, _tex.ExpiredError):
        return AatExpired(str(exc))
    if isinstance(exc, _tex.MonotonicityError):
        return AatWidenedScope(str(exc))
    if isinstance(exc, _tex.PopError):
        return AatPopMismatch(str(exc))
    if isinstance(exc, _tex.MissingSignature):
        return AatPopMismatch(str(exc))
    if isinstance(exc, (_tex.SerializationError, _tex.CryptoError)):
        return AatBadSignature(str(exc))
    if isinstance(exc, _tex.ChainError):
        return AatBrokenChain(str(exc))
    return AatError(f"{type(exc).__name__}: {exc}")


# ---------------------------------------------------------------------------
# Chain document
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ChainDocument:
    """An AAT chain as it is carried on disk.

    Public material only. The holder's private key is never part of this file;
    it is supplied separately at invocation time to produce proof-of-possession.
    """

    root_public_key_pem: str
    warrants_b64: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "aat_chain_version": CHAIN_FORMAT_VERSION,
            "root_public_key_pem": self.root_public_key_pem,
            "warrants": list(self.warrants_b64),
        }

    def write(self, path: Union[str, Path]) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2) + "\n")


def load_chain_document(path: Union[str, Path]) -> ChainDocument:
    """Read a chain file. Raises ``AatMalformedChain`` on anything unusable."""
    p = Path(path)
    try:
        raw = json.loads(p.read_text())
    except FileNotFoundError as exc:
        raise AatMalformedChain(f"AAT chain file not found: {p}") from exc
    except json.JSONDecodeError as exc:
        raise AatMalformedChain(f"AAT chain file is not valid JSON: {p}: {exc}") from exc

    if not isinstance(raw, dict):
        raise AatMalformedChain(f"AAT chain file must contain a JSON object: {p}")

    version = raw.get("aat_chain_version")
    if version != CHAIN_FORMAT_VERSION:
        raise AatMalformedChain(
            f"Unsupported aat_chain_version {version!r} in {p} "
            f"(this adapter reads version {CHAIN_FORMAT_VERSION})"
        )

    root_pem = raw.get("root_public_key_pem")
    if not isinstance(root_pem, str) or not root_pem.strip():
        raise AatMalformedChain(f"root_public_key_pem is missing or empty in {p}")

    warrants = raw.get("warrants")
    if not isinstance(warrants, list) or not warrants:
        raise AatMalformedChain(f"warrants must be a non-empty array in {p}")
    if not all(isinstance(w, str) and w for w in warrants):
        raise AatMalformedChain(f"every entry in warrants must be a non-empty string in {p}")

    return ChainDocument(root_public_key_pem=root_pem, warrants_b64=list(warrants))


# ---------------------------------------------------------------------------
# Verified chain
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VerifiedChain:
    """A chain that passed verification, ordered root -> leaf.

    Only ``leaf`` carries the authority that may be exercised. The rest of the
    chain is retained for provenance, not summed: per the draft, a derived
    token's authority is what it says, already narrowed. See ``DESIGN.md``.
    """

    warrants: List[Any]
    root_public_key: Any
    _authorizer: Any

    @property
    def leaf(self) -> Any:
        return self.warrants[-1]

    @property
    def root(self) -> Any:
        return self.warrants[0]

    @property
    def leaf_jti(self) -> str:
        """The leaf token identifier -- the AAT that authorises a given call."""
        return str(self.leaf.id)

    @property
    def root_jti(self) -> str:
        """The chain root identifier."""
        return str(self.root.id)

    @property
    def depth(self) -> int:
        return int(self.leaf.depth)

    @property
    def tools(self) -> List[str]:
        """Tool names the leaf authorises, sorted for stable output."""
        return sorted(str(t) for t in self.leaf.tools)

    @property
    def expires_at(self) -> str:
        """Leaf expiry as an RFC 3339 string."""
        return str(self.leaf.expires_at())

    def capabilities(self) -> Dict[str, Any]:
        """Leaf capabilities as ``{tool: {arg: constraint}}``."""
        return dict(self.leaf.capabilities)


def _parse_rfc3339(value: str) -> datetime:
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return datetime.fromisoformat(text).astimezone(timezone.utc)


def _assert_not_expired(warrants: Sequence[Any], as_of: Optional[datetime]) -> None:
    """Reject any expired token in the chain.

    Done explicitly because ``Authorizer.verify_chain()`` in the reference
    implementation returns success for an expired warrant; expiry is enforced
    only on the authorization call. Relying on ``verify_chain`` alone would
    accept expired authority. Recorded in ``INTEROP-NOTES.md``.
    """
    now = (as_of or datetime.now(timezone.utc)).astimezone(timezone.utc)
    for index, warrant in enumerate(warrants):
        try:
            expiry = _parse_rfc3339(warrant.expires_at())
        except Exception as exc:
            raise AatMalformedChain(
                f"token at position {index} has an unreadable expiry: {exc}"
            ) from exc
        if expiry <= now:
            raise AatExpired(
                f"token at position {index} ({warrant.id}) expired at {warrant.expires_at()}"
            )


def verify_chain(
    document: ChainDocument,
    *,
    as_of: Optional[datetime] = None,
) -> VerifiedChain:
    """Verify a chain against its root trust anchor.

    Returns a :class:`VerifiedChain` ordered root -> leaf, or raises one of the
    typed failures in this module. There is no partial success: a chain either
    verifies whole or yields nothing.
    """
    try:
        root_key = PublicKey.from_pem(document.root_public_key_pem)
    except Exception as exc:
        raise AatMalformedChain(f"root_public_key_pem is not a usable key: {exc}") from exc

    warrants: List[Any] = []
    for index, encoded in enumerate(document.warrants_b64):
        try:
            warrants.append(Warrant.from_base64(encoded))
        except _tex.TenuoError as exc:
            raise _classify(exc) from exc
        except Exception as exc:
            raise AatMalformedChain(
                f"token at position {index} could not be decoded: {exc}"
            ) from exc

    authorizer = Authorizer()
    try:
        authorizer.add_trusted_root(root_key)
    except Exception as exc:
        raise AatMalformedChain(f"root trust anchor rejected: {exc}") from exc

    try:
        authorizer.verify_chain(warrants)
    except _tex.TenuoError as exc:
        raise _classify(exc) from exc
    except Exception as exc:
        raise AatError(f"chain verification failed: {exc}") from exc

    _assert_not_expired(warrants, as_of)

    return VerifiedChain(
        warrants=warrants,
        root_public_key=root_key,
        _authorizer=authorizer,
    )


def verify_chain_file(
    path: Union[str, Path],
    *,
    as_of: Optional[datetime] = None,
) -> VerifiedChain:
    """Load and verify a chain file in one call."""
    return verify_chain(load_chain_document(path), as_of=as_of)
