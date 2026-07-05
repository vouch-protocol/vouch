"""
FROST(Ed25519, SHA-512) threshold signing (RFC 9591).

A key is split among ``max_signers`` participants so that any ``min_signers``
of them can produce a signature together, WITHOUT the full private key ever
being reconstructed at any point, not even during signing. This is distinct
from :mod:`vouch.recovery` (Shamir secret sharing), where the secret IS
reconstructed at recovery time; FROST is for live, repeated signing across a
threshold of custodians, and the key never exists whole anywhere.

The critical property that makes this a drop-in fit for Vouch: the aggregated
signature is a STANDARD Ed25519 signature, so it verifies with the existing
:meth:`vouch.verifier.Verifier.verify` and needs no new proof type
or verifier. Combine it with :meth:`vouch.signer.Signer.from_backend` to get a
``Signer`` whose "sign callback" runs a threshold-signing ceremony instead of
holding a raw key::

    generated = generate_key(min_signers=2, max_signers=3)
    threshold_signer = ThresholdSigner(generated.shares[:2], generated.group_public_key)
    signer = Signer.from_backend(
        did="did:web:agent.example",
        public_key=generated.group_public_key.public_key_jwk,
        sign=threshold_signer.sign,
    )
    credential = signer.sign(action="read", target="t", resource="https://x/y")

The cryptography is not implemented here: this module is a thin ctypes binding
over the same audited Rust core (`frost-ed25519`, the Zcash Foundation crate,
RFC 9591) that backs the Go, JVM, .NET, C++, and Swift SDKs, so every language
produces byte-identical results from one implementation. It requires the
native ``vouch_core_uniffi`` shared library to be available (see
:func:`_load_library`); if it cannot be found, calling any function in this
module raises a clear ``RuntimeError`` rather than falling back to a
hand-written implementation of threshold cryptography.

There is deliberately no "reconstruct" function here. Nothing in this module
takes key shares and returns a seed or a private scalar.
"""

from __future__ import annotations

import base64
import ctypes
import ctypes.util
import json
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from vouch import multikey


class ThresholdError(RuntimeError):
    """Raised when the native FROST core is unavailable or a call fails."""


_LIB: Optional[ctypes.CDLL] = None
_LIB_LOAD_ATTEMPTED = False

_LIB_BASENAMES = {
    "linux": "libvouch_core_uniffi.so",
    "darwin": "libvouch_core_uniffi.dylib",
    "win32": "vouch_core_uniffi.dll",
}


def _candidate_paths() -> List[str]:
    """Where to look for the native core, in order of preference."""
    candidates: List[str] = []

    env_path = os.getenv("VOUCH_CORE_LIB")
    if env_path:
        candidates.append(env_path)

    import sys

    basename = _LIB_BASENAMES.get(sys.platform, _LIB_BASENAMES["linux"])

    # Development layout: this file lives in <repo>/vouch/threshold.py, and the
    # freshly built core sits at <repo>/core/uniffi/target/{release,debug}/.
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(here)
    for profile in ("release", "debug"):
        candidates.append(os.path.join(repo_root, "core", "uniffi", "target", profile, basename))

    return candidates


def _load_library() -> ctypes.CDLL:
    global _LIB, _LIB_LOAD_ATTEMPTED
    if _LIB is not None:
        return _LIB
    if _LIB_LOAD_ATTEMPTED:
        raise ThresholdError(_not_found_message())
    _LIB_LOAD_ATTEMPTED = True

    for path in _candidate_paths():
        if path and os.path.exists(path):
            try:
                _LIB = ctypes.CDLL(path)
                _configure_signatures(_LIB)
                return _LIB
            except OSError:
                continue

    found = ctypes.util.find_library("vouch_core_uniffi")
    if found:
        try:
            _LIB = ctypes.CDLL(found)
            _configure_signatures(_LIB)
            return _LIB
        except OSError:
            pass

    raise ThresholdError(_not_found_message())


def _not_found_message() -> str:
    return (
        "vouch.threshold requires the native vouch_core_uniffi library "
        "(the audited FROST-Ed25519 core shared with the Go/JVM/.NET/C++/Swift "
        "SDKs). Build it with `cargo build --release` in core/uniffi, or set "
        "VOUCH_CORE_LIB to the shared library path."
    )


def _configure_signatures(lib: ctypes.CDLL) -> None:
    lib.vouch_string_free.argtypes = [ctypes.c_char_p]
    lib.vouch_string_free.restype = None

    lib.vouch_threshold_generate_key.argtypes = [
        ctypes.c_uint16,
        ctypes.c_uint16,
        ctypes.POINTER(ctypes.c_char_p),
    ]
    lib.vouch_threshold_generate_key.restype = ctypes.c_void_p

    lib.vouch_threshold_commit.argtypes = [
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_char_p),
    ]
    lib.vouch_threshold_commit.restype = ctypes.c_void_p

    lib.vouch_threshold_sign_share.argtypes = [
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_char_p),
    ]
    lib.vouch_threshold_sign_share.restype = ctypes.c_void_p

    lib.vouch_threshold_aggregate.argtypes = [
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_char_p),
    ]
    lib.vouch_threshold_aggregate.restype = ctypes.c_void_p


def _take_string(lib: ctypes.CDLL, result: Optional[int], err_out: ctypes.c_char_p) -> str:
    """Read a heap C string returned by the core, freeing it. Raises on NULL."""
    if not result:
        message = err_out.value.decode("utf-8") if err_out.value else "unknown error"
        if err_out.value:
            lib.vouch_string_free(err_out)
        raise ThresholdError(message)
    s = ctypes.cast(result, ctypes.c_char_p).value
    text = s.decode("utf-8") if s is not None else ""
    lib.vouch_string_free(ctypes.cast(result, ctypes.c_char_p))
    return text


def _call(fn_name: str, *args: Any) -> str:
    lib = _load_library()
    fn = getattr(lib, fn_name)
    err_out = ctypes.c_char_p()
    result = fn(*args, ctypes.byref(err_out))
    return _take_string(lib, result, err_out)


@dataclass
class KeyShare:
    """One participant's share of a threshold key. Secret; keep it only on the
    participant it was issued to."""

    identifier: str  # base64
    key_package: str  # base64, SECRET

    def to_json(self) -> str:
        return json.dumps({"identifier": self.identifier, "key_package": self.key_package})

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "KeyShare":
        return cls(identifier=d["identifier"], key_package=d["key_package"])


@dataclass
class GroupPublicKey:
    """The threshold group's public identity."""

    verifying_key: str  # base64, 32 bytes: a standard Ed25519 public key
    public_key_package: str  # base64, needed to aggregate

    @property
    def public_key_jwk(self) -> str:
        """The group public key as a JWK JSON string, for
        :meth:`vouch.signer.Signer.from_backend` or any other Vouch API that
        takes a public key."""
        raw = base64.standard_b64decode(self.verifying_key)
        x = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
        return json.dumps({"kty": "OKP", "crv": "Ed25519", "x": x})

    @property
    def public_key_multikey(self) -> str:
        """The group public key as a Multikey (z-prefixed) string."""
        raw = base64.standard_b64decode(self.verifying_key)
        return multikey.encode_ed25519_public(raw)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "GroupPublicKey":
        return cls(verifying_key=d["verifying_key"], public_key_package=d["public_key_package"])


@dataclass
class GenerateKeyResult:
    shares: List[KeyShare]
    group_public_key: GroupPublicKey


def generate_key(min_signers: int, max_signers: int) -> GenerateKeyResult:
    """Mint a fresh threshold-native Ed25519 identity.

    Returns ``max_signers`` key shares, any ``min_signers`` of which can sign
    together, and the group's public key. This mints a NEW identity; it does
    not convert an existing single-key Ed25519 identity (see
    :mod:`vouch.threshold`'s module docstring for why).
    """
    raw = _call("vouch_threshold_generate_key", min_signers, max_signers)
    data = json.loads(raw)
    return GenerateKeyResult(
        shares=[KeyShare.from_dict(s) for s in data["shares"]],
        group_public_key=GroupPublicKey.from_dict(data["group_public_key"]),
    )


@dataclass
class Round1:
    nonces: str  # base64, SECRET, single-use
    commitments: str  # base64, public


def commit(key_share: KeyShare) -> Round1:
    """Round 1: a signer generates its single-use nonces and public
    commitment. ``nonces`` MUST be used for exactly one :func:`sign_share` call
    and then discarded; reusing them leaks the signer's key share."""
    raw = _call("vouch_threshold_commit", key_share.to_json().encode("utf-8"))
    data = json.loads(raw)
    return Round1(nonces=data["nonces"], commitments=data["commitments"])


def sign_share(
    message: bytes,
    key_share: KeyShare,
    nonces: str,
    commitments_by_participant: Dict[str, str],
) -> str:
    """Round 2: given the message and every participating signer's
    commitment, this signer produces its signature share (base64) using its
    own key share and its own (single-use) nonces from :func:`commit`.
    ``commitments_by_participant`` maps each participant's base64 identifier to
    its base64 commitment, including this signer's own."""
    return _call(
        "vouch_threshold_sign_share",
        base64.standard_b64encode(message),
        key_share.to_json().encode("utf-8"),
        nonces.encode("utf-8"),
        json.dumps(commitments_by_participant).encode("utf-8"),
    )


def aggregate(
    message: bytes,
    commitments_by_participant: Dict[str, str],
    shares_by_participant: Dict[str, str],
    group_public_key: GroupPublicKey,
) -> bytes:
    """Combine ``min_signers`` (or more) signature shares into the final,
    standard Ed25519 signature. Verify the result with
    ``Verifier.verify`` against ``group_public_key.public_key_jwk``,
    exactly like any other Vouch credential."""
    group_public_key_json = json.dumps(
        {
            "verifying_key": group_public_key.verifying_key,
            "public_key_package": group_public_key.public_key_package,
        }
    )
    sig_b64 = _call(
        "vouch_threshold_aggregate",
        base64.standard_b64encode(message),
        json.dumps(commitments_by_participant).encode("utf-8"),
        json.dumps(shares_by_participant).encode("utf-8"),
        group_public_key_json.encode("utf-8"),
    )
    return base64.standard_b64decode(sig_b64)


@dataclass
class ThresholdSigner:
    """Convenience: run a full commit/sign/aggregate ceremony in one call.

    Holds ``min_signers`` (or more) key shares locally and produces a signature
    over any message with a single :meth:`sign` call, running round 1, round 2,
    and aggregation across the shares it holds. This fits a coordinator process
    that has access to enough shares to sign (for example, a service with
    several custodian shares mounted, or a test harness); a true multi-device
    ceremony instead calls :func:`commit` / :func:`sign_share` / :func:`aggregate`
    directly across devices, passing commitments and shares over the network.

    Pass :attr:`sign` to :meth:`vouch.signer.Signer.from_backend` to get a
    ``Signer`` backed by threshold signing.
    """

    shares: List[KeyShare]
    group_public_key: GroupPublicKey

    def __post_init__(self) -> None:
        if len(self.shares) < 2:
            raise ValueError("ThresholdSigner needs at least 2 key shares")

    def sign(self, digest: bytes) -> bytes:
        nonces_by_id: Dict[str, str] = {}
        commitments: Dict[str, str] = {}
        for share in self.shares:
            round1 = commit(share)
            commitments[share.identifier] = round1.commitments
            nonces_by_id[share.identifier] = round1.nonces

        shares_out: Dict[str, str] = {}
        for share in self.shares:
            shares_out[share.identifier] = sign_share(
                digest, share, nonces_by_id[share.identifier], commitments
            )

        return aggregate(digest, commitments, shares_out, self.group_public_key)


__all__ = [
    "ThresholdError",
    "KeyShare",
    "GroupPublicKey",
    "GenerateKeyResult",
    "Round1",
    "ThresholdSigner",
    "generate_key",
    "commit",
    "sign_share",
    "aggregate",
]
