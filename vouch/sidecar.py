"""
Vouch Protocol signing sidecar (Python).

A small local HTTP server that holds the agent's signing key in its own process,
so the model that asks for signatures never has the key. It speaks the same HTTP
contract as the Go sidecar (``go-sidecar/cmd/vouch-sidecar``), so a tool wrapper
written for one works with the other.

Run it::

    vouch sidecar                                   # the identity `vouch init` saved
    vouch sidecar --allowlist vouch-allowlist.json  # only sign the listed actions
    vouch sidecar --default-validity 10m --max-validity 2h
    vouch sidecar --did did:web:localhost --dev     # throwaway key, local testing

Endpoints:

    POST /sign         sign an intent, return a Verifiable Credential
    POST /sign/hybrid  the same, with the post-quantum proof set
    GET  /health       readiness, the agent DID, the last signature time
    GET  /did          the agent DID and its verification method
    GET  /pubkey       the public keys in Multikey form
    GET  /.well-known/did.json  the DID document for the signing key

The caller chooses how long each credential lasts with ``validSeconds``. The
default applies when the caller names none, and the maximum is the longest it
may ask for; both are set when the sidecar starts.

The server listens on 127.0.0.1 by default. To listen on another address, set
``VOUCH_SIDECAR_TOKEN``; the signing endpoints then need the header
``Authorization: Bearer <token>``.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import ipaddress
import json
import os
import re
import sys
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, FrozenSet, List, Mapping, Optional, TextIO, Tuple
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vouch.keys import (
    MLDSA44,
    IdentityDamagedError,
    IdentityError,
    IdentityLockedError,
    KeyManager,
    KeyPair,
    WrongPasswordError,
    generate_identity,
)
from vouch.keys import _read_rows as read_key_rows
from vouch.signer import Signer

SEED_ENV = "VOUCH_ED25519_SEED"
PRIVATE_KEY_ENV = "VOUCH_PRIVATE_KEY"
DID_ENV = "VOUCH_DID"
PASSPHRASE_ENV = "VOUCH_KEY_PASSPHRASE"
TOKEN_ENV = "VOUCH_SIDECAR_TOKEN"
HOST_ENV = "VOUCH_SIDECAR_HOST"
DEFAULT_VALIDITY_ENV = "VOUCH_SIDECAR_DEFAULT_VALIDITY"
MAX_VALIDITY_ENV = "VOUCH_SIDECAR_MAX_VALIDITY"

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8877
DEFAULT_VALIDITY = "5m"
DEFAULT_MAX_VALIDITY = "1h"

MAX_BODY_BYTES = 1 << 20
MAX_LOGGED_TEXT = 128

KEY_FROM_FILE = "key file"
KEY_FROM_ENV = "environment"
KEY_FROM_KEYSTORE = "keystore"
KEY_EPHEMERAL = "ephemeral"

PQ_SAVED = "saved"
PQ_PER_RUN = "per-run"
PQ_NONE = "none"
_NO_SAVED_PQ_KEY = (
    "this identity has no saved post-quantum key. Start the sidecar with --hybrid on the "
    "identity `vouch init` saved, or with an identity file that carries one"
)

# What to do about a missing post-quantum key, by where the key came from.
_NO_PQ_KEY_BY_SOURCE = {
    KEY_FROM_ENV: (
        "--hybrid needs a post-quantum key, and a key given in the environment carries none. "
        "Use the identity `vouch init` saved instead, or pass its file with --key"
    ),
    KEY_FROM_FILE: (
        "--hybrid needs a post-quantum key, and this key file carries none. Pass an identity "
        "file from ~/.vouch/keys made by `vouch init` instead"
    ),
}


def _no_pq_key_message(source: str, did: str, file_names_identity: bool) -> str:
    """What to do about a missing post-quantum key, for this identity."""
    if source == KEY_FROM_FILE and file_names_identity:
        return (
            f"--hybrid needs a post-quantum key, and this identity file carries none. Run "
            f"`vouch init --did {did} --add-post-quantum-key` to add one, or start the "
            f"sidecar with `--did {did}` instead of --key, which adds it"
        )
    return _NO_PQ_KEY_BY_SOURCE.get(source, _NO_SAVED_PQ_KEY)


PROOF_CLASSICAL = "eddsa-jcs-2022"
PROOF_HYBRID = "eddsa-jcs-2022+mldsa44-jcs-2024"


class SidecarError(ValueError):
    """A problem with how the sidecar was configured or started."""


# ---------------------------------------------------------------------------
# Durations
# ---------------------------------------------------------------------------

_DURATION_PART = re.compile(r"(\d+)([hms])")


def parse_duration(text: str) -> int:
    """Turn ``"90"``, ``"90s"``, ``"5m"`` or ``"1h30m"`` into whole seconds.

    Raises:
      SidecarError: the text is not a duration.
    """
    raw = (text or "").strip().lower()
    if raw.isdigit():
        return int(raw)
    parts = _DURATION_PART.findall(raw)
    if not parts or "".join(n + unit for n, unit in parts) != raw:
        raise SidecarError(f"{text!r} is not a duration. Use a form such as 30s, 5m or 1h")
    scale = {"h": 3600, "m": 60, "s": 1}
    return sum(int(n) * scale[unit] for n, unit in parts)


def validity_window(default_validity: str, max_validity: str) -> Tuple[int, int]:
    """Check the two validity settings and return them in seconds."""
    default_seconds = parse_duration(default_validity)
    max_seconds = parse_duration(max_validity)
    if default_seconds < 1:
        raise SidecarError("--default-validity must be at least one second, for example 5m")
    if max_seconds < default_seconds:
        raise SidecarError(
            f"--default-validity ({default_validity}) is longer than --max-validity "
            f"({max_validity}): raise the maximum or lower the default"
        )
    return default_seconds, max_seconds


# ---------------------------------------------------------------------------
# Which identity to sign as
# ---------------------------------------------------------------------------


@dataclass
class ResolvedIdentity:
    """The agent the sidecar signs as, and the key it signs with."""

    did: str
    private_jwk: str = field(repr=False)
    source: str = ""
    # The identity's saved ML-DSA-44 key as raw (public, secret) bytes, or None.
    mldsa44: Optional[Tuple[bytes, bytes]] = field(default=None, repr=False)
    # True when the post-quantum key was created and saved just now.
    added_post_quantum_key: bool = False
    # True when a key file names its identity (an identity file, not a bare JWK).
    file_names_identity: bool = False


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _public_from_seed(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )


def _checked_private_jwk(raw: Any) -> str:
    """Validate a private Ed25519 JWK and return it as a compact JSON string.

    The public half stated in the JWK must match the private half.
    """
    try:
        jwk = json.loads(raw) if isinstance(raw, str) else raw
    except json.JSONDecodeError:
        raise SidecarError("the private key is not a JWK") from None
    if not isinstance(jwk, dict) or jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise SidecarError("the key must be an Ed25519 JWK (kty OKP, crv Ed25519)")
    d = jwk.get("d")
    if not isinstance(d, str) or not d:
        raise SidecarError('the key has no private part (the JWK "d" member is missing)')
    try:
        seed = _b64url_decode(d)
    except (ValueError, TypeError):
        seed = b""
    if len(seed) != 32:
        raise SidecarError("the private key must be 32 bytes, base64url-encoded")
    public = _public_from_seed(seed)
    stated = jwk.get("x")
    if stated:
        try:
            matches = hmac.compare_digest(_b64url_decode(stated), public)
        except (ValueError, TypeError):
            matches = False
        if not matches:
            raise SidecarError("the public key in the key file does not match its private key")
    return json.dumps(
        {"kty": "OKP", "crv": "Ed25519", "d": d, "x": _b64url_encode(public)},
        separators=(",", ":"),
    )


def _identity_from_key_file(path: str, did: Optional[str]) -> ResolvedIdentity:
    try:
        with open(path, "r") as f:
            data = json.load(f)
    except OSError as e:
        raise SidecarError(f"cannot read the key file: {e.strerror or e}") from None
    except json.JSONDecodeError:
        raise SidecarError("the key file is not valid JSON") from None
    if not isinstance(data, dict):
        raise SidecarError("the key file is not valid JSON")

    file_did = data.get("id") if isinstance(data.get("id"), str) else None
    if data.get("encrypted"):
        raise SidecarError(
            "the key file is locked with a passphrase. Keep it in the keystore and start "
            "the sidecar with --did, which asks for the passphrase"
        )
    private = data["private_key"] if "private_key" in data else data
    private_jwk = _checked_private_jwk(private)

    if did and file_did and did != file_did:
        raise SidecarError(f"the key file is for {file_did}, but --did is {did}")
    chosen = did or file_did
    if not chosen:
        raise SidecarError("--did is required: this key file does not name an identity")
    try:
        rows, _ = read_key_rows({**data, "id": file_did or chosen}, None)
    except IdentityError as e:
        raise SidecarError(f"the key file is damaged: {e}") from None
    saved = KeyPair(private_jwk, "", chosen, rows).mldsa44_keypair()
    return ResolvedIdentity(
        did=chosen,
        private_jwk=private_jwk,
        source=KEY_FROM_FILE,
        mldsa44=saved,
        file_names_identity=bool(file_did),
    )


def _no_key_error(did: Optional[str]) -> SidecarError:
    if did:
        return SidecarError(
            f"no signing key for {did}: create it with `vouch init`, or pass --key <file>. "
            "For local testing, --dev uses a throwaway key"
        )
    return SidecarError(
        "no signing key found: create an identity with `vouch init --domain <your domain>`, "
        "or pass --key <file>. For local testing, --did did:web:localhost --dev uses a "
        "throwaway key"
    )


def _identity_from_keystore(
    did: Optional[str],
    environ: Mapping[str, str],
    ask_passphrase: Optional[Callable[[str], str]],
    need_post_quantum: bool = False,
) -> ResolvedIdentity:
    km = KeyManager()
    stored = sorted({entry["did"] for entry in km.list_identities()})
    if not did:
        if not stored:
            raise _no_key_error(None)
        if len(stored) > 1:
            raise SidecarError(
                f"several identities found ({', '.join(stored)}): choose one with --did"
            )
        did = stored[0]
    if km.get_public_key(did) is None:
        raise _no_key_error(did)

    # A passphrase set in the environment is always used, so a locked file
    # swapped for an unlocked one is noticed instead of loaded.
    passphrase = environ.get(PASSPHRASE_ENV, "")
    try:
        try:
            keys = km.load_identity(did, passphrase or None)
        except IdentityLockedError:
            passphrase = ask_passphrase(did) if ask_passphrase else ""
            if not passphrase:
                raise SidecarError(
                    f"the identity for {did} is locked with a passphrase. Run the sidecar in a "
                    f"terminal to be asked for it, or set {PASSPHRASE_ENV}"
                ) from None
            keys = km.load_identity(did, passphrase)
    except WrongPasswordError as e:
        if "not locked" in str(e):
            raise SidecarError(str(e)) from None
        raise SidecarError(f"wrong passphrase for {did}") from None
    except IdentityDamagedError as e:
        raise SidecarError(f"the identity for {did} is damaged: {e}") from None
    if keys.did != did:
        raise SidecarError(f"the keystore file for {did} names a different identity")
    added = False
    if need_post_quantum and keys.key_for(MLDSA44) is None:
        # An identity from before post-quantum keys were saved gains one here,
        # once. Its Ed25519 key is left as it is.
        try:
            keys = km.ensure_post_quantum_key(did, passphrase or None)
        except IdentityError as e:
            raise SidecarError(f"cannot add the post-quantum key for {did}: {e}") from None
        except OSError as e:
            raise SidecarError(
                f"cannot save the post-quantum key for {did}: {e.strerror or e}"
            ) from None
        except ImportError:
            raise SidecarError(
                "--hybrid needs the post-quantum package: pip install pqcrypto"
            ) from None
        added = True
    return ResolvedIdentity(
        did=did,
        private_jwk=_checked_private_jwk(keys.private_key_jwk),
        source=KEY_FROM_KEYSTORE,
        mldsa44=keys.mldsa44_keypair(),
        added_post_quantum_key=added,
    )


def resolve_identity(
    *,
    did: Optional[str] = None,
    key_path: Optional[str] = None,
    dev: bool = False,
    environ: Optional[Mapping[str, str]] = None,
    ask_passphrase: Optional[Callable[[str], str]] = None,
    need_post_quantum: bool = False,
) -> ResolvedIdentity:
    """Work out which agent to sign as and load its key.

    With nothing configured the keystore is used: the identity for ``did``, or
    the only identity there when ``did`` is not given. An explicit key file or
    an environment key takes its place, and ``dev`` swaps in a random key for
    one run. When none of these yields a key this raises: the sidecar never
    invents a lasting key.

    Raises:
      SidecarError: no usable key, or the settings contradict each other.
    """
    env = os.environ if environ is None else environ
    env_jwk = env.get(PRIVATE_KEY_ENV, "")
    env_seed = env.get(SEED_ENV, "")
    did = did or None

    explicit = [name for name, value in (("--key", key_path), (PRIVATE_KEY_ENV, env_jwk)) if value]
    if env_seed:
        explicit.append(SEED_ENV)
    if len(explicit) > 1:
        raise SidecarError(f"set only one of {' and '.join(explicit)}")

    if key_path:
        return _identity_from_key_file(key_path, did)

    if env_jwk or env_seed:
        chosen = did or env.get(DID_ENV)
        if not chosen:
            raise SidecarError(f"--did is required with {explicit[0]}")
        if env_jwk:
            return ResolvedIdentity(chosen, _checked_private_jwk(env_jwk), KEY_FROM_ENV)
        try:
            seed = bytes.fromhex(env_seed.strip())
        except ValueError:
            seed = b""
        if len(seed) != 32:
            # The value is not echoed: it is a secret.
            raise SidecarError(f"{SEED_ENV} must be 64 hex characters")
        jwk = {"kty": "OKP", "crv": "Ed25519", "d": _b64url_encode(seed)}
        return ResolvedIdentity(chosen, _checked_private_jwk(jwk), KEY_FROM_ENV)

    if dev:
        if not did:
            raise SidecarError("--did is required with --dev, for example --did did:web:localhost")
        return ResolvedIdentity(did, generate_identity().private_key_jwk, KEY_EPHEMERAL)

    return _identity_from_keystore(did, env, ask_passphrase, need_post_quantum)


# ---------------------------------------------------------------------------
# Listening address and allow-list
# ---------------------------------------------------------------------------


def is_loopback_host(host: str) -> bool:
    """True when ``host`` only accepts connections from this machine."""
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def check_exposure(host: str, token: str) -> None:
    """Refuse a listening address other machines can reach unless a token is set."""
    if is_loopback_host(host) or token:
        return
    raise SidecarError(
        f"refusing to listen on {host!r} without {TOKEN_ENV}: other machines could ask this "
        f"sidecar to sign. Set {TOKEN_ENV}, or keep the default --host {DEFAULT_HOST}"
    )


def load_allowlist(path: str, did: str) -> FrozenSet[str]:
    """Read the action names from an allow-list file such as vouch-allowlist.json."""
    try:
        with open(path, "r") as f:
            doc = json.load(f)
    except OSError as e:
        raise SidecarError(f"cannot read the allow-list: {e.strerror or e}") from None
    except json.JSONDecodeError:
        raise SidecarError(f"{path} is not valid JSON") from None
    if not isinstance(doc, dict):
        raise SidecarError(f"{path} is not an allow-list")
    issuer = doc.get("issuer")
    if issuer and issuer != did:
        raise SidecarError(f"{path} is for {issuer}, but this sidecar signs as {did}")
    actions = doc.get("actions")
    names = frozenset(
        a["name"]
        for a in (actions if isinstance(actions, list) else [])
        if isinstance(a, dict) and isinstance(a.get("name"), str) and a["name"]
    )
    if not names:
        raise SidecarError(f"{path} names no actions")
    return names


# ---------------------------------------------------------------------------
# The sidecar itself: one request in, one response out
# ---------------------------------------------------------------------------


@dataclass
class SidecarConfig:
    """How one sidecar behaves."""

    did: str
    key_source: str = KEY_FROM_KEYSTORE
    token: str = ""
    allowed_actions: Optional[FrozenSet[str]] = None
    default_valid_seconds: int = 300
    max_valid_seconds: int = 3600
    hybrid: bool = False
    # Where the ML-DSA-44 key comes from: "saved" with the identity, "per-run"
    # (generated for this process, as --dev does), or "none".
    post_quantum: str = PQ_PER_RUN
    loopback_only: bool = True
    verbose: bool = False


@dataclass
class Response:
    """What the sidecar answers."""

    status: int
    body: bytes
    content_type: str = "application/json"
    www_authenticate: bool = False

    def json(self) -> Any:
        return json.loads(self.body)


class _Refusal(Exception):
    def __init__(self, status: int, reason: str, challenge: bool = False) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason
        self.challenge = challenge


def _clip(text: str) -> str:
    return text if len(text) <= MAX_LOGGED_TEXT else text[:MAX_LOGGED_TEXT]


class Sidecar:
    """Holds the signer and answers requests.

    ``handle`` takes a request in plain values and returns a :class:`Response`,
    so it can be driven by any HTTP server, or by a test, without a socket.
    """

    def __init__(
        self, signer: Signer, config: SidecarConfig, log_stream: Optional[TextIO] = None
    ) -> None:
        if config.default_valid_seconds < 1 or config.max_valid_seconds < 1:
            raise SidecarError("validity settings must be at least one second")
        if config.default_valid_seconds > config.max_valid_seconds:
            raise SidecarError("the default validity is longer than the maximum")
        self._signer = signer
        self._cfg = config
        self._log_stream = log_stream
        self._log_lock = threading.Lock()
        self._last_signed_at: Optional[str] = None
        self._public_multikey = signer.get_public_key_multikey()
        self._pq_multikey: Optional[str] = None
        if config.post_quantum not in (PQ_SAVED, PQ_PER_RUN, PQ_NONE):
            raise SidecarError("post_quantum must be saved, per-run or none")
        if config.hybrid and config.post_quantum == PQ_NONE:
            raise SidecarError(_NO_SAVED_PQ_KEY)
        if config.post_quantum == PQ_SAVED or config.hybrid:
            # Have the ML-DSA-44 key ready now. With --hybrid, a missing
            # package stops startup instead of failing every request.
            try:
                if config.hybrid:
                    from vouch import data_integrity_hybrid

                    data_integrity_hybrid._import_pqcrypto()
                self._pq_multikey = signer.public_key_mldsa44_multikey()
            except ImportError:
                raise SidecarError(
                    "--hybrid needs the post-quantum package: pip install pqcrypto"
                ) from None

    # -- public surface -----------------------------------------------------

    @property
    def config(self) -> SidecarConfig:
        return self._cfg

    def handle(self, method: str, target: str, headers: Mapping[str, str], body: bytes) -> Response:
        """Answer one HTTP request. Never raises."""
        lowered = {k.lower(): v for k, v in headers.items()}
        path = urlsplit(target).path
        signing = path in ("/sign", "/sign/hybrid")
        info: Dict[str, Any] = {}
        try:
            self._guard_host(lowered.get("host", ""))
            response = self._route(method, path, lowered, body, info)
        except _Refusal as refusal:
            response = Response(
                refusal.status,
                (refusal.reason + "\n").encode("utf-8"),
                "text/plain; charset=utf-8",
                www_authenticate=refusal.challenge,
            )
            info["reason"] = refusal.reason

        if self._cfg.verbose:
            self._log("DEBUG", "request", method=method, path=_clip(path), status=response.status)
        if signing and response.status == 200:
            self._log(
                "INFO",
                "signed",
                did=self._cfg.did,
                action=info.get("action", ""),
                credential_id=info.get("credential_id", ""),
                valid_until=info.get("valid_until", ""),
                proof=info.get("proof", ""),
            )
        elif signing:
            self._log(
                "WARN",
                "refused",
                status=response.status,
                reason=info.get("reason", ""),
                action=info.get("action", ""),
            )
        return response

    # -- routing ------------------------------------------------------------

    def _route(
        self,
        method: str,
        path: str,
        headers: Mapping[str, str],
        body: bytes,
        info: Dict[str, Any],
    ) -> Response:
        if path == "/sign":
            return self._sign(method, headers, body, info, post_quantum=self._cfg.hybrid)
        if path == "/sign/hybrid":
            return self._sign(method, headers, body, info, post_quantum=True)
        if path == "/health":
            return self._json(self._health())
        if path == "/did":
            return self._json({"did": self._cfg.did, "verificationMethod": self._method_id()})
        if path == "/pubkey":
            return self._json(self._pubkey())
        if path == "/.well-known/did.json":
            return self._json(self._did_document())
        raise _Refusal(404, "not found")

    def _guard_host(self, host_header: str) -> None:
        if not self._cfg.loopback_only:
            return
        host = host_header.strip()
        if host.startswith("["):  # [::1]:8877
            host = host[1:].split("]", 1)[0]
        elif host.count(":") == 1:  # name:port
            host = host.rsplit(":", 1)[0]
        if not is_loopback_host(host):
            raise _Refusal(403, "this sidecar only answers local requests")

    def _authorized(self, headers: Mapping[str, str]) -> bool:
        if not self._cfg.token:
            return True
        header = headers.get("authorization", "")
        if not header.startswith("Bearer "):
            return False
        # Compare digests so the check takes the same time whatever was sent.
        got = hashlib.sha256(header[len("Bearer ") :].encode("utf-8")).digest()
        want = hashlib.sha256(self._cfg.token.encode("utf-8")).digest()
        return hmac.compare_digest(got, want)

    # -- signing ------------------------------------------------------------

    def _sign(
        self,
        method: str,
        headers: Mapping[str, str],
        body: bytes,
        info: Dict[str, Any],
        post_quantum: bool,
    ) -> Response:
        if method != "POST":
            raise _Refusal(405, "method not allowed")
        if not self._authorized(headers):
            raise _Refusal(401, "a valid bearer token is required", challenge=True)
        media_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if media_type != "application/json":
            raise _Refusal(415, "Content-Type must be application/json")
        if len(body) > MAX_BODY_BYTES:
            raise _Refusal(400, "the request is too large")
        try:
            request = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            raise _Refusal(400, "invalid request: the body is not JSON") from None
        if not isinstance(request, dict):
            raise _Refusal(400, "invalid request: the body must be a JSON object")

        intent = request.get("intent")
        if request.get("payload") is not None:
            raise _Refusal(400, "this sidecar signs an intent; the payload form is not served here")
        if not isinstance(intent, dict):
            raise _Refusal(400, "the request needs an intent with action, target and resource")
        for name in ("action", "target", "resource"):
            if not isinstance(intent.get(name), str) or not intent[name]:
                raise _Refusal(400, f"intent.{name} is required and must be a string")
        info["action"] = _clip(intent["action"])
        allowed = self._cfg.allowed_actions
        if allowed is not None and intent["action"] not in allowed:
            raise _Refusal(403, "this sidecar does not sign that action")

        valid_seconds = self._validity(request)
        options: Dict[str, Any] = {"intent": intent, "valid_seconds": valid_seconds}
        score = request.get("reputationScore")
        if score is not None:
            if isinstance(score, bool) or not isinstance(score, int):
                raise _Refusal(400, "reputationScore must be a whole number")
            options["reputation_score"] = max(0, min(100, score))
        chain = request.get("delegationChain")
        if chain:
            if not isinstance(chain, list) or not all(isinstance(link, dict) for link in chain):
                raise _Refusal(400, "delegationChain must be a list of objects")
            options["delegation_chain"] = chain
        status = request.get("credentialStatus")
        if status is not None:
            if not isinstance(status, dict):
                raise _Refusal(400, "credentialStatus must be an object")
            if post_quantum:
                raise _Refusal(400, "credentialStatus is not available with the proof set here")
            options["credential_status"] = status
        if post_quantum and self._cfg.post_quantum == PQ_NONE:
            raise _Refusal(409, _NO_SAVED_PQ_KEY)

        try:
            if post_quantum:
                info["proof"] = PROOF_HYBRID
                credential = self._signer.sign_hybrid(**options)
                self._pq_multikey = self._signer.public_key_mldsa44_multikey()
            else:
                info["proof"] = PROOF_CLASSICAL
                credential = self._signer.sign(**options)
        except ImportError:
            raise _Refusal(
                501, "post-quantum signing needs the pqcrypto package on the sidecar"
            ) from None
        except ValueError as e:
            raise _Refusal(400, f"cannot sign this intent: {e}") from None

        info["credential_id"] = credential.get("id", "")
        info["valid_until"] = credential.get("validUntil", "")
        self._last_signed_at = _utc_now()
        return self._json(credential)

    def _validity(self, request: Dict[str, Any]) -> int:
        """How long the credential lasts. The caller chooses; none means the default."""
        requested = request.get("validSeconds") or request.get("valid_seconds") or 0
        if isinstance(requested, bool) or not isinstance(requested, int):
            raise _Refusal(400, "validSeconds must be a whole number of seconds")
        if requested == 0:
            return self._cfg.default_valid_seconds
        if requested < 0 or requested > self._cfg.max_valid_seconds:
            raise _Refusal(
                400,
                f"validity must be between 1 and {self._cfg.max_valid_seconds} seconds; "
                f"leave it out for the default of {self._cfg.default_valid_seconds}",
            )
        return requested

    # -- read-only endpoints ------------------------------------------------

    def _method_id(self) -> str:
        return self._signer.verification_method_id()

    def _health(self) -> Dict[str, Any]:
        return {
            "status": "operational",
            "ready": True,
            "mode": "standard",
            "did": self._cfg.did,
            "key": self._cfg.key_source,
            "hybrid": self._cfg.hybrid,
            "postQuantumKey": self._cfg.post_quantum,
            "defaultValiditySeconds": self._cfg.default_valid_seconds,
            "maxValiditySeconds": self._cfg.max_valid_seconds,
            "lastSignedAt": self._last_signed_at,
        }

    def _pubkey(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "verificationMethod": self._method_id(),
            "publicKeyMultibase": self._public_multikey,
        }
        if self._pq_multikey:
            out["mldsa44"] = {
                "verificationMethod": self._signer.mldsa44_verification_method_id(),
                "publicKeyMultibase": self._pq_multikey,
            }
        return out

    def _did_document(self) -> Dict[str, Any]:
        method = self._method_id()
        methods: List[Dict[str, str]] = [
            {
                "id": method,
                "type": "Multikey",
                "controller": self._cfg.did,
                "publicKeyMultibase": self._public_multikey,
            }
        ]
        assertion = [method]
        if self._cfg.hybrid and self._pq_multikey:
            pq_method = self._signer.mldsa44_verification_method_id()
            methods.append(
                {
                    "id": pq_method,
                    "type": "Multikey",
                    "controller": self._cfg.did,
                    "publicKeyMultibase": self._pq_multikey,
                }
            )
            assertion.append(pq_method)
        return {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/multikey/v1",
            ],
            "id": self._cfg.did,
            "verificationMethod": methods,
            "assertionMethod": assertion,
            "authentication": [method],
        }

    # -- helpers ------------------------------------------------------------

    @staticmethod
    def _json(value: Any) -> Response:
        return Response(200, (json.dumps(value) + "\n").encode("utf-8"))

    def _log(self, level: str, message: str, **fields: Any) -> None:
        """Write one JSON line. Logs carry the action and credential ID, never
        the key, the token, or the request body."""
        stream = self._log_stream
        if stream is None:
            return
        line = json.dumps({"time": _utc_now(), "level": level, "msg": message, **fields})
        with self._log_lock:
            stream.write(line + "\n")
            stream.flush()

    def log_startup(self, address: str) -> None:
        self._log(
            "INFO",
            "vouch-sidecar listening",
            address=address,
            did=self._cfg.did,
            key=self._cfg.key_source,
            public_key=self._public_multikey,
            hybrid=self._cfg.hybrid,
            post_quantum_key=self._cfg.post_quantum,
            default_validity_seconds=self._cfg.default_valid_seconds,
            max_validity_seconds=self._cfg.max_valid_seconds,
        )
        if self._cfg.key_source == KEY_EPHEMERAL:
            self._log("WARN", "dev mode: using a random key for this run only")


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------


class _RequestHandler(BaseHTTPRequestHandler):
    server_version = "vouch-sidecar"
    sys_version = ""
    timeout = 15

    def _dispatch(self) -> None:
        sidecar: Sidecar = self.server.sidecar  # type: ignore[attr-defined]
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY_BYTES:
            self._send(Response(400, b"the request is too large\n", "text/plain; charset=utf-8"))
            return
        body = self.rfile.read(length) if length else b""
        self._send(sidecar.handle(self.command, self.path, dict(self.headers.items()), body))

    def _send(self, response: Response) -> None:
        self.send_response(response.status)
        self.send_header("Content-Type", response.content_type)
        self.send_header("Content-Length", str(len(response.body)))
        if response.www_authenticate:
            self.send_header("WWW-Authenticate", "Bearer")
        self.end_headers()
        self.wfile.write(response.body)

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = _dispatch

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        """The sidecar writes its own JSON log lines."""


def make_server(sidecar: Sidecar, host: str, port: int) -> ThreadingHTTPServer:
    """Bind the HTTP server. Call ``serve_forever()`` on the result."""
    server = ThreadingHTTPServer((host, port), _RequestHandler)
    server.daemon_threads = True
    server.sidecar = sidecar  # type: ignore[attr-defined]
    return server


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


def add_arguments(parser: argparse.ArgumentParser) -> None:
    """The flags of `vouch sidecar`, shared with `vouch-bridge --did ...`."""
    env = os.environ
    parser.add_argument(
        "--did", help="Agent DID. Optional when the keystore holds exactly one identity"
    )
    parser.add_argument(
        "--host", default=env.get(HOST_ENV, DEFAULT_HOST), help="Address to listen on"
    )
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="HTTP listen port")
    parser.add_argument(
        "--key",
        help="Path to a private Ed25519 JWK file or an identity file, in place of the keystore",
    )
    parser.add_argument(
        "--dev", action="store_true", help="Use a random key for this run only (local testing)"
    )
    parser.add_argument(
        "--allowlist", help="Path to an allow-list JSON file; only the actions it names are signed"
    )
    parser.add_argument(
        "--default-validity",
        dest="default_validity",
        default=env.get(DEFAULT_VALIDITY_ENV, DEFAULT_VALIDITY),
        help="How long a credential lasts when the caller does not say, for example 5m",
    )
    parser.add_argument(
        "--max-validity",
        dest="max_validity",
        default=env.get(MAX_VALIDITY_ENV, DEFAULT_MAX_VALIDITY),
        help="Longest validity a caller may ask for, for example 1h",
    )
    parser.add_argument(
        "--hybrid",
        action="store_true",
        help="Sign with the post-quantum proof set (Ed25519 plus ML-DSA-44)",
    )
    parser.add_argument("--verbose", action="store_true", help="Log every request")


def _ask_passphrase(did: str) -> str:
    if not sys.stdin.isatty():
        return ""
    return getpass.getpass(f"Passphrase for {did}: ")


def build_sidecar(args: argparse.Namespace, log_stream: Optional[TextIO] = None) -> Sidecar:
    """Turn parsed flags and the environment into a ready :class:`Sidecar`.

    Raises:
      SidecarError: the settings are unusable or no key was found.
    """
    token = os.environ.get(TOKEN_ENV, "")
    check_exposure(args.host, token)
    default_seconds, max_seconds = validity_window(args.default_validity, args.max_validity)
    identity = resolve_identity(
        did=args.did,
        key_path=args.key,
        dev=args.dev,
        ask_passphrase=_ask_passphrase,
        need_post_quantum=args.hybrid,
    )
    if identity.mldsa44 is not None:
        post_quantum = PQ_SAVED
    elif identity.source == KEY_EPHEMERAL:
        post_quantum = PQ_PER_RUN
    else:
        post_quantum = PQ_NONE
    if args.hybrid and post_quantum == PQ_NONE:
        raise SidecarError(
            _no_pq_key_message(identity.source, identity.did, identity.file_names_identity)
        )
    # The secrets have been read; drop them so nothing this process starts
    # later inherits them.
    for name in (SEED_ENV, PRIVATE_KEY_ENV, PASSPHRASE_ENV, TOKEN_ENV):
        os.environ.pop(name, None)

    allowed = load_allowlist(args.allowlist, identity.did) if args.allowlist else None
    signer = Signer(
        private_key=identity.private_jwk,
        did=identity.did,
        default_expiry_seconds=default_seconds,
        mldsa44_keypair=identity.mldsa44,
    )
    sidecar = Sidecar(
        signer,
        SidecarConfig(
            did=identity.did,
            key_source=identity.source,
            token=token,
            allowed_actions=allowed,
            default_valid_seconds=default_seconds,
            max_valid_seconds=max_seconds,
            hybrid=args.hybrid,
            post_quantum=post_quantum,
            loopback_only=is_loopback_host(args.host),
            verbose=args.verbose,
        ),
        log_stream=log_stream,
    )
    if identity.added_post_quantum_key:
        sidecar._log(
            "INFO",
            "added a post-quantum key to the saved identity",
            did=identity.did,
            public_key=sidecar._pq_multikey,
        )
    return sidecar


def run(args: argparse.Namespace) -> int:
    """Start the sidecar and serve until interrupted. Returns an exit code."""
    try:
        sidecar = build_sidecar(args, log_stream=sys.stdout)
        server = make_server(sidecar, args.host, args.port)
    except SidecarError as e:
        print(f"vouch sidecar: {e}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"vouch sidecar: cannot listen on {args.host}:{args.port}: {e}", file=sys.stderr)
        return 1

    sidecar.log_startup(f"{args.host}:{server.server_address[1]}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="vouch sidecar",
        description="Run the Vouch Protocol signing sidecar: it holds the agent's key and "
        "signs what the agent is about to do.",
    )
    add_arguments(parser)
    return run(parser.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
