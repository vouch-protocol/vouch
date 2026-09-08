"""The protection wrapper behind ``vouch.mcp.FastMCP`` and ``vouch.mcp.protect``.

One place decides whether a tool call may run. Everything else in this package
is plumbing that routes calls through here.

The five steps, in order, all before the tool body:

1. Locate the credential.
2. Verify it (proof, issuer binding, purpose, validity window, revocation).
3. Confirm the issuer is trusted.
4. Confirm the credential's intent is *this* call, not a similar one.
5. Ask Shield.

Any failure returns a structured refusal. No exception reaches the tool body,
and no partial success lets it run.
"""

from __future__ import annotations

import functools
import inspect
import json
import logging
import os
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence

from vouch import jcs
from vouch.shield import Shield, ShieldConfig
from vouch.verifier import Verifier

logger = logging.getLogger(__name__)

#: The tool argument carrying the credential.
CREDENTIAL_ARG = "credential"

__all__ = [
    "GuardConfig",
    "Refusal",
    "ToolGuard",
    "compute_resource",
    "CREDENTIAL_ARG",
]


class VouchMcpConfigError(RuntimeError):
    """Raised when a protected server is not configured to protect anything."""


@dataclass(frozen=True)
class Refusal:
    """A structured refusal. Returned to the caller in place of a tool result."""

    reason: str
    tool: str
    detail: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        out = {"error": "refused", "reason": self.reason, "tool": self.tool}
        if self.detail:
            out["detail"] = self.detail
        return out


def compute_resource(
    args: Dict[str, Any], resource_fn: Optional[Callable[[Dict[str, Any]], str]]
) -> str:
    """The resource string this call binds to.

    Default is the JCS canonicalisation of the whole argument dict, so a
    credential authorises exactly one call with exactly these arguments. A tool
    that opts into ``resource=`` is deliberately loosening that; see the README.
    """
    payload = {k: v for k, v in args.items() if k != CREDENTIAL_ARG}
    if resource_fn is not None:
        value = resource_fn(payload)
        if not isinstance(value, str) or not value:
            raise ValueError("resource= callable must return a non-empty string")
        return value
    return jcs.canonicalize_str(payload)


@dataclass
class GuardConfig:
    """Configuration for a protected server. Read from the environment."""

    rules_path: str
    trusted_issuers: frozenset
    target: str
    check_revocation: bool = True

    @classmethod
    def from_env(cls, *, server_name: str, env: Optional[Dict[str, str]] = None) -> "GuardConfig":
        """Build from environment. Raises rather than starting unprotected."""
        source = os.environ if env is None else env

        rules_path = source.get("VOUCH_RULES")
        if not rules_path:
            raise VouchMcpConfigError(
                "VOUCH_RULES is not set. A Vouch-protected MCP server needs a "
                "Shield rules file to know what it may do. Point VOUCH_RULES at "
                "one, or use vouch.mcp.FastMCP(..., rules_path=...). Refusing to "
                "start unprotected."
            )

        raw_issuers = source.get("VOUCH_TRUSTED_ISSUERS", "")
        issuers = frozenset(d.strip() for d in raw_issuers.split(",") if d.strip())
        if not issuers:
            raise VouchMcpConfigError(
                "VOUCH_TRUSTED_ISSUERS is not set. Without it no credential can "
                "be accepted, so every call would be refused. Set it to a "
                "comma-separated list of DIDs. Refusing to start unprotected."
            )

        target = source.get("VOUCH_TARGET") or server_name
        check_revocation = source.get("VOUCH_CHECK_REVOCATION", "1") not in ("0", "false", "no")

        return cls(
            rules_path=rules_path,
            trusted_issuers=issuers,
            target=target,
            check_revocation=check_revocation,
        )


class ToolGuard:
    """Decides whether one tool call may run, and wraps functions to enforce it."""

    def __init__(self, config: GuardConfig, *, shield: Optional[Shield] = None) -> None:
        self._config = config
        self._shield = shield or Shield(
            ShieldConfig(rules_path=config.rules_path, require_signature=False)
        )
        self._verifier = Verifier(allow_did_resolution=True)
        if not self._shield.rules.ok:
            # Loud, but still deny-all rather than a crash: a running server
            # that refuses everything is easier to diagnose than one that will
            # not start, and it cannot be mistaken for a permissive one.
            logger.error(
                "Vouch: rules did not load (%s). Every call will be refused.",
                self._shield.rules.malformed_reason,
            )

    @property
    def config(self) -> GuardConfig:
        return self._config

    @property
    def shield(self) -> Shield:
        return self._shield

    # -- the decision ------------------------------------------------------

    def check(
        self,
        tool_name: str,
        args: Dict[str, Any],
        *,
        resource_fn: Optional[Callable[[Dict[str, Any]], str]] = None,
    ) -> Optional[Refusal]:
        """Return None if the call may run, or a Refusal if it may not.

        Emits exactly one structured decision line to the log, whichever way it
        goes, so an operator can read the server's behaviour from stderr.
        """
        refusal, did, resource = self._decide(tool_name, args, resource_fn)
        verdict = "DENY " if refusal is not None else "ALLOW"
        detail = ""
        if refusal is not None:
            detail = refusal.reason + (f" ({refusal.detail})" if refusal.detail else "")
        logger.log(
            logging.WARNING if refusal is not None else logging.INFO,
            "%s  %s  %s  %s  %s",
            verdict,
            did,
            tool_name,
            resource,
            detail,
        )
        return refusal

    def _decide(
        self,
        tool_name: str,
        args: Dict[str, Any],
        resource_fn: Optional[Callable[[Dict[str, Any]], str]],
    ) -> "tuple[Optional[Refusal], str, str]":
        """The decision itself. Returns (refusal or None, did, resource)."""
        did = "-"
        try:
            resource = compute_resource(args, resource_fn)
        except Exception:
            resource = "-"

        raw = args.get(CREDENTIAL_ARG)

        # 1. Locate and parse the credential.
        if not raw:
            return Refusal("no credential", tool_name), did, resource
        if isinstance(raw, str):
            try:
                credential = json.loads(raw)
            except json.JSONDecodeError as exc:
                return Refusal("no credential", tool_name, f"not valid JSON: {exc}"), did, resource
        elif isinstance(raw, dict):
            credential = raw
        else:
            return (
                Refusal("no credential", tool_name, "credential must be a JSON object"),
                did,
                resource,
            )
        if not isinstance(credential, dict):
            return (
                Refusal("no credential", tool_name, "credential must be a JSON object"),
                did,
                resource,
            )

        # 2. Verify it. Resolves the issuer key from trusted roots, did:key
        #    offline, or did:web, then checks proof, issuer binding, proof
        #    purpose, and the validity window.
        is_valid, passport = self._verifier.check_vouch_credential(credential)
        if not is_valid or passport is None:
            return (
                Refusal(
                    "credential did not verify",
                    tool_name,
                    "signature, issuer binding, or validity window failed",
                ),
                did,
                resource,
            )

        # 2b. Revocation, when the credential carries a status entry.
        did = passport.iss
        revoked = self._revocation_refusal(credential, tool_name)
        if revoked is not None:
            return revoked, did, resource

        # 3. Trusted issuer.
        if passport.iss not in self._config.trusted_issuers:
            return Refusal("untrusted issuer", tool_name, passport.iss), did, resource

        # 4. The credential must be for *this* call. A credential for
        #    read_file reports/q3.txt must not authorise reports/q4.txt.
        try:
            expected_resource = compute_resource(args, resource_fn)
        except Exception as exc:
            return (
                Refusal("credential does not match request", tool_name, str(exc)),
                did,
                resource,
            )

        intent = passport.intent or {}
        if intent.get("action") != tool_name:
            return (
                Refusal(
                    "credential does not match request",
                    tool_name,
                    f"intent.action is {intent.get('action')!r}, called {tool_name!r}",
                ),
                did,
                resource,
            )
        if intent.get("target") != self._config.target:
            return (
                Refusal(
                    "credential does not match request",
                    tool_name,
                    f"intent.target is {intent.get('target')!r}, "
                    f"this server is {self._config.target!r}",
                ),
                did,
                resource,
            )
        if intent.get("resource") != expected_resource:
            return (
                Refusal(
                    "credential does not match request",
                    tool_name,
                    "intent.resource does not match these arguments",
                ),
                did,
                resource,
            )

        # 5. Shield.
        decision = self._shield.check(
            passport.iss,
            action=tool_name,
            target=self._config.target,
            resource=expected_resource,
        )
        if not decision.allow:
            return Refusal(decision.reason, tool_name), did, resource

        return None, did, resource

    def _revocation_refusal(self, credential: Dict[str, Any], tool_name: str) -> Optional[Refusal]:
        entry = credential.get("credentialStatus")
        if not entry or not self._config.check_revocation:
            return None
        try:
            from vouch.status_list import verify_status
            from vouch.status_list_fetcher import StatusListFetcher

            url = entry.get("statusListCredential") if isinstance(entry, dict) else None
            if not url:
                return Refusal("credential did not verify", tool_name, "malformed credentialStatus")
            status_list = StatusListFetcher().get(url)
            if verify_status(credential_status=entry, status_list_credential=status_list):
                return Refusal("credential revoked", tool_name)
        except Exception as exc:
            # A status list that cannot be checked is not a status list that
            # passed. Fail closed.
            return Refusal("revocation status unavailable", tool_name, str(exc))
        return None

    # -- wrapping ----------------------------------------------------------

    def wrap(
        self,
        fn: Callable[..., Any],
        *,
        tool_name: str,
        resource_fn: Optional[Callable[[Dict[str, Any]], str]] = None,
    ) -> Callable[..., Any]:
        """Return a function with a ``credential`` parameter that guards ``fn``.

        The wrapper carries a signature with ``credential`` appended, so the MCP
        SDK generates a schema that requires it. The argument is consumed here
        and never reaches ``fn``.

        A refusal is raised as an MCP ``ToolError`` carrying the structured
        reason, which the protocol reports to the client with ``isError`` set.
        Returning it as an ordinary value would leave a refusal looking like a
        result, which a model could read straight past; an error cannot be
        mistaken for data. The tool body still never sees an exception, because
        it is never entered.
        """
        guard = self

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                bound = _bind(fn, args, kwargs)
                refusal = guard.check(tool_name, bound, resource_fn=resource_fn)
                if refusal is not None:
                    raise _tool_error(refusal)
                bound.pop(CREDENTIAL_ARG, None)
                return await fn(**bound)

        else:

            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                bound = _bind(fn, args, kwargs)
                refusal = guard.check(tool_name, bound, resource_fn=resource_fn)
                if refusal is not None:
                    raise _tool_error(refusal)
                bound.pop(CREDENTIAL_ARG, None)
                return fn(**bound)

        _attach_credential_parameter(wrapper, fn)
        wrapper.__vouch_protected__ = True
        return wrapper


def _tool_error(refusal: Refusal) -> Exception:
    """An MCP ToolError carrying the refusal as JSON."""
    payload = json.dumps(refusal.to_dict(), separators=(",", ":"))
    try:
        from mcp.server.fastmcp.exceptions import ToolError

        return ToolError(payload)
    except ImportError:  # pragma: no cover - SDK always present in practice
        return PermissionError(payload)


def _bind(fn: Callable[..., Any], args: Sequence[Any], kwargs: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise a call to a plain dict of argument names to values."""
    bound = dict(kwargs)
    if args:
        names = [
            name
            for name, param in inspect.signature(fn).parameters.items()
            if param.kind
            in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
        ]
        for name, value in zip(names, args):
            bound[name] = value
    return bound


def _attach_credential_parameter(wrapper: Callable[..., Any], fn: Callable[..., Any]) -> None:
    """Give ``wrapper`` ``fn``'s signature plus a required ``credential``."""
    signature = inspect.signature(fn)
    parameters: List[inspect.Parameter] = [
        p
        for p in signature.parameters.values()
        if p.kind not in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)
    ]
    parameters.append(
        inspect.Parameter(CREDENTIAL_ARG, inspect.Parameter.KEYWORD_ONLY, annotation=str)
    )
    wrapper.__signature__ = signature.replace(parameters=parameters)

    annotations = dict(getattr(fn, "__annotations__", {}))
    annotations[CREDENTIAL_ARG] = str
    wrapper.__annotations__ = annotations

    doc = inspect.getdoc(fn) or ""
    wrapper.__doc__ = (
        f"{doc}\n\n"
        "Requires a Vouch Credential authorising exactly this call, passed as "
        "`credential` (the JSON returned by vouch-mcp's `sign`)."
    ).strip()
