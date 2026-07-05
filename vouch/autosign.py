"""
Zero-prompt, deterministic signing for agent tool calls.

Historically every Vouch framework integration shipped a *"make a token"* tool
that the model had to remember to call, in prose, on every action. That is
fragile: security that depends on a well-worded prompt and a cooperative LLM is
not security. If the model forgets, paraphrases, or hallucinates a token,
nothing is signed and nothing fails loudly.

This module flips it. You wrap the real tool **once**; every invocation is
signed in Python, deterministically, *before* the tool body runs. The signed
credential is published on a context variable so the outbound request (or the
receiving verifier) can pick it up. No prompt, no LLM compliance, no per-call
effort.

Three tiers of effort, smallest first::

    protect([charge_invoice, send_email])   # one line: wrap a list of tools
    @signed                                  # one decorator: annotate one tool
    <framework>.autosign()                   # near-zero: sign every tool, framework-wide

Identity resolves the same way ``vouch init`` set it up - environment variables
first, then the on-disk keystore (``~/.vouch/keys``), then (opt-in) an ephemeral
key. Configure it once and forget it, exactly like ``vouch git init``.

This is the issuance (signing) half. The verification half already exists:
``vouch.shield.Shield`` and ``vouch.Verifier.verify`` consume the
credentials produced here.
"""

from __future__ import annotations

import functools
import inspect
import logging
import os
from contextvars import ContextVar
from typing import Any, Callable, Dict, List, Optional, Sequence

from vouch.keys import KeyManager
from vouch.signer import Signer

logger = logging.getLogger(__name__)

# The most recently signed credential for the current execution context. An
# outbound HTTP layer (or a test) reads this to attach the token to the real
# request without the tool body having to thread it through by hand.
_current_credential: ContextVar[Optional[Dict[str, Any]]] = ContextVar(
    "vouch_current_credential", default=None
)

# Cache the auto-resolved signer so we do not re-read keys on every call.
_DEFAULT_SIGNER: Optional[Signer] = None
_DEFAULT_RESOLVED = False

# Sentinel kwargs the wrapper will populate if (and only if) the wrapped tool
# declares them, so a tool body can opt in to seeing its own credential.
INJECT_CREDENTIAL_KW = "vouch_credential"


def reset_default_signer() -> None:
    """Forget the cached auto-resolved signer (mainly for tests)."""
    global _DEFAULT_SIGNER, _DEFAULT_RESOLVED
    _DEFAULT_SIGNER = None
    _DEFAULT_RESOLVED = False


def resolve_signer(signer: Optional[Signer] = None) -> Optional[Signer]:
    """Resolve the Signer to use, cheapest source first.

    Resolution order, mirroring how ``vouch init`` / ``vouch git init`` already
    provision identity:

      1. An explicit ``signer`` argument.
      2. ``VOUCH_PRIVATE_KEY`` + ``VOUCH_DID`` environment variables.
      3. The on-disk keystore at ``~/.vouch/keys`` (first unencrypted identity).
      4. If ``VOUCH_AUTO_IDENTITY`` is truthy, a freshly generated ephemeral
         key (logged loudly, because ephemeral identities are not auditable
         across restarts).

    Returns ``None`` if no identity can be resolved and auto-provisioning is
    off, so callers can degrade gracefully rather than crash a whole agent run.
    """
    if signer is not None:
        return signer

    global _DEFAULT_SIGNER, _DEFAULT_RESOLVED
    if _DEFAULT_RESOLVED:
        return _DEFAULT_SIGNER

    _DEFAULT_RESOLVED = True
    _DEFAULT_SIGNER = _build_default_signer()
    return _DEFAULT_SIGNER


def _build_default_signer() -> Optional[Signer]:
    # 2. Environment variables (the existing convention every integration used).
    private_key = os.getenv("VOUCH_PRIVATE_KEY")
    did = os.getenv("VOUCH_DID")
    if private_key and did:
        try:
            return Signer(private_key=private_key, did=did)
        except Exception as e:  # pragma: no cover - defensive
            logger.warning("VOUCH_PRIVATE_KEY/VOUCH_DID present but unusable: %s", e)

    # 3. On-disk keystore - whatever `vouch init` saved, unencrypted only
    #    (an encrypted identity needs a passphrase we cannot prompt for here).
    try:
        km = KeyManager()
        for entry in km.list_identities():
            if entry.get("encrypted"):
                continue
            kp = km.load_identity(entry["did"])
            logger.info("Vouch autosign using keystore identity %s", kp.did)
            return Signer(private_key=kp.private_key_jwk, did=kp.did)
    except Exception as e:  # pragma: no cover - defensive
        logger.debug("Keystore lookup failed: %s", e)

    # 4. Opt-in ephemeral identity.
    if _truthy(os.getenv("VOUCH_AUTO_IDENTITY")):
        from vouch.keys import generate_identity

        domain = os.getenv("VOUCH_AUTO_IDENTITY_DOMAIN", "ephemeral.agent.local")
        kp = generate_identity(domain=domain)
        logger.warning(
            "Vouch autosign generated an EPHEMERAL identity (%s). It is not "
            "persisted; run `vouch init` for a stable, auditable identity.",
            kp.did,
        )
        return Signer(private_key=kp.private_key_jwk, did=kp.did)

    logger.warning(
        "Vouch autosign found no identity (no VOUCH_PRIVATE_KEY/VOUCH_DID, no "
        "keystore identity, VOUCH_AUTO_IDENTITY unset). Tool calls will run "
        "UNSIGNED. Run `vouch init` to fix."
    )
    return None


def _truthy(value: Optional[str]) -> bool:
    return bool(value) and value.strip().lower() not in {"0", "false", "no", "off", ""}


def current_credential() -> Optional[Dict[str, Any]]:
    """The credential signed for the most recent protected call, if any."""
    return _current_credential.get()


def current_token_header(header: str = "Vouch-Token") -> Dict[str, str]:
    """A ready-to-attach HTTP header dict for the current credential.

    Empty if nothing has been signed in this context yet. Lets a tool body do::

        requests.post(url, json=body, headers=current_token_header())
    """
    import json

    cred = _current_credential.get()
    if cred is None:
        return {}
    return {header: json.dumps(cred)}


def sign_intent(
    action: str,
    *,
    target: str = "unspecified",
    resource: str = "unspecified",
    signer: Optional[Signer] = None,
    extra: Optional[Dict[str, Any]] = None,
    parent: Optional[Dict[str, Any]] = None,
    publish: bool = True,
) -> Optional[Dict[str, Any]]:
    """Sign a single intent and (by default) publish it as the current credential.

    This is the one place signing happens for the whole autosign layer. All
    three intent fields required by Specification §5.4.1 (``action``,
    ``target``, ``resource``) are always populated, defaulting to sensible
    placeholders so a caller can sign with just an action.

    Pass ``parent`` (a delegation grant credential from :func:`delegate`) to
    chain this credential under it; the protocol's resource-narrowing rule
    (§9.3) is enforced - a child can only narrow the granted authority.

    Returns the signed Verifiable Credential dict, or ``None`` if no identity
    could be resolved (the call still proceeds - unsigned, loudly logged).
    """
    resolved = resolve_signer(signer)
    if resolved is None:
        return None

    intent: Dict[str, Any] = {
        "action": action,
        "target": target,
        "resource": resource,
    }
    if extra:
        # Keep the three required fields authoritative; fold in extras alongside.
        for k, v in extra.items():
            intent.setdefault(k, v)

    credential = resolved.sign(intent, parent_credential=parent)
    if publish:
        _current_credential.set(credential)
    return credential


def _parent_intent(parent: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """The granted intent inside a delegation grant credential, or {}."""
    if not parent:
        return {}
    return parent.get("credentialSubject", {}).get("intent", {}) or {}


def delegate(
    *,
    action: str,
    target: str,
    resource: str,
    to: Optional[str] = None,
    signer: Optional[Signer] = None,
    valid_seconds: Optional[int] = None,
    reputation_score: Optional[int] = None,
) -> Optional[Dict[str, Any]]:
    """Issue a delegation grant in one call (the principal/supervisor side).

    The principal (resolved signer) authorizes ``action`` on ``target`` /
    ``resource``. Hand the returned grant to an agent and pass it as ``parent=``
    to :func:`protect` / :func:`signed` / :func:`sign_intent`; every action the
    agent signs is then chained under this grant and can only *narrow* the
    authority, never widen it (Specification §9.3)::

        grant = vouch.delegate(action="charge", target="api.bank",
                               resource="invoices", signer=principal)
        agent_tools = protect([charge_invoice], parent=grant)

    ``to`` (the delegatee's DID) is recorded for your own audit trail; the
    protocol binds authority through the credential chain and the
    resource-narrowing rule rather than a subject match.

    Returns the signed grant credential, or ``None`` if no identity resolved.
    """
    resolved = resolve_signer(signer)
    if resolved is None:
        return None

    intent: Dict[str, Any] = {"action": action, "target": target, "resource": resource}
    if to:
        intent["delegatee"] = to
    return resolved.sign(
        intent,
        valid_seconds=valid_seconds,
        reputation_score=reputation_score,
    )


def _derive_target(args: tuple, kwargs: Dict[str, Any]) -> str:
    for key in ("target", "url", "endpoint", "to", "host", "service"):
        if key in kwargs and isinstance(kwargs[key], str):
            return kwargs[key]
    return "agent:tool-call"


def _derive_resource(args: tuple, kwargs: Dict[str, Any], action: str) -> str:
    for key in ("resource", "path", "id", "invoice_id", "query", "table"):
        if key in kwargs and kwargs[key] is not None:
            return str(kwargs[key])
    return action


def signed(
    fn: Optional[Callable] = None,
    *,
    action: Optional[str] = None,
    target: Optional[str] = None,
    resource: Optional[str] = None,
    signer: Optional[Signer] = None,
    parent: Optional[Dict[str, Any]] = None,
):
    """Wrap a callable so every invocation is signed before it runs.

    Usable as a bare decorator or with arguments::

        @signed
        def charge_invoice(invoice_id, amount): ...

        @signed(action="charge", target="api.payments.example.com")
        def charge_invoice(invoice_id, amount): ...

    On each call it derives ``action`` (explicit, else the function name),
    ``target`` and ``resource`` (explicit, else inferred from the call's
    keyword arguments), signs a credential, publishes it via
    :func:`current_credential`, optionally injects it as a ``vouch_credential``
    keyword if the wrapped function declares that parameter, then runs the
    function unchanged. Signing failures never block the underlying call.
    """

    def decorate(func: Callable) -> Callable:
        wants_injection = _accepts_kwarg(func, INJECT_CREDENTIAL_KW)
        resolved_action = action or getattr(func, "__name__", "tool_call")

        # When delegating, default target/resource to the granted scope so the
        # chain validates by default; an explicit narrower value still wins.
        granted = _parent_intent(parent)

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                eff_target = target or granted.get("target") or _derive_target(args, kwargs)
                eff_resource = (
                    resource
                    or granted.get("resource")
                    or _derive_resource(args, kwargs, resolved_action)
                )
                cred = sign_intent(
                    resolved_action,
                    target=eff_target,
                    resource=eff_resource,
                    signer=signer,
                    parent=parent,
                )
            except Exception as e:  # never let signing break the tool
                logger.warning("Vouch autosign failed for %s: %s", resolved_action, e)
                cred = None

            if wants_injection and INJECT_CREDENTIAL_KW not in kwargs:
                kwargs[INJECT_CREDENTIAL_KW] = cred

            return func(*args, **kwargs)

        wrapper.__vouch_signed__ = True  # type: ignore[attr-defined]
        return wrapper

    # Support both @signed and @signed(...)
    if fn is not None and callable(fn):
        return decorate(fn)
    return decorate


def _accepts_kwarg(func: Callable, name: str) -> bool:
    try:
        sig = inspect.signature(func)
    except (TypeError, ValueError):
        return False
    for p in sig.parameters.values():
        if p.kind == inspect.Parameter.VAR_KEYWORD:
            return True
        if p.name == name:
            return True
    return False


def install_decorator_autosign(
    module: Any,
    attr: str,
    *,
    signer: Optional[Signer] = None,
) -> bool:
    """Monkeypatch a framework's tool-*decorator* so every tool it produces is
    sign-wrapped.

    This is the engine behind each framework's ``autosign()``. It handles both
    decorator styles:

      * bare        ``@tool`` applied straight to a function, and
      * factory     ``@tool("name", ...)`` that returns a decorator.

    Idempotent: patching an already-patched decorator is a no-op. Returns
    ``True`` if it patched, ``False`` if it was already patched.

    Only frameworks that expose a single global tool-decorator (CrewAI,
    LangChain, AutoGPT) can use this. AutoGen has no decorator but registers
    tools through a call, so it uses :func:`install_callable_arg_autosign`
    instead. Frameworks whose tools are plain functions with no global hook
    (Vertex AI, Google, ADK) use ``protect([...])`` - the one-line equivalent.
    """
    original = getattr(module, attr)
    if getattr(original, "__vouch_autosign__", False):
        return False

    @functools.wraps(original)
    def patched(*args, **kwargs):
        # Bare use: the decorator is applied directly to the function.
        if len(args) == 1 and not kwargs and callable(args[0]):
            return original(signed(args[0], signer=signer))

        # Factory use: calling the decorator returns the real decorator, which
        # we wrap so it sign-wraps the function it receives.
        decorator = original(*args, **kwargs)

        def wrapping(func):
            return decorator(signed(func, signer=signer))

        return wrapping

    patched.__vouch_autosign__ = True  # type: ignore[attr-defined]
    setattr(module, attr, patched)
    return True


def install_callable_arg_autosign(
    module: Any,
    attr: str,
    *,
    signer: Optional[Signer] = None,
    arg_index: int = 0,
) -> bool:
    """Monkeypatch a module-level function that *takes a tool function as an
    argument* so the tool is sign-wrapped before it is used.

    This is the engine behind frameworks that register tools through a call
    rather than a decorator - e.g. ``autogen.register_function(fn, caller=...,
    executor=...)``. The function at ``arg_index`` (positional) is wrapped with
    :func:`signed`; everything else is passed through untouched.

    Idempotent; returns ``True`` if it patched, ``False`` if already patched.
    """
    original = getattr(module, attr)
    if getattr(original, "__vouch_autosign__", False):
        return False

    @functools.wraps(original)
    def patched(*args, **kwargs):
        args_list = list(args)
        if (
            len(args_list) > arg_index
            and callable(args_list[arg_index])
            and not getattr(args_list[arg_index], "__vouch_signed__", False)
        ):
            args_list[arg_index] = signed(args_list[arg_index], signer=signer)
        return original(*args_list, **kwargs)

    patched.__vouch_autosign__ = True  # type: ignore[attr-defined]
    setattr(module, attr, patched)
    return True


def protect(
    tools: Sequence[Callable],
    *,
    signer: Optional[Signer] = None,
    parent: Optional[Dict[str, Any]] = None,
    **signed_kwargs: Any,
) -> List[Callable]:
    """Sign-wrap a list of plain callable tools, preserving their signatures.

    The framework-agnostic counterpart to the per-framework ``protect``
    adapters. For frameworks whose tools are plain functions (AutoGen, AutoGPT,
    Vertex AI, Google) this is all that is needed::

        agent.tools = protect([search_db, send_email])

    Pass ``parent`` (a grant from :func:`delegate`) to chain every call under a
    delegation, narrowing-enforced::

        agent.tools = protect([charge_invoice], parent=grant)
    """
    out: List[Callable] = []
    for tool in tools:
        if getattr(tool, "__vouch_signed__", False):
            out.append(tool)  # already wrapped - idempotent
        else:
            out.append(signed(tool, signer=signer, parent=parent, **signed_kwargs))
    return out


__all__ = [
    "signed",
    "protect",
    "delegate",
    "install_decorator_autosign",
    "install_callable_arg_autosign",
    "sign_intent",
    "resolve_signer",
    "reset_default_signer",
    "current_credential",
    "current_token_header",
    "INJECT_CREDENTIAL_KW",
]
