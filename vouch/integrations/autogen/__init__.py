"""Vouch AutoGen integration - deterministic signing.

AutoGen has no global tool *decorator*, but it does register tools through a
module-level call, ``autogen.register_function(fn, caller=..., executor=...)``.
``autosign()`` patches that call so every registered tool is signed before the
executor runs it - near-zero setup::

    import vouch.integrations.autogen as va
    va.autosign()

    autogen.register_function(charge_invoice, caller=assistant, executor=user)
    # charge_invoice is now signed on every execution, transparently.

For tools you register some other way (e.g. the ``@user_proxy.register_for_
execution()`` decorator), wrap them with ``protect([...])`` or ``@signed``
instead - ``register_function`` is the only global hook AutoGen exposes.
"""

from typing import Optional

from vouch import Signer
from vouch.autosign import (
    current_credential,
    install_callable_arg_autosign,
    protect,
    sign_intent,
    signed,
)


def autosign(*, signer: Optional[Signer] = None) -> bool:
    """Near-zero setup: sign every tool registered via ``autogen.register_function``.

    Returns ``True`` if it patched, ``False`` if already patched. Raises if
    AutoGen is not installed.
    """
    try:
        import autogen
    except ImportError as e:  # pragma: no cover - optional dep
        raise RuntimeError("autogen is not installed; cannot autosign") from e
    return install_callable_arg_autosign(autogen, "register_function", signer=signer)


__all__ = [
    "protect",
    "signed",
    "autosign",
    "sign_intent",
    "current_credential",
]
