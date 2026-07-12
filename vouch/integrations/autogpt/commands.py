"""
Vouch Protocol AutoGPT Integration - deterministic signing.

AutoGPT exposes commands through the ``@command`` decorator, so all three tiers
apply:

  * ``protect([...])``  - wrap a list of commands (one line)
  * ``@signed``         - annotate a single command (one decorator)
  * ``autosign()``      - sign every ``@command`` framework-wide (near-zero)

See :mod:`vouch.autosign` for the framework-agnostic core.
"""

from typing import Optional

from vouch import Signer
from vouch.autosign import (  # noqa: F401
    current_credential,
    install_decorator_autosign,
    protect,
    sign_intent,
    signed,
)


def autosign(*, signer: Optional[Signer] = None) -> bool:
    """Near-zero setup: sign **every** AutoGPT command defined after this call.

    Monkeypatches ``autogpt.command_decorator.command`` so any command created
    with ``@command(...)`` is automatically sign-wrapped::

        import vouch.integrations.autogpt as va
        va.autosign()

        @command("read_email", ...)      # signed transparently
        def read_email(...): ...
    """
    try:
        import autogpt.command_decorator as cmd_module
    except ImportError as e:  # pragma: no cover - optional dep
        raise RuntimeError("autogpt is not installed; cannot autosign") from e
    return install_decorator_autosign(cmd_module, "command", signer=signer)
