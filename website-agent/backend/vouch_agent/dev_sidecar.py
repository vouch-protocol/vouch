"""Local development entry point for the signing sidecar.

Equivalent to ``python -m vouch_agent.sidecar --dev``: an ephemeral key that
lives only in this process. Kept so existing local setups keep working.

Run with:
    python -m vouch_agent.dev_sidecar --port 8877
"""

from __future__ import annotations

import sys

from .sidecar import main as _sidecar_main


def main() -> None:
    _sidecar_main([*sys.argv[1:], "--dev"])


if __name__ == "__main__":
    main()
