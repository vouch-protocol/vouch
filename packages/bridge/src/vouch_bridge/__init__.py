"""
Vouch Bridge Daemon - Universal Adapter Core

A local daemon that securely holds Ed25519 keys and signs data on behalf of
adapters (Browser Extension, CLI, VSCode, etc.).
"""

from vouch_bridge.server import app, main

__version__ = "1.1.0"
__all__ = ["app", "main", "__version__"]
