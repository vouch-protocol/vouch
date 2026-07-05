"""
Vouch Protocol Goose (Block) Integration.

Goose is an MCP client: its tools come from MCP servers registered as
"extensions" in ``~/.config/goose/config.yaml``. Vouch already ships an MCP
server (the ``vouch-mcp`` package), so making Goose Vouch-aware means
registering that server as a Goose extension. Then any Goose session can create
an identity, sign and verify credentials, scan for leaked keys, and decode DIDs
through the same tools every other MCP client uses.

:func:`extension_config` returns the config entry, and :func:`install` merges it
into the Goose config file, creating it if needed and leaving everything else
untouched.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

__all__ = ["EXTENSION_NAME", "goose_config_path", "extension_config", "install"]

EXTENSION_NAME = "vouch"


def goose_config_path() -> Path:
    """Return the Goose config file path, honoring ``XDG_CONFIG_HOME``."""
    base = os.environ.get("XDG_CONFIG_HOME")
    root = Path(base) if base else Path.home() / ".config"
    return root / "goose" / "config.yaml"


def extension_config(
    *,
    cmd: str = "vouch-mcp",
    args: Optional[List[str]] = None,
    timeout: int = 300,
) -> Dict[str, Any]:
    """Return the Goose config entry that runs vouch-mcp as a stdio extension.

    The shape matches Goose's stdio extension schema: ``enabled``, ``type``,
    ``cmd``, ``args``, and ``timeout``.
    """
    return {
        "enabled": True,
        "type": "stdio",
        "cmd": cmd,
        "args": list(args or []),
        "timeout": timeout,
    }


def install(
    *,
    name: str = EXTENSION_NAME,
    config_path: Optional[Path] = None,
    cmd: str = "vouch-mcp",
    args: Optional[List[str]] = None,
    timeout: int = 300,
    overwrite: bool = True,
) -> Path:
    """Register vouch-mcp as a Goose extension in the Goose config file.

    Merges an ``extensions.<name>`` entry into ``~/.config/goose/config.yaml``
    (or ``config_path``), creating the file and parent directories if needed and
    preserving any existing extensions and settings. Returns the path written.

    Set ``overwrite=False`` to leave an existing entry of the same name intact.
    """
    yaml = _require_yaml()
    path = Path(config_path) if config_path else goose_config_path()

    data: Dict[str, Any] = {}
    if path.exists():
        loaded = yaml.safe_load(path.read_text()) or {}
        if isinstance(loaded, dict):
            data = loaded

    extensions = data.get("extensions")
    if not isinstance(extensions, dict):
        extensions = {}
    if name in extensions and not overwrite:
        return path

    extensions[name] = extension_config(cmd=cmd, args=args, timeout=timeout)
    data["extensions"] = extensions

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False))
    return path


def _require_yaml():
    try:
        import yaml  # type: ignore

        return yaml
    except ImportError as e:  # pragma: no cover - optional dep
        raise RuntimeError(
            "PyYAML is required to edit the Goose config. Install it with: pip install pyyaml"
        ) from e


def _main() -> int:
    """Entry point for the ``vouch-goose`` command."""
    parser = argparse.ArgumentParser(
        prog="vouch-goose",
        description="Register the vouch-mcp server as a Goose extension.",
    )
    parser.add_argument(
        "--config", help="Path to the Goose config.yaml (default: ~/.config/goose/config.yaml)"
    )
    parser.add_argument("--name", default=EXTENSION_NAME, help="Extension name to use in Goose")
    parser.add_argument("--cmd", default="vouch-mcp", help="Command Goose runs for the extension")
    parser.add_argument(
        "--keep-existing",
        action="store_true",
        help="Do not overwrite an existing entry of the same name",
    )
    ns = parser.parse_args()

    path = install(
        name=ns.name,
        config_path=Path(ns.config) if ns.config else None,
        cmd=ns.cmd,
        overwrite=not ns.keep_existing,
    )
    print(f"Registered Goose extension '{ns.name}' (cmd: {ns.cmd}) in {path}")
    print("Start Goose and the Vouch tools are available.")
    return 0
