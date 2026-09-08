#!/usr/bin/env python3
"""A Vouch-protected MCP server.

An ordinary filesystem MCP server. The only thing that makes it Vouch-protected
is the import on the next line: ``vouch.mcp.FastMCP`` protects every tool it
registers, so each call must arrive with a Vouch Credential that verifies and
that Shield permits, before the tool body runs.

Run:
    VOUCH_FS_ROOT=/tmp/vouch-demo \\
    VOUCH_RULES=examples/mcp_server/rules.yaml \\
    VOUCH_TRUSTED_ISSUERS=did:key:z6Mk... \\
    VOUCH_TARGET=files \\
    python3 examples/mcp_server/server.py

See README.md for the 30-second setup.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from vouch.mcp import FastMCP  # the one line that protects everything below

mcp = FastMCP("files")

_ROOT = Path(os.getenv("VOUCH_FS_ROOT", "")).expanduser()


def _resolve(path: str) -> Path:
    """Resolve a relative path inside the configured root, or refuse.

    Shield already rejects `..` traversal in the *policy* string. This is the
    second half of the job: policy matching is lexical, so it cannot see a
    symlink pointing out of the root. Both checks are needed, and neither
    replaces the other.
    """
    candidate = (_ROOT / path).resolve()
    root = _ROOT.resolve()
    if candidate != root and root not in candidate.parents:
        raise ValueError(f"path escapes VOUCH_FS_ROOT: {path}")
    return candidate


@mcp.tool(resource=lambda args: args["path"])
def read_file(path: str) -> str:
    """Read a file inside the server's root.

    Args:
        path: Path relative to the root, e.g. 'reports/q3.txt'.
    """
    return _resolve(path).read_text()


@mcp.tool(resource=lambda args: args["path"])
def write_file(path: str, content: str) -> str:
    """Write a file inside the server's root.

    Args:
        path: Path relative to the root.
        content: What to write.
    """
    target = _resolve(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)
    return f"wrote {len(content)} bytes to {path}"


@mcp.tool(resource=lambda args: args["path"])
def delete_file(path: str) -> str:
    """Delete a file inside the server's root.

    Args:
        path: Path relative to the root.
    """
    _resolve(path).unlink()
    return f"deleted {path}"


@mcp.tool(resource=lambda args: args["path"])
def list_dir(path: str = ".") -> list[str]:
    """List a directory inside the server's root.

    Args:
        path: Directory relative to the root. Defaults to the root itself.
    """
    return sorted(p.name for p in _resolve(path).iterdir())


def main() -> None:
    if not os.getenv("VOUCH_FS_ROOT"):
        sys.exit(
            "VOUCH_FS_ROOT is not set. This server refuses to run without a root "
            "directory to confine itself to."
        )
    if not _ROOT.is_dir():
        sys.exit(f"VOUCH_FS_ROOT is not a directory: {_ROOT}")
    mcp.run()


if __name__ == "__main__":
    main()
