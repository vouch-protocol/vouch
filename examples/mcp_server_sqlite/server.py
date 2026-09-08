#!/usr/bin/env python3
"""A Vouch-protected MCP server over SQLite.

The same one-line integration as ``examples/mcp_server``, on a resource that is
not a file path. Here the policy unit is a **table name**, so rules can say
``public.*`` and mean it.

That is the point of this example: ``vouch.mcp.FastMCP`` does not know or care
what a resource is. It binds the credential to whatever string the tool declares
as its resource, and Shield globs over that.

Run:
    VOUCH_RULES=examples/mcp_server_sqlite/rules.yaml \\
    VOUCH_TRUSTED_ISSUERS=did:key:z6Mk... \\
    VOUCH_TARGET=sqlite \\
    python3 examples/mcp_server_sqlite/server.py
"""

from __future__ import annotations

import sqlite3

from vouch.mcp import FastMCP  # the one line that protects everything below

mcp = FastMCP("sqlite")

_db = sqlite3.connect(":memory:", check_same_thread=False)
_db.row_factory = sqlite3.Row
_db.executescript(
    """
    CREATE TABLE IF NOT EXISTS "public.customers" (id INTEGER, name TEXT);
    CREATE TABLE IF NOT EXISTS "internal.salaries" (id INTEGER, amount INTEGER);
    INSERT INTO "public.customers" VALUES (1, 'Ada'), (2, 'Grace');
    INSERT INTO "internal.salaries" VALUES (1, 120000), (2, 130000);
    """
)


@mcp.tool(resource=lambda args: args["table"])
def run_query(table: str, where: str = "1=1") -> list[dict]:
    """Read rows from a table.

    The credential authorises one table, and Shield decides which tables this
    agent may reach. A rule of ``public.*`` permits ``public.customers`` and
    refuses ``internal.salaries``.

    Args:
        table: The table to read.
        where: A SQL WHERE clause. Defaults to all rows.
    """
    # The table name is policy-checked above; it is still quoted here rather
    # than interpolated raw, because an authorisation check is not an input
    # sanitiser and should never be asked to be one.
    quoted = '"' + table.replace('"', '""') + '"'
    rows = _db.execute(f"SELECT * FROM {quoted} WHERE {where}").fetchall()  # noqa: S608
    return [dict(row) for row in rows]


if __name__ == "__main__":
    mcp.run()
