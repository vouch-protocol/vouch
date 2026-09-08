# A Vouch-protected MCP server over SQLite

The same one-line integration as `examples/mcp_server/`, on a resource that is
not a file path.

```python
from vouch.mcp import FastMCP          # was: from mcp.server.fastmcp import FastMCP
```

This example exists to show that `vouch.mcp.FastMCP` does not know or care what
a resource is. Here the policy unit is a **table name**:

```python
@mcp.tool(resource=lambda args: args["table"])
def run_query(table: str, where: str = "1=1") -> list[dict]: ...
```

so a rule can say:

```yaml
- { action: run_query, target: sqlite, resource: "public.*" }
```

A table name contains no `/`, so the whole string is one segment and `*` matches
any run of characters within it. The `.` is a literal character, not a wildcard.
`public.*` therefore permits `public.customers` and refuses
`internal.salaries`.

## Run it

```bash
pip install "vouch-protocol[mcp]"

export VOUCH_RULES="examples/mcp_server_sqlite/rules.yaml"
export VOUCH_TRUSTED_ISSUERS="did:key:z6Mk..."
export VOUCH_TARGET="sqlite"

python3 examples/mcp_server_sqlite/server.py
```

Edit `rules.yaml` to name your agent's DID first. `setup_demo.py` in the
filesystem example mints one if you need it.

## One thing worth noticing

The table name is authorisation-checked before the query runs, and it is *still*
quoted before it reaches SQL. An authorisation check answers "may this agent
touch this table"; it is not an input sanitiser and should never be asked to be
one. Two different jobs.
