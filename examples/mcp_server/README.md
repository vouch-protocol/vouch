# A Vouch-protected MCP server

An ordinary filesystem MCP server exposing `read_file`, `write_file`,
`delete_file` and `list_dir`. The only thing that makes it Vouch-protected is
one import:

```python
from vouch.mcp import FastMCP          # was: from mcp.server.fastmcp import FastMCP
```

Every tool registered on that server is protected by default. Before a tool body
runs, the call must arrive with a Vouch Credential that verifies, that was
issued by a trusted DID, that authorises *this exact call*, and that Shield's
rules permit. Any failure is refused and the body is never entered.

This is the receiving side of Vouch. `vouch-mcp` is a **signer**: it holds a key
and issues credentials. It cannot stop anyone from calling a different tool
server. The check has to live where the work happens, which is here.

## 30-second setup

```bash
pip install "vouch-protocol[mcp]"

# Mint an identity, write rules, create files to act on.
python3 examples/mcp_server/setup_demo.py --out /tmp/vouch-demo
```

That prints the environment to export. Then:

```bash
export VOUCH_FS_ROOT="/tmp/vouch-demo"
export VOUCH_RULES="/tmp/vouch-demo/rules.yaml"
export VOUCH_TRUSTED_ISSUERS="did:key:z6Mk..."     # from the setup output
export VOUCH_TARGET="files"

python3 examples/mcp_server/server.py
```

## Claude Desktop

```json
{
  "mcpServers": {
    "vouch": {
      "command": "vouch-mcp",
      "env": {
        "VOUCH_DID": "did:key:z6Mk...",
        "VOUCH_PRIVATE_KEY": "PASTE_THE_CONTENTS_OF_agent.jwk",
        "VOUCH_RULES": "/tmp/vouch-demo/rules.yaml"
      }
    },
    "files": {
      "command": "python3",
      "args": ["/path/to/vouch-protocol/examples/mcp_server/server.py"],
      "env": {
        "VOUCH_FS_ROOT": "/tmp/vouch-demo",
        "VOUCH_RULES": "/tmp/vouch-demo/rules.yaml",
        "VOUCH_TRUSTED_ISSUERS": "did:key:z6Mk...",
        "VOUCH_TARGET": "files",
        "PYTHONPATH": "/path/to/vouch-protocol"
      }
    }
  }
}
```

Two servers: `vouch` issues credentials, `files` demands them. Ask Claude to sign
`read_file` on `reports/q3.txt` with the first, then call the second with the
credential it got back.

## Configuration

| Variable | Required | Meaning |
|---|---|---|
| `VOUCH_FS_ROOT` | yes | Directory this server confines itself to |
| `VOUCH_RULES` | yes | Shield v2 rules file |
| `VOUCH_TRUSTED_ISSUERS` | yes | Comma-separated DIDs whose credentials are accepted |
| `VOUCH_TARGET` | no | `intent.target` to require. Defaults to the server name |
| `VOUCH_CHECK_REVOCATION` | no | `0` to skip status-list lookups. On by default |

A missing required variable makes the server **refuse to start**. It never
starts unprotected.

## What a decision looks like

One structured line per call, on stderr:

```
ALLOW  did:key:z6Mkgym...  read_file  reports/q3.txt
DENY   did:key:z6Mkgym...  read_file  secrets/keys.txt  resource outside scope
DENY   did:key:z6Mkgym...  read_file  reports/q4.txt    credential does not match request (intent.resource does not match these arguments)
DENY   -                   read_file  reports/q3.txt    no credential
```

Refusal reasons are stable strings you can grep and alert on: `no credential`,
`credential did not verify`, `credential revoked`, `untrusted issuer`,
`credential does not match request`, `no matching rule`, `resource outside
scope`, `unknown did`, `invalid resource`, `malformed rules`.

## The rules

`rules.yaml` matches on the same three fields the credential binds:

```yaml
version: 2
rules:
  - did: did:key:z6Mk...
    allow:
      - { action: read_file, target: files, resource: "reports/**" }
deny_default: true
```

A **segment** is the text between `/` separators. `*` matches exactly one
segment and never crosses a `/`; `**` matches any number, including zero. So
`reports/**` covers `reports/q3.txt` and `reports/2026/q3.txt`, but not
`secrets/keys.txt`.

Resources are normalised before matching: `..` and `.` are resolved, leading and
duplicate slashes collapse, and anything climbing above the root is refused
outright. `reports/../etc/passwd` becomes `etc/passwd` and does not match
`reports/**`.

That normalisation is lexical. It cannot see a symlink pointing out of the
directory, so this server *also* resolves every path and confines it to
`VOUCH_FS_ROOT`. Policy matching and filesystem confinement are two different
jobs and neither substitutes for the other.

## Resource binding

By default a credential authorises exactly one call with exactly one set of
arguments: `intent.resource` is the JCS canonicalisation of the whole argument
dict. Change any argument and the credential no longer matches.

The tools here opt into something coarser:

```python
@mcp.tool(resource=lambda args: args["path"])
def read_file(path: str) -> str: ...
```

Now `intent.resource` is the path, which is what lets a rule say `reports/**`
and mean it. That is a deliberate loosening, and a policy decision the tool
author is making. Treat it with the same seriousness as `unprotected=True`.

## Opting a tool out

```python
@mcp.tool(unprotected=True)
def health() -> str:
    return "ok"
```

Logs a warning when it is registered and on every call. Anything reachable
without a credential should be something you would be happy to see called by
anyone.

## Related

- `examples/mcp_server_sqlite/` - the same one-line integration where the
  resource is a table name rather than a path.
- `docs/design/shield-v2-and-protected-mcp.md` - the rule schema and the glob
  and normalisation spec.
