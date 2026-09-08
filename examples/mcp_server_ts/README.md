# A Vouch-protected MCP server (TypeScript)

The TypeScript counterpart of [`examples/mcp_server/`](../mcp_server/). Same
four tools, same rules, same behaviour; the only difference is the language.

The one line that protects everything:

```ts
import { McpServer } from '@vouch-protocol-official/mcp';
// was: import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
```

## 30-second setup

```bash
# Mint an identity, write rules, create files to act on. The Python example's
# setup script does this and prints the environment both servers need.
python3 examples/mcp_server/setup_demo.py --out /tmp/vouch-demo

cd examples/mcp_server_ts
npm install
npm run build

export VOUCH_FS_ROOT="/tmp/vouch-demo"
export VOUCH_RULES="/tmp/vouch-demo/rules.yaml"
export VOUCH_TRUSTED_ISSUERS="did:key:z6Mk..."   # from the setup output
export VOUCH_TARGET="files"

npm start
```

A credential minted by `vouch-mcp` works against this server unchanged, because
both sides speak the same credential format and the same rules. That is the
point of running the same scene twice.

## Claude Desktop

```json
{
  "mcpServers": {
    "files-ts": {
      "command": "node",
      "args": ["/path/to/vouch-protocol/examples/mcp_server_ts/dist/server.js"],
      "env": {
        "VOUCH_FS_ROOT": "/tmp/vouch-demo",
        "VOUCH_RULES": "/tmp/vouch-demo/rules.yaml",
        "VOUCH_TRUSTED_ISSUERS": "did:key:z6Mk...",
        "VOUCH_TARGET": "files"
      }
    }
  }
}
```

## Two checks, not one

Shield rejects `..` traversal in the policy string. That matching is lexical, so
it cannot see a symlink pointing out of the directory. This server therefore
also resolves every path and confines it to `VOUCH_FS_ROOT`. Policy matching and
filesystem confinement are different jobs and neither substitutes for the other.

See the package [README](../../packages/vouch-mcp-ts/README.md) for
configuration, resource binding, and refusal reasons.
