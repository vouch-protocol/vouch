# @vouch-protocol-official/mcp

A Vouch-protected MCP server. Change one import and every tool checks a
credential before it acts.

```ts
import { McpServer } from '@vouch-protocol-official/mcp';
// was: import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
```

Every tool registered on that server is protected. Before a tool body runs, the
call must arrive with a Vouch Credential that verifies, comes from a trusted
issuer, authorises *this exact call*, and passes your Shield rules. Any failure
is refused through the protocol's error path and the body is never entered.

This is the receiving side. A signer can decline to mint a credential, but it
cannot stop a client calling some other server. The check has to live where the
work happens.

## Install

```bash
npm install @vouch-protocol-official/mcp @modelcontextprotocol/sdk zod
```

## Use

```ts
import { McpServer } from '@vouch-protocol-official/mcp';
import { z } from 'zod';

const server = new McpServer({ name: 'files', version: '1.0.0' });

server.registerTool(
  'read_file',
  {
    inputSchema: { path: z.string() },
    resource: (args) => args.path as string,
  },
  async ({ path }: { path: string }) => ({
    content: [{ type: 'text', text: read(path) }],
  }),
);
```

The wrapper adds a required `credential` argument to each tool's schema and
consumes it before your function runs, so your function body is unchanged.

## Configuration

| Variable | Required | Meaning |
|---|---|---|
| `VOUCH_RULES` | yes | Path to the Shield rules file |
| `VOUCH_TRUSTED_ISSUERS` | yes | Comma-separated DIDs whose credentials are accepted |
| `VOUCH_TARGET` | no | `intent.target` to require. Defaults to the server name |

All three can be passed to the constructor instead. A server missing what it
needs **refuses to start**. It never starts unprotected.

## Rules

Rules match the same three fields a credential binds: `action`, `target`, and
`resource`.

```yaml
version: 2
rules:
  - did: did:web:agent.example.com
    allow:
      - { action: read_file, target: files, resource: "reports/**" }
deny_default: true
```

A segment is the text between `/` separators. `*` matches exactly one segment
and never crosses a `/`; `**` matches any number. Resources are normalised
first, so `reports/../etc/passwd` cannot slip through a `reports/**` rule.

That normalisation is lexical and cannot see a symlink, so a server mapping a
resource onto a real path must also confine that path itself.

## Resource binding

By default a credential authorises one call with one exact set of arguments:
`intent.resource` is the JCS canonicalisation of the argument object, so
changing any argument changes what the credential is for.

`resource` loosens that to a chosen value, which is what lets a rule glob over
paths or table names. Treat it as a policy decision worth making on purpose.

## Opting out

```ts
server.registerTool('health', { unprotected: true }, async () => ({
  content: [{ type: 'text', text: 'ok' }],
}));
```

Logs a warning at registration and on every call. Anything reachable without a
credential should be something you are happy for anyone to call.

## Refusals

A refused call throws `VouchRefusedError`, which the MCP protocol reports to the
client with `isError` set. A refusal is never returned as an ordinary value: a
returned object looks like a result, which a model can read straight past, and
an error cannot be mistaken for data.

Reasons are stable strings you can alert on: `no credential`,
`credential did not verify`, `untrusted issuer`,
`credential does not match request`, `no matching rule`,
`resource outside scope`, `unknown did`, `invalid resource`, `malformed rules`.

One structured line goes to stderr per decision:

```
ALLOW  did:key:z6Mk...  read_file  reports/q3.txt
DENY   did:key:z6Mk...  read_file  secrets/keys.txt  resource outside scope
```

## A note on typing

The SDK's `registerTool` is overloaded and generic, so an override that narrowed
it would not be assignable to the base class. The config object is typed by
`VouchToolConfig`, and tool callbacks take their argument type from an
annotation, as the example shows. Everything else passes through to the SDK
unchanged.

## Not using `McpServer`?

`protect(server)` applies the same checks to a server this package did not
construct. It cannot add a `credential` parameter to a schema it does not own,
so the tool has to accept one already. Prefer `McpServer` where you can: a
wrapper someone has to remember to apply is a wrapper someone will forget.

## Related

- `examples/mcp_server_ts/` in the repository, a working filesystem server.
- The Python equivalent is `vouch.mcp.FastMCP` in `vouch-protocol`.
- `test-vectors/shield/` is the cross-language contract both implementations meet.

Apache-2.0.
