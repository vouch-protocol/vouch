# Vouch MCP Server - Quick Start

Cryptographically sign your AI agent's actions. Works with Claude Desktop, Cursor, and any MCP client.

---

## 🚀 Setup (3 Minutes)

### Step 1: Install

```bash
pip install vouch-protocol
```

### Step 2: Generate Identity (Copy-Paste Ready!)

```bash
vouch init --env
```

**Output:**
```bash
export VOUCH_DID='did:vouch:abc123...'
export VOUCH_PRIVATE_KEY='{"kty":"OKP","crv":"Ed25519",...}'
```

> 💡 Copy these values - you'll paste them in the next step!

### Step 3: Configure Claude Desktop

Edit your config file:

| OS | Path |
|----|------|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |

```json
{
  "mcpServers": {
    "vouch": {
      "command": "vouch-mcp",
      "env": {
        "VOUCH_PRIVATE_KEY": "<paste your key here>",
        "VOUCH_DID": "did:vouch:abc123..."
      }
    }
  }
}
```

### Step 4: Restart Claude Desktop

You'll see 🛠️ tools with:
- **sign_action** - Sign any action
- **get_identity** - Show your DID

---

## 💬 Try It!

> "What's my Vouch identity?"

> "Sign my intent to read my calendar"

Claude returns a cryptographic token:
```
Vouch-Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9...
```

---

## 🔧 Troubleshooting

### "VOUCH_PRIVATE_KEY or VOUCH_DID not set"

Your keys aren't being passed to the server. Check:
1. Did you paste the values from `vouch init --env`?
2. Is the JSON valid? (no trailing commas)

### Test the server manually

```bash
export VOUCH_DID='did:vouch:test'
export VOUCH_PRIVATE_KEY='{"kty":"OKP","crv":"Ed25519","x":"...","d":"..."}'

echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | vouch-mcp
```

---

## 📦 Links

- [Full MCP Tutorial](./mcp-tutorial.md) - Build your first MCP server with Vouch
- [GitHub](https://github.com/vouch-protocol/vouch)
- [MCP Specification](https://modelcontextprotocol.io)
