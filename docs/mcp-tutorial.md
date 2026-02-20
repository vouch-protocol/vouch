# MCP + Vouch Tutorial: Build Your First Signed AI Agent

This tutorial shows you how to build an MCP server from scratch, then add Vouch for cryptographic authentication.

**Time:** 15 minutes  
**Prerequisites:** Python 3.9+, basic terminal skills

---

## Part 1: MCP Without Vouch (The Problem)

First, let's see how a basic MCP server works - and why it's insecure.

### Step 1: Create a Simple MCP Server

Create `my_mcp_server.py`:

```python
#!/usr/bin/env python3
"""
A simple MCP server WITHOUT authentication.
Problem: Anyone can claim to be this agent!
"""

import sys
import json

def handle_request(request):
    """Handle incoming MCP requests."""
    method = request.get("method")
    request_id = request.get("id")
    
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "my-agent", "version": "1.0.0"}
            }
        }
    
    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "tools": [
                    {
                        "name": "send_email",
                        "description": "Send an email on behalf of the user",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "to": {"type": "string"},
                                "subject": {"type": "string"},
                                "body": {"type": "string"}
                            },
                            "required": ["to", "subject", "body"]
                        }
                    }
                ]
            }
        }
    
    if method == "tools/call":
        params = request.get("params", {})
        tool_name = params.get("name")
        arguments = params.get("arguments", {})
        
        if tool_name == "send_email":
            # ⚠️ PROBLEM: No proof this request came from an authorized agent!
            # Any script could pretend to be this MCP server.
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": [{
                        "type": "text",
                        "text": f"Email sent to {arguments.get('to')}"
                    }]
                }
            }
    
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": "Unknown method"}}


def main():
    """MCP server loop - reads JSON-RPC from stdin, writes to stdout."""
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            request = json.loads(line)
            response = handle_request(request)
            print(json.dumps(response), flush=True)
        except Exception as e:
            print(json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32603, "message": str(e)}}), flush=True)


if __name__ == "__main__":
    main()
```

### Step 2: Test It

```bash
# Test the server
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | python my_mcp_server.py
```

**Output:**
```json
{"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "send_email", ...}]}}
```

### The Problem 🚨

This works, but there's no authentication. Any script could:
1. Pretend to be your MCP server
2. Send emails on your behalf
3. Claim actions were authorized by you

**How do external services know this request is legitimate?**

---

## Part 2: Add Vouch (The Solution)

Now let's add cryptographic identity.

### Step 1: Install Vouch

```bash
pip install vouch-protocol
```

### Step 2: Generate Your Agent's Identity

```bash
vouch init --env
```

Copy the output - you'll need `VOUCH_DID` and `VOUCH_PRIVATE_KEY`.

### Step 3: Create a Vouch-Enabled MCP Server

Create `my_vouch_mcp_server.py`:

```python
#!/usr/bin/env python3
"""
MCP server WITH Vouch authentication.
Every action is cryptographically signed!
"""

import sys
import json
import os

# Import Vouch
from vouch import Signer

# Load identity from environment
VOUCH_DID = os.getenv("VOUCH_DID")
VOUCH_PRIVATE_KEY = os.getenv("VOUCH_PRIVATE_KEY")

# Initialize signer (if credentials available)
signer = None
if VOUCH_DID and VOUCH_PRIVATE_KEY:
    signer = Signer(private_key=VOUCH_PRIVATE_KEY, did=VOUCH_DID)
    print(f"✓ Vouch identity loaded: {VOUCH_DID}", file=sys.stderr)


def handle_request(request):
    """Handle incoming MCP requests with Vouch signing."""
    method = request.get("method")
    request_id = request.get("id")
    
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "my-vouch-agent", "version": "1.0.0"}
            }
        }
    
    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "tools": [
                    {
                        "name": "send_email",
                        "description": "Send a signed email on behalf of the user",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "to": {"type": "string"},
                                "subject": {"type": "string"},
                                "body": {"type": "string"}
                            },
                            "required": ["to", "subject", "body"]
                        }
                    },
                    {
                        "name": "get_identity",
                        "description": "Get this agent's cryptographic identity",
                        "inputSchema": {"type": "object", "properties": {}}
                    }
                ]
            }
        }
    
    if method == "tools/call":
        params = request.get("params", {})
        tool_name = params.get("name")
        arguments = params.get("arguments", {})
        
        if tool_name == "get_identity":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": [{
                        "type": "text",
                        "text": f"Agent DID: {VOUCH_DID or 'Not configured'}"
                    }]
                }
            }
        
        if tool_name == "send_email":
            if not signer:
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32603, "message": "Vouch identity not configured"}
                }
            
            # ✅ SOLUTION: Sign the action with Vouch!
            payload = {
                "action": "send_email",
                "to": arguments.get("to"),
                "subject": arguments.get("subject"),
            }
            vouch_token = signer.sign(payload)
            
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": [{
                        "type": "text",
                        "text": f"""✅ Email action signed!

To: {arguments.get('to')}
Subject: {arguments.get('subject')}

Vouch-Token: {vouch_token}

This token proves the request came from: {VOUCH_DID}
External services can verify this token to confirm authenticity."""
                    }]
                }
            }
    
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": "Unknown method"}}


def main():
    """MCP server loop."""
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            request = json.loads(line)
            response = handle_request(request)
            print(json.dumps(response), flush=True)
        except Exception as e:
            print(json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32603, "message": str(e)}}), flush=True)


if __name__ == "__main__":
    main()
```

### Step 4: Test It

```bash
# Set your identity (from vouch init --env)
export VOUCH_DID='did:vouch:abc123'
export VOUCH_PRIVATE_KEY='{"kty":"OKP","crv":"Ed25519",...}'

# Test sending a signed email
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send_email","arguments":{"to":"alice@example.com","subject":"Hello","body":"Test"}}}' | python my_vouch_mcp_server.py
```

**Output:**
```json
{
  "result": {
    "content": [{
      "text": "✅ Email action signed!\n\nTo: alice@example.com\nSubject: Hello\n\nVouch-Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9...\n\nThis token proves the request came from: did:vouch:abc123"
    }]
  }
}
```

---

## Part 3: Even Easier - Use the Built-in Server

Vouch includes a ready-to-use MCP server. Just run:

```bash
vouch-mcp
```

Configure Claude Desktop to use it:

```json
{
  "mcpServers": {
    "vouch": {
      "command": "vouch-mcp",
      "env": {
        "VOUCH_PRIVATE_KEY": "<your key>",
        "VOUCH_DID": "did:vouch:..."
      }
    }
  }
}
```

---

## Summary

| Without Vouch | With Vouch |
|---------------|------------|
| No proof of identity | Cryptographic DID |
| Anyone can impersonate | Actions are signed |
| No audit trail | Verifiable tokens |

**Next Steps:**
- [MCP Quickstart](./mcp-quickstart.md) - Get running in 3 minutes
- [Vouch Documentation](https://vouch-protocol.com)
