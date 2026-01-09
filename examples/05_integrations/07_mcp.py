#!/usr/bin/env python3
"""
07_mcp.py - Vouch with Model Context Protocol

Sign MCP tool calls for Claude and other LLMs.

Run: python 07_mcp.py
"""

from vouch import Signer

print("🔌 MCP (Model Context Protocol) + Vouch")
print("=" * 50)

# =============================================================================
# MCP Server with Vouch
# =============================================================================

print("""
# MCP Server with Vouch Signing

from mcp.server import MCPServer
from vouch.integrations.mcp import VouchMCPServer

server = VouchMCPServer(
    signer=Signer(name="MCP Server"),
    tools=[
        {
            "name": "read_file",
            "description": "Read a file",
            "parameters": {"path": {"type": "string"}}
        },
        {
            "name": "write_file", 
            "description": "Write to a file",
            "parameters": {"path": {"type": "string"}, "content": {"type": "string"}}
        }
    ]
)

# Every tool call is automatically signed
@server.tool("read_file")
def read_file(path: str) -> str:
    # This call is signed before execution
    return open(path).read()

@server.tool("write_file")
def write_file(path: str, content: str) -> str:
    # This call is signed before execution
    with open(path, "w") as f:
        f.write(content)
    return f"Wrote {len(content)} bytes to {path}"

server.run()
""")

# =============================================================================
# Demo
# =============================================================================

signer = Signer(name="MCP Server")

# Simulate MCP tool call
tool_call = {
    "tool": "write_file",
    "params": {"path": "/data/output.txt", "content": "Hello World"},
    "request_id": "req_123"
}

import json
token = signer.sign(json.dumps(tool_call))

print(f"\n📋 Signed MCP Tool Call:")
print(f"   Tool: {tool_call['tool']}")
print(f"   Params: {tool_call['params']}")
print(f"   Token: {token[:50]}...")

print("""
✅ MCP Benefits:
   • All Claude tool calls signed
   • Works with Claude Desktop
   • Interoperable with other MCP clients
   • Full audit trail
""")
