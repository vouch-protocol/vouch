"""
Vouch Protocol MCP Server - Model Context Protocol integration.

Provides a Standard-IO based MCP server for Claude Desktop, Cursor, and other
MCP-compatible clients.
"""

import sys
import json
import logging
import os
from typing import Optional, Dict, Any

from vouch import Signer


logging.basicConfig(level=logging.INFO, stream=sys.stderr)
logger = logging.getLogger(__name__)


class VouchMCPServer:
    """
    MCP Server providing Vouch identity signing capabilities.

    Exposes tools for AI agents to generate cryptographic Vouch-Tokens
    for authentication with external services.
    """

    def __init__(self):
        self._signer: Optional[Signer] = None
        self._did: Optional[str] = None
        self._load_credentials()

    def _load_credentials(self) -> None:
        """Load signing credentials from environment."""
        private_key = os.getenv("VOUCH_PRIVATE_KEY")
        did = os.getenv("VOUCH_DID")

        if private_key and did:
            try:
                self._signer = Signer(private_key=private_key, did=did)
                self._did = did
                logger.info(f"Vouch MCP Server initialized with DID: {did}")
            except Exception as e:
                logger.error(f"Failed to initialize signer: {e}")
        else:
            logger.warning("VOUCH_PRIVATE_KEY or VOUCH_DID not set")

    def _get_tools_list(self) -> list:
        """Return the list of available tools."""
        return [
            {
                "name": "sign_action",
                "description": "Generate a cryptographic Vouch-Token to sign a sensitive action. Use this before making authenticated API calls.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "intent": {
                            "type": "string",
                            "description": "What action are you taking? (e.g., 'read_email', 'send_payment', 'access_database')",
                        },
                        "target": {
                            "type": "string",
                            "description": "Optional: The target service or resource",
                        },
                    },
                    "required": ["intent"],
                },
            },
            {
                "name": "get_identity",
                "description": "Get the current agent's DID (Decentralized Identifier)",
                "inputSchema": {"type": "object", "properties": {}},
            },
        ]

    def process_request(self, line: str) -> Optional[Dict[str, Any]]:
        """Process an incoming MCP request."""
        try:
            request = json.loads(line.strip())
            request_id = request.get("id")
            method = request.get("method")

            # Handle initialize
            if method == "initialize":
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "vouch-mcp-server", "version": "1.1.3"},
                    },
                }

            # Handle tools/list
            if method == "tools/list":
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {"tools": self._get_tools_list()},
                }

            # Handle tools/call
            if method == "tools/call":
                params = request.get("params", {})
                tool_name = params.get("name")
                arguments = params.get("arguments", {})

                return self._handle_tool_call(request_id, tool_name, arguments)

            # Unknown method
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            }

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON: {e}")
            return None
        except Exception as e:
            logger.error(f"Request processing error: {e}")
            return {"jsonrpc": "2.0", "id": None, "error": {"code": -32603, "message": str(e)}}

    def _handle_tool_call(
        self, request_id: Any, tool_name: str, arguments: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Handle a tool call request."""

        if tool_name == "sign_action":
            if not self._signer:
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {
                        "code": -32603,
                        "message": "VOUCH_PRIVATE_KEY and VOUCH_DID must be set in environment",
                    },
                }

            intent = arguments.get("intent", "")
            target = arguments.get("target", "")

            try:
                payload = {"intent": intent}
                if target:
                    payload["target"] = target

                token = self._signer.sign(payload)

                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": f"Vouch-Token: {token}\n\nAdd this as a header: 'Vouch-Token: {token}'",
                            }
                        ]
                    },
                }
            except Exception as e:
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32603, "message": f"Signing failed: {e}"},
                }

        elif tool_name == "get_identity":
            did = self._did or "Not configured"
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {"content": [{"type": "text", "text": f"Agent DID: {did}"}]},
            }

        else:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32602, "message": f"Unknown tool: {tool_name}"},
            }

    def run(self) -> None:
        """Run the MCP server loop."""
        logger.info("Vouch MCP Server starting...")

        for line in sys.stdin:
            if not line.strip():
                continue

            response = self.process_request(line)
            if response:
                print(json.dumps(response), flush=True)


def main():
    """Entry point for the MCP server."""
    server = VouchMCPServer()
    server.run()


if __name__ == "__main__":
    main()
