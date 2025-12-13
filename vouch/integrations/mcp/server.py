import sys
import json
import logging
from vouch import Auditor

# A simple Standard-IO Model Context Protocol (MCP) Server
# This allows Claude Desktop or Cursor to "use" Vouch tools locally.

logging.basicConfig(level=logging.INFO, stream=sys.stderr)

class VouchMCPServer:
    def __init__(self):
        self.auditor = None
        # Try to load keys from env
        self.load_keys()

    def load_keys(self):
        # In a real app, manage this securely. For MVP, we look for env vars.
        import os
        key = os.getenv("VOUCH_PRIVATE_KEY")
        if key:
            self.auditor = Auditor(key)

    def process_request(self, line):
        try:
            request = json.loads(line)
            if request.get("method") == "tools/list":
                return {
                    "jsonrpc": "2.0",
                    "id": request["id"],
                    "result": {
                        "tools": [{
                            "name": "sign_action",
                            "description": "Generate a cryptographic Vouch-Token to sign a sensitive action.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "intent": {"type": "string", "description": "What are you doing? (e.g. 'read_email')"},
                                    "did": {"type": "string", "description": "Your Agent DID"}
                                },
                                "required": ["intent", "did"]
                            }
                        }]
                    }
                }
            elif request.get("method") == "tools/call":
                if request["params"]["name"] == "sign_action":
                    if not self.auditor:
                        return {"jsonrpc": "2.0", "id": request["id"], "error": {"code": -32603, "message": "VOUCH_PRIVATE_KEY not set in env"}}
                    
                    args = request["params"]["arguments"]
                    proof = self.auditor.issue_vouch({
                        "did": args["did"],
                        "integrity_hash": args["intent"]
                    })
                    return {
                        "jsonrpc": "2.0", "id": request["id"],
                        "result": {"content": [{"type": "text", "text": proof["certificate"]}]}
                    }
        except Exception as e:
            pass
        return None

if __name__ == "__main__":
    server = VouchMCPServer()
    # MCP loop
    for line in sys.stdin:
        response = server.process_request(line)
        if response:
            print(json.dumps(response))
            sys.stdout.flush()
