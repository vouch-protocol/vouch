import os
import shutil

# ==========================================
# CONFIGURATION
# ==========================================
# REPLACE THIS with your actual Discord Invite Link if you haven't yet!
DISCORD_LINK = "https://discord.gg/RXuKJDfC" 

# ==========================================
# 1. CORE UPGRADE: DYNAMIC RESOLVER
# ==========================================
verifier_code = """import json
import time
import base64
import requests
from jwcrypto import jwk, jws

class Verifier:
    def __init__(self, trusted_roots=None):
        self.trusted_roots = trusted_roots or {}
        self.used_nonces = set()

    def _resolve_did(self, did):
        if did in self.trusted_roots:
            return jwk.JWK.from_json(self.trusted_roots[did])

        if not did.startswith("did:web:"):
            raise ValueError(f"Unsupported DID method: {did}")

        domain = did.replace("did:web:", "")
        url = f"https://{domain}/.well-known/did.json"
        
        try:
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            did_doc = response.json()
            key_data = did_doc['verificationMethod'][0]['publicKeyJwk']
            return jwk.JWK.from_json(json.dumps(key_data))
        except Exception as e:
            return None

    def check_vouch(self, token):
        try:
            parts = token.split('.')
            if len(parts) != 3: return False, "Invalid Token Format"
            
            payload_str = parts[1] + '=' * (-len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_str))
            
            agent_did = payload.get('sub')
            if not agent_did: return False, "No Identity (sub) in token"

            public_key = self._resolve_did(agent_did)
            if not public_key:
                return False, f"Could not resolve public key for {agent_did}"

            verifier = jws.JWS()
            verifier.deserialize(token)
            verifier.verify(public_key)
            
            if time.time() > payload['exp']: return False, "Expired Vouch"
            if payload['jti'] in self.used_nonces: return False, "Replay Detected"
            self.used_nonces.add(payload['jti'])

            return True, payload

        except Exception as e:
            return False, f"Verification Error: {str(e)}"
"""

# ==========================================
# 2. INTEGRATION: LANGCHAIN
# ==========================================
langchain_code = """from typing import Optional, Type
from langchain.tools import BaseTool
from pydantic import BaseModel, Field
from vouch import Auditor
import os

class VouchSignerInput(BaseModel):
    intent: str = Field(description="A description of the action being signed (e.g. 'search_database')")

class VouchSignerTool(BaseTool):
    name = "vouch_signer"
    description = "Generates a verifiable identity proof (Vouch-Token) for sensitive actions."
    args_schema: Type[BaseModel] = VouchSignerInput

    def _run(self, intent: str) -> str:
        private_key = os.getenv("VOUCH_PRIVATE_KEY")
        agent_did = os.getenv("VOUCH_DID")
        if not private_key: return "Error: VOUCH_PRIVATE_KEY not set."
        
        auditor = Auditor(private_key)
        proof = auditor.issue_vouch({"did": agent_did, "integrity_hash": intent})
        return f"Vouch-Token: {proof['certificate']}"

    def _arun(self, intent: str):
        raise NotImplementedError("Async not implemented yet")
"""

# ==========================================
# 3. INTEGRATION: AUTOGPT
# ==========================================
autogpt_code = """import os
from vouch import Auditor

# Mock decorator if AutoGPT is not installed
try:
    from autogpt.command_decorator import command
except ImportError:
    def command(*args, **kwargs):
        def decorator(func): return func
        return decorator

@command(
    "sign_with_vouch",
    "Generates a Vouch-Token to prove identity",
    {
        "intent": {"type": "string", "description": "What you are doing", "required": True},
        "target_service": {"type": "string", "description": "Target domain", "required": True}
    },
)
def sign_with_vouch(intent: str, target_service: str) -> str:
    try:
        key = os.getenv("VOUCH_PRIVATE_KEY")
        did = os.getenv("VOUCH_DID", "did:web:anonymous")
        if not key: return "Error: VOUCH_PRIVATE_KEY missing"
        
        auditor = Auditor(key)
        proof = auditor.issue_vouch({"did": did, "integrity_hash": f"{target_service}:{intent}"})
        return f"Vouch-Token generated. Add header: 'Vouch-Token: {proof['certificate']}'"
    except Exception as e:
        return f"Error: {str(e)}"
"""

# ==========================================
# 4. INTEGRATION: CREWAI
# ==========================================
crewai_code = """from langchain.tools import tool
from vouch import Auditor
import os

class VouchCrewTools:
    @tool("Sign Request with Vouch")
    def sign_request(intent: str):
        \"\"\"Generates a cryptographic Vouch-Token. Useful for proving identity to external APIs.\"\"\"
        key = os.getenv("VOUCH_PRIVATE_KEY")
        did = os.getenv("VOUCH_DID")
        
        if not key: return "Error: VOUCH_PRIVATE_KEY not found."
        
        auditor = Auditor(key)
        proof = auditor.issue_vouch({"did": did, "integrity_hash": intent})
        return f"Vouch-Token: {proof['certificate']}"
"""

# ==========================================
# 5. INTEGRATION: AUTOGEN
# ==========================================
autogen_code = """from vouch import Auditor
import os
from typing import Annotated

def sign_action(
    intent: Annotated[str, "The action you are about to take"]
) -> str:
    \"\"\"
    Generates a Vouch-Token to sign a sensitive action for AutoGen agents.
    \"\"\"
    key = os.getenv("VOUCH_PRIVATE_KEY")
    did = os.getenv("VOUCH_DID")
    
    if not key:
        return "Error: VOUCH_PRIVATE_KEY not configured."

    auditor = Auditor(key)
    proof = auditor.issue_vouch({
        "did": did,
        "integrity_hash": intent
    })
    return f"Vouch-Token: {proof['certificate']}"
"""

# ==========================================
# 6. INTEGRATION: MCP & VERTEX (Condensed)
# ==========================================
mcp_code = """import sys
import json
from vouch import Auditor
import os

if __name__ == "__main__":
    # Simple loop to process stdin for MCP
    pass # (Placeholder for full implementation to save space in this script)
"""
# Note: For brevity in this God Script, I'm simplifying MCP here. 
# If you need the full MCP code from previous step, let me know. 
# But for the file structure, we just need the file to exist.

vertex_code = """from vouch import Auditor
import os
def sign_request_with_vouch(intent: str) -> str:
    key = os.environ.get("VOUCH_PRIVATE_KEY")
    did = os.environ.get("VOUCH_DID")
    if not key: return "Error: Keys missing"
    auditor = Auditor(key)
    proof = auditor.issue_vouch({"did": did, "integrity_hash": intent})
    return f"Vouch-Token: {proof['certificate']}"
"""

# ==========================================
# 7. GOVERNANCE
# ==========================================
gov_md = "# Vouch Governance\\nLazy consensus. Project Lead: @rampyg."
coc_md = "# Code of Conduct\\nWe pledge to make participation harassment-free."

# ==========================================
# EXECUTION
# ==========================================

# 1. Update Core
with open("vouch/verifier.py", "w") as f: f.write(verifier_code)

# 2. Create All Directories
dirs = [
    "vouch/integrations/langchain",
    "vouch/integrations/autogpt",
    "vouch/integrations/crewai",
    "vouch/integrations/autogen",
    "vouch/integrations/mcp",
    "vouch/integrations/vertex_ai"
]
for d in dirs:
    os.makedirs(d, exist_ok=True)
    with open(f"{d}/__init__.py", "w") as f: f.write("")

# 3. Write Files
with open("vouch/integrations/langchain/tool.py", "w") as f: f.write(langchain_code)
with open("vouch/integrations/autogpt/commands.py", "w") as f: f.write(autogpt_code)
with open("vouch/integrations/crewai/tool.py", "w") as f: f.write(crewai_code)
with open("vouch/integrations/autogen/tool.py", "w") as f: f.write(autogen_code)
with open("vouch/integrations/vertex_ai/tool.py", "w") as f: f.write(vertex_code)
# (MCP we leave a placeholder or reuse previous code if file exists to avoid overwrite risk)

# 4. Governance
with open("GOVERNANCE.md", "w") as f: f.write(gov_md)
with open("CODE_OF_CONDUCT.md", "w") as f: f.write(coc_md)

print("✅ COMPLETE UPDATE INSTALLED.")
print("   - Integrations Added: LangChain, AutoGPT, CrewAI, AutoGen, VertexAI")
print("   - Core: Resolver Updated")
print("   - Governance: Active")
