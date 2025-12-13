from langchain.tools import tool
from vouch import Auditor
import os

class VouchCrewTools:
    @tool("Sign Request with Vouch")
    def sign_request(intent: str):
        """Generates a cryptographic Vouch-Token. Useful for proving identity to external APIs."""
        key = os.getenv("VOUCH_PRIVATE_KEY")
        did = os.getenv("VOUCH_DID")
        
        if not key: return "Error: VOUCH_PRIVATE_KEY not found."
        
        auditor = Auditor(key)
        proof = auditor.issue_vouch({"did": did, "integrity_hash": intent})
        return f"Vouch-Token: {proof['certificate']}"
