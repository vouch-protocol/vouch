from vouch import Auditor
import os
def sign_request_with_vouch(intent: str) -> str:
    key = os.environ.get("VOUCH_PRIVATE_KEY")
    did = os.environ.get("VOUCH_DID")
    if not key: return "Error: Keys missing"
    auditor = Auditor(key)
    proof = auditor.issue_vouch({"did": did, "integrity_hash": intent})
    return f"Vouch-Token: {proof['certificate']}"
