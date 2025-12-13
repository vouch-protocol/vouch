import os
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
