from vouch import Auditor
import os
from typing import Annotated

def sign_action(
    intent: Annotated[str, "The action you are about to take"]
) -> str:
    """
    Generates a Vouch-Token to sign a sensitive action for AutoGen agents.
    """
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
