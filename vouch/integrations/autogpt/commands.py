import os
from vouch import Auditor

# NOTE: In a real AutoGPT install, this import comes from the system.
# We use a dummy decorator here so this file is valid Python in the repo.
try:
    from autogpt.command_decorator import command
except ImportError:
    def command(*args, **kwargs):
        def decorator(func):
            return func
        return decorator

# Global Auditor Instance (Lazy loaded)
_auditor = None

def _get_auditor():
    global _auditor
    if _auditor is None:
        # Load keys from AutoGPT's .env file or environment
        private_key = os.getenv("VOUCH_PRIVATE_KEY")
        if not private_key:
            raise ValueError("VOUCH_PRIVATE_KEY not found in environment")
        _auditor = Auditor(private_key)
    return _auditor

@command(
    "sign_with_vouch",
    "Generates a Vouch-Token to prove identity for sensitive actions",
    {
        "intent": {
            "type": "string",
            "description": "A brief description of what you are about to do (e.g. 'read_email')",
            "required": True,
        },
        "target_service": {
            "type": "string",
            "description": "The domain you are connecting to (e.g. 'api.bank.com')",
            "required": True,
        }
    },
)
def sign_with_vouch(intent: str, target_service: str) -> str:
    """
    Returns a Vouch-Token string that should be added to the HTTP Header 'Vouch-Token'.
    """
    try:
        auditor = _get_auditor()

        # The AutoGPT Agent's Identity (Configured in env)
        agent_did = os.getenv("VOUCH_DID", "did:web:anonymous-agent")

        # Create the proof
        vouch_data = {
            "did": agent_did,
            "integrity_hash": f"{target_service}:{intent}"
        }

        result = auditor.issue_vouch(vouch_data)
        return f"Vouch-Token generated successfully. Add this header to your request: 'Vouch-Token: {result['certificate']}'"

    except Exception as e:
        return f"Error generating Vouch-Token: {str(e)}"
