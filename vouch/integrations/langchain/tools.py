from typing import Optional, Type
from pydantic import BaseModel, Field

# Try importing LangChain (It's optional, so we handle the error if missing)
try:
    from langchain.tools import BaseTool
except ImportError:
    # Fallback for users who don't have LangChain installed
    class BaseTool:
        pass

from vouch import Auditor

class VouchSignerInput(BaseModel):
    """Input for the Vouch Signer."""
    action_summary: str = Field(..., description="A brief summary of what action the agent is taking (e.g., 'booking_flight')")

class VouchSignerTool(BaseTool):
    name = "vouch_identity_signer"
    description = "Use this tool to generate a cryptographic Vouch-Token when you need to prove your identity to an external API."
    args_schema: Type[BaseModel] = VouchSignerInput

    # Private attributes
    _auditor: Auditor = None
    _did: str = None

    def __init__(self, private_key_json: str, agent_did: str):
        super().__init__()
        self._auditor = Auditor(private_key_json)
        self._did = agent_did

    def _run(self, action_summary: str) -> str:
        """Generates the Vouch-Token header."""

        # Create the payload based on the agent's intent
        vouch_data = {
            "did": self._did,
            "integrity_hash": f"action:{action_summary}" # Simple binding of intent
        }

        # Issue the token
        result = self._auditor.issue_vouch(vouch_data)

        # Return the ready-to-use header value
        return result['certificate']

    async def _arun(self, action_summary: str) -> str:
        """Async support (optional but good practice)."""
        return self._run(action_summary)
