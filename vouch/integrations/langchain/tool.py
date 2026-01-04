"""
Vouch Protocol LangChain Integration.

Provides a LangChain-compatible tool for generating Vouch-Tokens.
"""

from typing import Type, Optional
import os

from pydantic import BaseModel, Field

try:
    from langchain.tools import BaseTool
except ImportError:
    # Fallback for users without LangChain
    class BaseTool:
        """Fallback BaseTool class."""

        name: str = ""
        description: str = ""

        def _run(self, *args, **kwargs):
            raise NotImplementedError("LangChain not installed")


from vouch import Signer


class VouchSignerInput(BaseModel):
    """Input schema for the Vouch Signer tool."""

    intent: str = Field(
        description="A description of the action being signed (e.g., 'search_database', 'send_email')"
    )
    target: Optional[str] = Field(default=None, description="Optional target service or resource")


class VouchSignerTool(BaseTool):
    """
    LangChain tool for generating Vouch-Tokens.

    Use this tool to generate cryptographic identity proofs before making
    authenticated API calls to external services.

    Example:
        >>> from vouch.integrations.langchain.tool import VouchSignerTool
        >>> tool = VouchSignerTool()  # Uses env vars
        >>> token = tool._run("read_customer_data")
    """

    name: str = "vouch_signer"
    description: str = (
        "Generates a cryptographic Vouch-Token to prove your identity. "
        "Use this before making authenticated API calls to external services. "
        "The token should be included as a 'Vouch-Token' header in your request."
    )
    args_schema: Type[BaseModel] = VouchSignerInput

    # Instance configuration
    _signer: Optional[Signer] = None

    def __init__(
        self, private_key_json: Optional[str] = None, agent_did: Optional[str] = None, **kwargs
    ):
        """
        Initialize the Vouch Signer tool.

        Args:
            private_key_json: JWK JSON string. Falls back to VOUCH_PRIVATE_KEY env var.
            agent_did: The agent's DID. Falls back to VOUCH_DID env var.
        """
        super().__init__(**kwargs)

        private_key = private_key_json or os.getenv("VOUCH_PRIVATE_KEY")
        did = agent_did or os.getenv("VOUCH_DID")

        if private_key and did:
            try:
                self._signer = Signer(private_key=private_key, did=did)
            except Exception:
                # Log but don't fail initialization
                pass

    def _run(self, intent: str, target: Optional[str] = None) -> str:
        """
        Generate a Vouch-Token for the given intent.

        Args:
            intent: Description of the action being taken.
            target: Optional target service.

        Returns:
            The Vouch-Token string or an error message.
        """
        if not self._signer:
            private_key = os.getenv("VOUCH_PRIVATE_KEY")
            did = os.getenv("VOUCH_DID")

            if not private_key:
                return "Error: VOUCH_PRIVATE_KEY not set in environment"
            if not did:
                return "Error: VOUCH_DID not set in environment"

            try:
                self._signer = Signer(private_key=private_key, did=did)
            except Exception as e:
                return f"Error initializing signer: {e}"

        try:
            payload = {"intent": intent}
            if target:
                payload["target"] = target

            token = self._signer.sign(payload)
            return f"Vouch-Token: {token}"

        except Exception as e:
            return f"Error signing: {e}"

    async def _arun(self, intent: str, target: Optional[str] = None) -> str:
        """Async version of _run."""
        return self._run(intent, target)
