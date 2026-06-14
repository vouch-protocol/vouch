"""
Vouch Protocol LangChain Integration.

Provides a LangChain-compatible tool that issues v1.0 Vouch Credentials
(eddsa-jcs-2022 Data Integrity proofs) to authorize agent tool calls.
"""

from typing import Optional, Type

from pydantic import BaseModel, Field

try:
    from langchain.tools import BaseTool
except ImportError:
    # Fallback so this module imports without LangChain installed.
    class BaseTool:  # type: ignore
        """Fallback BaseTool class."""

        name: str = ""
        description: str = ""

        def _run(self, *args, **kwargs):
            raise NotImplementedError("LangChain not installed")


from vouch import Signer
from vouch.integrations._common import load_signer, sign_tool_call_json


class VouchSignerInput(BaseModel):
    """Input schema for the Vouch signer tool."""

    action: str = Field(
        description="The verb for the call, e.g. 'read', 'write', 'execute', 'send'."
    )
    target: str = Field(
        description="The service or URL being called, e.g. 'https://api.example.com'."
    )
    resource: Optional[str] = Field(
        default=None,
        description=(
            "The specific object being acted on, e.g. 'customer:123'. "
            "Defaults to the target when omitted."
        ),
    )


class VouchSignerTool(BaseTool):
    """LangChain tool that issues a Vouch Credential for a single tool call.

    Use it before an authenticated call to an external service. Attach the
    returned JSON as a 'Vouch-Credential' header or send it in the request body.

    Example:
        >>> from vouch.integrations.langchain.tool import VouchSignerTool
        >>> tool = VouchSignerTool()  # reads VOUCH_PRIVATE_KEY / VOUCH_DID
        >>> cred = tool._run("read", "https://api.example.com", "customer:123")
    """

    name: str = "vouch_signer"
    description: str = (
        "Issue a cryptographic Vouch Credential authorizing one tool call. "
        "Call this before any authenticated request to an external service. "
        "Attach the returned JSON as a 'Vouch-Credential' header."
    )
    args_schema: Type[BaseModel] = VouchSignerInput

    _signer: Optional[Signer] = None

    def __init__(
        self,
        private_key_json: Optional[str] = None,
        agent_did: Optional[str] = None,
        **kwargs,
    ):
        """Initialize the tool.

        Args:
            private_key_json: JWK JSON string. Falls back to VOUCH_PRIVATE_KEY.
            agent_did: The agent DID. Falls back to VOUCH_DID.
        """
        super().__init__(**kwargs)
        if private_key_json and agent_did:
            try:
                self._signer = Signer(private_key=private_key_json, did=agent_did)
            except Exception:
                self._signer = None

    def _get_signer(self) -> Signer:
        if self._signer is None:
            self._signer = load_signer()
        return self._signer

    def _run(self, action: str, target: str, resource: Optional[str] = None) -> str:
        """Issue a credential and return it as compact JSON, or an error string."""
        try:
            signer = self._get_signer()
            return sign_tool_call_json(signer, action, target, resource)
        except Exception as e:
            return f"Error issuing Vouch Credential: {e}"

    async def _arun(self, action: str, target: str, resource: Optional[str] = None) -> str:
        """Async variant of _run."""
        return self._run(action, target, resource)
