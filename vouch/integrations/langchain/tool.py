from typing import Optional, Type
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
