"""
Vouch Protocol n8n Integration.

Provides helper code for using Vouch in n8n Python Code Nodes.
"""

import os
from typing import Dict, Any, List

from vouch import Signer


class N8NHelper:
    """Helper for generating n8n-compatible Python code blocks."""

    @staticmethod
    def get_code_node_snippet() -> str:
        """Returns the Python code for n8n Code Node."""
        return """
# n8n Python Code Node for Vouch Identity
# ----------------------------------------
# Prerequisite: Set EXTERNAL_PYTHON_PACKAGES=vouch-protocol in n8n env
# Also set VOUCH_PRIVATE_KEY and VOUCH_DID environment variables

from vouch import Signer
import os

# 1. CONFIG: Get Identity from Environment Variables
private_key = os.environ.get('VOUCH_PRIVATE_KEY')
did = os.environ.get('VOUCH_DID')

if not private_key or not did:
    raise ValueError("VOUCH_PRIVATE_KEY and VOUCH_DID must be set")

signer = Signer(private_key=private_key, did=did)

# 2. PROCESS: Sign every item in the workflow
for item in _input.all():
    # Create payload with item data
    payload = {
        "intent": "n8n_workflow",
        "data": item.json
    }
    
    # Generate the Vouch-Token
    item.json['vouch_token'] = signer.sign(payload)

return _input.all()
"""

    @staticmethod
    def sign_workflow_item(item_data: Dict[str, Any]) -> str:
        """
        Sign a workflow item.

        Args:
            item_data: The workflow item data.

        Returns:
            Vouch-Token or error message.
        """
        private_key = os.getenv("VOUCH_PRIVATE_KEY")
        did = os.getenv("VOUCH_DID")

        if not private_key:
            return "Error: VOUCH_PRIVATE_KEY not set"
        if not did:
            return "Error: VOUCH_DID not set"

        try:
            signer = Signer(private_key=private_key, did=did)

            payload = {"intent": "n8n_workflow", "data": item_data}

            return signer.sign(payload)

        except Exception as e:
            return f"Error: {e}"
