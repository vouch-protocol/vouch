import os
from vouch import Signer

class N8NHelper:
    """Helper to generate n8n-compatible Python code blocks."""

    @staticmethod
    def get_code_node_snippet() -> str:
        # Returns the Python code for n8n
        return """
# n8n Python Code Node for Vouch Identity
# ---------------------------------------
from vouch import Signer
import os

# 1. CONFIG: Get Identity from Environment Variables
private_key = os.environ.get('VOUCH_PRIVATE_KEY')
did = os.environ.get('VOUCH_DID')

signer = Signer(private_key=private_key, did=did)

# 2. PROCESS: Sign every item in the workflow
# Note: In n8n, input data is accessed via _input.all()
# for item in _input.all():
#     item.json['vouch_token'] = signer.sign(item.json)

# return _input.all()
"""