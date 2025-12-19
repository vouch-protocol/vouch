import json
import time
import base64
from typing import Dict, Any

try:
    from nacl.signing import SigningKey
    from nacl.encoding import HexEncoder
except ImportError:
    SigningKey = None

class Signer:
    def __init__(self, private_key: str, did: str):
        if not private_key or not did:
            raise ValueError("Vouch Signer requires 'private_key' and 'did'")
        self.did = did
        # Load the key
        if SigningKey:
            self.key_obj = SigningKey(private_key, encoder=HexEncoder)
        else:
            raise ImportError("pynacl is not installed. Run: pip install pynacl")

    def sign(self, payload: Dict[str, Any]) -> str:
        """Signs a JSON payload and returns the Vouch-Token string."""
        # 1. Canonicalize
        json_str = json.dumps(payload, sort_keys=True, separators=(',', ':'))
        
        # 2. Create Header Claims
        timestamp = int(time.time())
        nonce = base64.b64encode(os.urandom(8)).decode('utf-8')
        
        # 3. Construct Message to Sign
        # Format: did:timestamp:nonce:hashed_payload
        message = f"{self.did}:{timestamp}:{nonce}:{json_str}"
        
        # 4. Sign
        signature_bytes = self.key_obj.sign(message.encode('utf-8')).signature
        signature_hex = base64.b16encode(signature_bytes).decode('utf-8').lower()
        
        # 5. Return Header Format
        # Vouch-Token: version=1;did=...;ts=...;nonce=...;sig=...
        return f"version=1;did={self.did};ts={timestamp};nonce={nonce};sig={signature_hex}"
