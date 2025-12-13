import json
import time
import base64
import requests
from jwcrypto import jwk, jws

class Verifier:
    def __init__(self, trusted_roots=None):
        self.trusted_roots = trusted_roots or {}
        self.used_nonces = set()

    def _resolve_did(self, did):
        if did in self.trusted_roots:
            return jwk.JWK.from_json(self.trusted_roots[did])

        if not did.startswith("did:web:"):
            raise ValueError(f"Unsupported DID method: {did}")

        domain = did.replace("did:web:", "")
        url = f"https://{domain}/.well-known/did.json"
        
        try:
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            did_doc = response.json()
            key_data = did_doc['verificationMethod'][0]['publicKeyJwk']
            return jwk.JWK.from_json(json.dumps(key_data))
        except Exception as e:
            return None

    def check_vouch(self, token):
        try:
            parts = token.split('.')
            if len(parts) != 3: return False, "Invalid Token Format"
            
            payload_str = parts[1] + '=' * (-len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_str))
            
            agent_did = payload.get('sub')
            if not agent_did: return False, "No Identity (sub) in token"

            public_key = self._resolve_did(agent_did)
            if not public_key:
                return False, f"Could not resolve public key for {agent_did}"

            verifier = jws.JWS()
            verifier.deserialize(token)
            verifier.verify(public_key)
            
            if time.time() > payload['exp']: return False, "Expired Vouch"
            if payload['jti'] in self.used_nonces: return False, "Replay Detected"
            self.used_nonces.add(payload['jti'])

            return True, payload

        except Exception as e:
            return False, f"Verification Error: {str(e)}"
