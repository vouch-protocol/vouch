import json
import time
import base64
import requests
from jwcrypto import jwk, jws

class Verifier:
    def __init__(self, trusted_roots=None):
        """
        trusted_roots: A dictionary of {did: key_json} for local testing/overrides.
        """
        self.trusted_roots = trusted_roots or {}
        # ⚠️ WARNING: In-memory replay protection. Use Redis in production.
        self.used_nonces = set()

    def _resolve_did(self, did):
        """
        The Phonebook: Converts 'did:web:example.com' -> Public Key
        """
        # 1. Check Local Cache / Trusted Roots first (For testing)
        if did in self.trusted_roots:
            return jwk.JWK.from_json(self.trusted_roots[did])

        # 2. Dynamic Resolution (The Internet)
        if not did.startswith("did:web:"):
            raise ValueError(f"Unsupported DID method: {did}")

        # did:web:example.com -> https://example.com/.well-known/did.json
        domain = did.replace("did:web:", "")
        url = f"https://{domain}/.well-known/did.json"
        
        try:
            print(f"🌐 Resolving Identity: {url}...")
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            did_doc = response.json()
            
            # Extract the first public key (Simplification for v0.1)
            # In v1.0, match the 'kid' from the token header
            key_data = did_doc['verificationMethod'][0]['publicKeyJwk']
            return jwk.JWK.from_json(json.dumps(key_data))
            
        except Exception as e:
            print(f"❌ Resolution Failed: {str(e)}")
            return None

    def check_vouch(self, token):
        try:
            # 1. PEEK at the unverified payload to find the Identity (sub)
            # (We strip the signature to just read the JSON body first)
            parts = token.split('.')
            if len(parts) != 3: return False, "Invalid Token Format"
            
            # Base64 Decode (with padding fix)
            payload_str = parts[1] + '=' * (-len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_str))
            
            agent_did = payload.get('sub')
            if not agent_did: return False, "No Identity (sub) in token"

            # 2. RESOLVE the Public Key for that Identity
            public_key = self._resolve_did(agent_did)
            if not public_key:
                return False, f"Could not resolve public key for {agent_did}"

            # 3. VERIFY the signature using that key
            verifier = jws.JWS()
            verifier.deserialize(token)
            verifier.verify(public_key) # <--- Crypto Magic happens here
            
            # 4. Standard Checks (Time, Replay)
            if time.time() > payload['exp']: return False, "Expired Vouch"
            if payload['jti'] in self.used_nonces: return False, "Replay Detected"
            self.used_nonces.add(payload['jti'])

            return True, payload

        except Exception as e:
            return False, f"Verification Error: {str(e)}"
