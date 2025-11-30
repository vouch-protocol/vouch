import json
import time
import uuid
from jwcrypto import jwk, jws

class Auditor:
    def __init__(self, private_key_json):
        self.signing_key = jwk.JWK.from_json(private_key_json)

    def issue_vouch(self, agent_data):
        payload = {
            "jti": str(uuid.uuid4()),
            "sub": agent_data.get('did'),
            "iss": "did:web:vouch-authority",
            "nbf": int(time.time()),
            "exp": int(time.time()) + 86400,
            "vc": { "integrity_hash": agent_data.get('integrity_hash') }
        }
        signer = jws.JWS(json.dumps(payload).encode('utf-8'))
        signer.add_signature(self.signing_key, None, json.dumps({"alg":"EdDSA"}), json.dumps({"kid":self.signing_key.key_id}))
        return {"certificate": signer.serialize(compact=True)}
