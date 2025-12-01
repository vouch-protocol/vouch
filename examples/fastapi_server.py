from fastapi import FastAPI, Header, HTTPException
from vouch import Verifier

app = FastAPI()
# (Mock key for demo)
verifier = Verifier('{"kty":"OKP","crv":"Ed25519","x":"..."}')

# STANDARD COMPLIANCE: Use 'Vouch-Token' (RFC 6648)
@app.post("/agent/connect")
def connect_agent(vouch_token: str = Header(None, alias="Vouch-Token")):
    if not vouch_token:
        raise HTTPException(status_code=400, detail="Missing Vouch-Token header")
        
    is_valid, data = verifier.check_vouch(vouch_token)
    
    if not is_valid:
        raise HTTPException(status_code=401, detail="Agent Reputation Check Failed")
        
    return {
        "status": "Connected", 
        "agent": data['sub'],
        "reputation": data['vc']['reputation_score']
    }
