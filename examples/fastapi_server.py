from fastapi import FastAPI, Header, HTTPException
from vouch import Verifier

app = FastAPI()
# (Mock key for demo)
verifier = Verifier('{"kty":"OKP","crv":"Ed25519","x":"..."}')

@app.post("/agent/connect")
def connect_agent(authorization: str = Header(None)):
    is_valid, data = verifier.check_vouch(authorization)
    if not is_valid:
        raise HTTPException(status_code=401, detail="Agent Identity Verification Failed")
    return {"status": "Connected", "agent": data['sub']}
