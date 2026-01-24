import sys
import os
import json
from server import create_identity, sign_text, verify_text

def run_test():
    print("🧪 Starting MCP Text Signing Test...")

    # 1. Create Identity
    print("\n1️⃣ Creating Identity...")
    id_json = create_identity("MCP Tester")
    data = json.loads(id_json)
    
    # These are already JSON strings from the server
    priv_key = data["private_key_jwk"]
    pub_key = data.get("public_key_jwk") 
    did = data["did"]
    
    # Note: create_identity currently returns private_key_jwk. 
    # Vouch's KeyPair object usually has public_key_jwk too. 
    # Let's check what create_identity actually returns.
    # Ah, server.py: 
    # return json.dumps({ "did": ..., "private_key_jwk": ..., "note": ... })
    # It misses public_key_jwk in the response! 
    # verify_text needs public_key_jwk.
    # But wait, verify_text can resolve DID if we use check_vouch, strictly verify_text(token, pub) needs pub.
    # I should update create_identity to return public key too, or derive it.
    
    # For now, let's derive public key in test if possible, or assume server.py provides it.
    # Actually, let's fix server.py to return public_key_jwk as well, it's useful.
    # But first, let's try to derive it from private key in this test script if create_identity doesn't give it.
    
    # Check if public key is in data (it wasn't in my previous read of server.py)
    # server.py line 35: "private_key_jwk": keypair.private_key_jwk
    # It creates KeyPair which DOES have public_key_jwk. 
    # I should update server.py to return it.
    
    # I'll rely on a fix I will make in server.py in the next step.
    
    print(f"   DID: {did}")

    # 2. Sign Text
    text_content = "This is a verified prompt from an AI agent."
    print(f"\n2️⃣ Signing Text: '{text_content}'")
    token = sign_text(text_content, priv_key, did)
    
    if token.startswith("Error"):
        print(f"❌ Signing failed: {token}")
        return
        
    print(f"   Token: {token[:20]}...{token[-20:]}")

    # 3. Verify Text (We need public key)
    # Since I haven't fixed server.py yet, I'll cheat and extract it from private key here
    # or just assume the next step fixes it. 
    # Let's import jwcrypto to derive it if missing.
    try:
        from jwcrypto import jwk
        k = jwk.JWK.from_json(priv_key)
        derived_pub = k.export_public()
        print("\n3️⃣ Verifying Text...")
        result = verify_text(token, derived_pub)
        print(f"   Result: {result}")
    except Exception as e:
        print(f"❌ Verification setup failed: {e}")

if __name__ == "__main__":
    run_test()
