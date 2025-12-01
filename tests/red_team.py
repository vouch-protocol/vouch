import sys
import os
import json
import uuid
from jwcrypto import jwk

# Add parent directory to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from vouch import Verifier, Auditor

print("⚔️  VOUCH SECURITY SUITE")
print("------------------------")

# 1. Setup Keys
print("> Generating Ephemeral Keys...", end=" ")
key = jwk.JWK.generate(kty='OKP', crv='Ed25519') 
private_key = key.export_private()
public_key = key.export_public()
print("DONE")

# 2. Configure Auditor & Verifier
# NOTE: We pass the public key to the Verifier's 'trusted_roots' 
# so it doesn't try to fetch 'did:web:test-agent' from the real internet.
auditor = Auditor(private_key)
verifier = Verifier(trusted_roots={"did:web:test-agent": public_key})

# 3. Test Logic
print("> Running Test 1: Dynamic Verification...", end=" ")

vouch_data = {
    "did": "did:web:test-agent", 
    "integrity_hash": "sha256:test-hash"
}

try:
    # Issue
    cert = auditor.issue_vouch(vouch_data)
    
    # Verify
    is_valid, payload = verifier.check_vouch(cert['certificate'])

    if is_valid and payload['sub'] == "did:web:test-agent":
        print("PASSED ✅")
    else:
        print(f"FAILED ❌ (Result: {is_valid})")
        sys.exit(1)

except Exception as e:
    print(f"CRITICAL ERROR ❌: {str(e)}")
    sys.exit(1)

print("\n✅ Security Audit Complete. System Safe.")
