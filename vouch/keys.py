import json
from jwcrypto import jwk

def generate_identity():
    """
    Generates a fresh Ed25519 Keypair for a new Agent.
    """
    # 1. Generate Key
    key = jwk.JWK.generate(kty='OKP', crv='Ed25519')
    
    # 2. Export Private Key (Save this securely!)
    private_key = key.export_private()
    
    # 3. Export Public Key (Put this in vouch.json)
    public_key = key.export_public()
    
    print("🔑 NEW AGENT IDENTITY GENERATED\n")
    print("--- PRIVATE KEY (Keep Secret / Set as Env Var) ---")
    print(private_key)
    print("\n--- PUBLIC KEY (Put this in vouch.json) ---")
    print(public_key)

if __name__ == "__main__":
    generate_identity()
