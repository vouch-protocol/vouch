from mcp.server.fastmcp import FastMCP
from typing import Optional
from pathlib import Path
import json

# Import Vouch SDK
try:
    from vouch.signer import Signer
    from vouch.verifier import Verifier
    from vouch.keys import generate_identity, KeyPair
    # Image dependencies (optional)
    try:
        from vouch.media.c2pa import (
            MediaSigner, 
            MediaVerifier, 
            VouchIdentity, 
            generate_self_signed_certificate
        )
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        pass # Image signing optional
except ImportError as e:
    raise ImportError(f"Please install vouch-protocol (pip install -e ../../): {e}")

# Initialize FastMCP Server
mcp = FastMCP("Vouch Protocol")

@mcp.tool()
def create_identity(name: str) -> str:
    """Create a new Vouch Identity (DID + Key) for signing media."""
    # Generate random DID for demo
    did = f"did:vouch:{name.lower().replace(' ', '')}"
    keypair = generate_identity(domain=None) # function returns KeyPair
    keypair.did = did # Assign custom DID manually since domain is None
    
    # Return as JSON
    return json.dumps({
        "did": keypair.did,
        "private_key_jwk": keypair.private_key_jwk,
        "public_key_jwk": keypair.public_key_jwk,
        "note": "SAVE THIS SAFELY! You need it to sign."
    }, indent=2)

@mcp.tool()
def sign_image(image_path: str, private_key_jwk: str, title: str = "My Signed Image") -> str:
    """
    Sign an image with C2PA provenance using Vouch.
    
    Args:
        image_path: Absolute path to the source image.
        private_key_jwk: The JSON Web Key string from create_identity.
        title: Title of the image credential.
    """
    try:
        # 1. Load Identity & Private Key
        key_data = json.loads(private_key_jwk)
        
        # In this KeyPair object, private_key_jwk is a STRING of JSON, not a dict. 
        # Wait, generate_identity returns KeyPair where private_key_jwk is ALREADY a JSON string (export_private).
        # But create_identity returns it inside a bigger JSON wrapper. 
        # The input `private_key_jwk` to this function is expected to be that string.
        # Let's handle both raw dict and string str.
        
        if isinstance(key_data, str):
             key_dict = json.loads(key_data)
        else:
             key_dict = key_data
             
        # Extract 'd' param for Ed25519 reconstruction
        # Vouch keys uses jwcrypto, so export_private() result is standard JWK
        
        vouch_did = "did:vouch:unknown" # Extract from input if passed, or assume unknown

        
        # We need the raw Ed25519 object for the MediaSigner (which uses cryptography libs)
        # vouch.keys.Identity wraps it, let's extract or reconstruct.
        # Actually vouch.keys.Identity doesn't expose the raw object easily for c2pa.py's specific needs
        # which expects cryptography.Ed25519PrivateKey. 
        # But we can reconstruct it from the JWK 'd' param (private scalar).
        
        # Helper to get Ed25519PrivateKey from JWK dict
        from base64 import urlsafe_b64decode
        d_b64 = key_dict['d'] + "==" # padding
        d_bytes = urlsafe_b64decode(d_b64)
        private_key = Ed25519PrivateKey.from_private_bytes(d_bytes)
        
        # 2. Generate One-time Signing Cert
        # In production this comes from a CA. For demo, we self-sign.
        cert_pem = generate_self_signed_certificate(
            private_key, 
            common_name=vouch_did, 
            organization="Vouch MCP Demo"
        )
        
        # 3. Create Vouch Identity Object
        v_identity = VouchIdentity(
            did=vouch_did,
            display_name="Claude Agent",
            credential_type="DEMO"
        )
        
        # 4. Initialize Signer
        signer = MediaSigner(private_key, cert_pem, v_identity)
        
        # 5. Sign
        input_path = Path(image_path)
        output_path = input_path.parent / f"signed_{input_path.name}"
        
        result = signer.sign_image(
            source_path=input_path,
            output_path=output_path,
            title=title
        )
        
        if result.success:
            return f"Successfully signed! Output saved to: {output_path}"
        else:
            return f"Error signing: {result.error}"
            
    except Exception as e:
        return f"Error signing image: {str(e)}"

@mcp.tool()
def verify_image(image_path: str) -> str:
    """
    Verify the C2PA provenance of an image.
    
    Args:
        image_path: Absolute path to the image to verify.
    """
    try:
        verifier = MediaVerifier()
        result = verifier.verify_image(image_path)
        
        if result.is_valid:
            signer_name = result.signer_identity.display_name if result.signer_identity else "Unknown"
            return f"✅ VERIFIED! Signed by: {signer_name}\nManifest: {result.manifest_json}"
        else:
            return f"❌ Validation Failed: {result.error}"
    except Exception as e:
        return f"Error verifying image: {str(e)}"


@mcp.tool()
def sign_text(text: str, private_key_jwk: str, did: str) -> str:
    """
    Sign a text message or prompt using Vouch Identity.
    Returns a verifiable JWS token.
    """
    try:
        signer = Signer(private_key=private_key_jwk, did=did)
        token = signer.sign({"content": text})
        return token
    except Exception as e:
        return f"Error signing text: {str(e)}"

@mcp.tool()
def verify_text(token: str, public_key_jwk: str) -> str:
    """
    Verify a signed Vouch text token.
    """
    try:
        is_valid, passport = Verifier.verify(token, public_key_jwk=public_key_jwk)
        if is_valid and passport:
            content = passport.payload.get("content", "")
            return f"✅ VERIFIED! Signed by {passport.iss}\nContent: {content}\nTimestamp: {passport.iat}"
        else:
            return "❌ Invalid Signature or Token"
    except Exception as e:
        return f"Error verifying text: {str(e)}"

if __name__ == "__main__":
    mcp.run()
