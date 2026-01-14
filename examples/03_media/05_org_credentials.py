#!/usr/bin/env python3
"""
05_org_credentials.py - Organization Chain of Trust

Learn the complete flow:
1. Organization issues credential to employee
2. Employee signs photo with credential
3. Anyone can verify: "New York Times - Senior Photographer"

This is the "NYT Photographer" use case.

Run: python 05_org_credentials.py
"""

from datetime import datetime, timezone, timedelta
from vouch.media.native import sign_image_native, verify_image_native, generate_keypair
from vouch.pro import ProManager
from vouch.pro.credentials import issue_credential

# =============================================================================
# STEP 1: Organization Issues Credential
# =============================================================================

print("🏢 STEP 1: Organization Issues Credential")
print("=" * 50)

# Organization's key (in reality, securely managed by org admin)
org_key, org_did = generate_keypair()
print("   Org DID: did:vouch:nyt")  # Registered in directory

# Employee's key (on their device)
employee_key, employee_did = generate_keypair()
print(f"   Employee DID: {employee_did[:30]}...")

# Org admin issues credential
manager = ProManager()
credential = manager.issue_credential(
    issuer_key=org_key,
    issuer_did="did:vouch:nyt",  # This is in our dev org directory
    subject_did=employee_did,
    role="Senior Photographer",
    expiry=datetime.now(timezone.utc) + timedelta(days=365),
    department="Editorial",
    issuer_name="The New York Times",
)

print("\n   ✅ Credential issued!")
print(f"   Display: {credential.display_string}")
print(f"   Expiry: {credential.expiry[:10]}")
print(f"   Hash: {credential.credential_hash}")

# =============================================================================
# STEP 2: Employee Signs Photo with Credential
# =============================================================================

print("\n📷 STEP 2: Employee Signs Photo with Credential")
print("=" * 50)

# Create sample photo
from PIL import Image
import tempfile

with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f:
    img = Image.new('RGB', (800, 600), color='darkgreen')
    img.save(f.name)
    photo_path = f.name

# Employee signs with their credential attached
result = sign_image_native(
    source_path=photo_path,
    private_key=employee_key,
    did=employee_did,
    display_name="Alice Reporter",
    email="alice@nytimes.com",
    credential_type="PRO",
    credentials=[credential.to_dict()],  # 👈 Attach credential!
)

print("   ✅ Photo signed!")
print(f"   Signer: {result.signature.display_name}")
print(f"   Credentials attached: {len(result.signature.credentials)}")

# =============================================================================
# STEP 3: Anyone Verifies the Photo
# =============================================================================

print("\n🔍 STEP 3: Anyone Verifies the Photo")
print("=" * 50)

# Verify the image
verify_result = verify_image_native(result.output_path)

print(f"   Valid: {verify_result.is_valid}")
print(f"   Signer: {verify_result.signature.display_name}")

# Check organization credential
if verify_result.signature.credentials:
    cred = verify_result.signature.credentials[0]
    org_name = cred.get('issuer_name', cred['issuer'])
    role = cred.get('role', 'Unknown')
    dept = cred.get('department', '')
    
    print(f"\n   🏢 Organization: {org_name}")
    if dept:
        print(f"   Department: {dept}")
    print(f"   Role: {role}")
    print(f"   Expiry: {cred['expiry'][:10]}")

# Now verify the chain of trust
chain_result = manager.verify_chain(
    signer_did=employee_did,
    credentials=[credential],
)

print(f"\n   Chain Valid: {chain_result.is_valid}")
print(f"   Attribution: {chain_result.display_string}")

# =============================================================================
# STEP 4: What If Employee Leaves?
# =============================================================================

print("\n🚫 STEP 4: Revocation (Kill Switch)")
print("=" * 50)

import asyncio

async def demo_revocation():
    # Org revokes the credential
    await manager.revoke_credential(credential, reason="employment_ended")
    print(f"   ✅ Credential revoked: {credential.credential_hash}")
    
    # Now verification fails
    result = manager.verify_chain(
        signer_did=employee_did,
        credentials=[credential],
    )
    print(f"   Chain still valid? {result.is_valid}")
    if not result.is_valid:
        print(f"   Error: {result.errors[0]}")

asyncio.run(demo_revocation())

# =============================================================================
# Summary
# =============================================================================

print("""
📝 ORGANIZATION CHAIN OF TRUST SUMMARY:

1. ORG issues credential → Employee gets EmploymentCredential
2. EMPLOYEE signs photos → Credential embedded in sidecar
3. ANYONE verifies → Sees "NYT - Senior Photographer"
4. ORG revokes → Future verifications fail

🔗 TRUST CHAIN:
   Vouch → Verifies Org → Org → Verifies Employee → Signs Photo

✅ BENEFITS:
   - Org doesn't manage photos, just credentials
   - Employee keeps their DID if they change jobs
   - Photo carries its own proof (no server needed)
   - Revocation works instantly
""")
