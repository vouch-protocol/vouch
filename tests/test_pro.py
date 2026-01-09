# tests/test_pro.py
"""
Test suite for Vouch Pro - Organization Chain of Trust.

Tests cover:
- Credential issuance
- Chain verification
- Organization directory
- Revocation
"""

import pytest
from datetime import datetime, timezone, timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vouch.pro.credentials import (
    EmploymentCredential,
    CredentialType,
    issue_credential,
    verify_credential,
)
from vouch.pro.organizations import (
    VerifiedOrganization,
    OrganizationDirectory,
    lookup_organization_sync,
    is_verified_organization_sync,
)
from vouch.pro.manager import ProManager, RevocationList


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def org_keypair():
    """Generate organization keypair."""
    private_key = Ed25519PrivateKey.generate()
    return private_key


@pytest.fixture
def employee_did():
    """Employee DID."""
    return "did:vouch:employee_alice"


@pytest.fixture
def org_did():
    """Organization DID (NYT - seeded in dev orgs)."""
    return "did:vouch:nyt"


@pytest.fixture
def manager():
    """ProManager instance."""
    return ProManager()


@pytest.fixture
def valid_credential(org_keypair, org_did, employee_did):
    """Valid employment credential."""
    return issue_credential(
        issuer_key=org_keypair,
        issuer_did=org_did,
        subject_did=employee_did,
        role="Senior Photographer",
        expiry=datetime.now(timezone.utc) + timedelta(days=365),
        department="Editorial",
        issuer_name="The New York Times",
    )


# =============================================================================
# Test Credential Issuance
# =============================================================================

class TestCredentialIssuance:
    """Tests for credential issuance."""
    
    def test_issue_credential_returns_credential(self, org_keypair, org_did, employee_did):
        """Issuing credential returns EmploymentCredential."""
        credential = issue_credential(
            issuer_key=org_keypair,
            issuer_did=org_did,
            subject_did=employee_did,
            role="Photographer",
            expiry=datetime.now(timezone.utc) + timedelta(days=30),
        )
        
        assert isinstance(credential, EmploymentCredential)
        assert credential.type == CredentialType.EMPLOYMENT.value
    
    def test_credential_has_correct_fields(self, valid_credential, org_did, employee_did):
        """Credential has all required fields."""
        assert valid_credential.issuer == org_did
        assert valid_credential.subject == employee_did
        assert valid_credential.role == "Senior Photographer"
        assert valid_credential.department == "Editorial"
        assert valid_credential.signature is not None
        assert valid_credential.credential_hash is not None
    
    def test_credential_has_timestamp(self, valid_credential):
        """Credential has issued_at timestamp."""
        assert valid_credential.issued_at is not None
        # Should be recent
        issued = datetime.fromisoformat(valid_credential.issued_at.replace('Z', '+00:00'))
        assert datetime.now(timezone.utc) - issued < timedelta(minutes=1)
    
    def test_credential_display_string(self, valid_credential):
        """Credential has display string."""
        assert valid_credential.display_string == "The New York Times - Senior Photographer"
    
    def test_credential_to_json(self, valid_credential):
        """Credential serializes to JSON."""
        json_str = valid_credential.to_json()
        assert "EmploymentCredential" in json_str
        assert "Senior Photographer" in json_str
    
    def test_credential_from_json(self, valid_credential):
        """Credential deserializes from JSON."""
        json_str = valid_credential.to_json()
        restored = EmploymentCredential.from_json(json_str)
        
        assert restored.issuer == valid_credential.issuer
        assert restored.subject == valid_credential.subject
        assert restored.role == valid_credential.role


# =============================================================================
# Test Credential Verification
# =============================================================================

class TestCredentialVerification:
    """Tests for credential signature verification."""
    
    def test_verify_valid_signature(self, org_keypair, valid_credential):
        """Valid signature passes verification."""
        public_key = org_keypair.public_key()
        assert verify_credential(valid_credential, public_key)
    
    def test_verify_wrong_key_fails(self, valid_credential):
        """Wrong public key fails verification."""
        wrong_key = Ed25519PrivateKey.generate().public_key()
        assert not verify_credential(valid_credential, wrong_key)


# =============================================================================
# Test Expiry
# =============================================================================

class TestCredentialExpiry:
    """Tests for credential expiry checking."""
    
    def test_not_expired(self, valid_credential):
        """Future expiry is not expired."""
        assert not valid_credential.is_expired
    
    def test_expired_credential(self, org_keypair, org_did, employee_did):
        """Past expiry is expired."""
        expired = issue_credential(
            issuer_key=org_keypair,
            issuer_did=org_did,
            subject_did=employee_did,
            role="Photographer",
            expiry=datetime.now(timezone.utc) - timedelta(days=1),  # Yesterday
        )
        assert expired.is_expired


# =============================================================================
# Test Organization Directory
# =============================================================================

class TestOrganizationDirectory:
    """Tests for organization directory."""
    
    def test_dev_orgs_seeded(self):
        """Development orgs are seeded."""
        directory = OrganizationDirectory()
        
        nyt = directory.lookup_sync("did:vouch:nyt")
        assert nyt is not None
        assert nyt.name == "The New York Times"
    
    def test_lookup_unknown_org(self):
        """Unknown org returns None."""
        org = lookup_organization_sync("did:vouch:unknown")
        assert org is None
    
    def test_is_verified_returns_true(self):
        """Known org is verified."""
        assert is_verified_organization_sync("did:vouch:nyt")
    
    def test_is_verified_returns_false(self):
        """Unknown org is not verified."""
        assert not is_verified_organization_sync("did:vouch:unknown")


# =============================================================================
# Test ProManager
# =============================================================================

class TestProManager:
    """Tests for ProManager class."""
    
    def test_issue_credential(self, manager, org_keypair, org_did, employee_did):
        """Manager can issue credentials."""
        credential = manager.issue_credential(
            issuer_key=org_keypair,
            issuer_did=org_did,
            subject_did=employee_did,
            role="Photographer",
            expiry=datetime.now(timezone.utc) + timedelta(days=30),
        )
        
        assert credential is not None
        assert credential.role == "Photographer"
    
    def test_verify_chain_valid(self, manager, org_did, employee_did, valid_credential):
        """Valid chain passes verification."""
        result = manager.verify_chain(
            signer_did=employee_did,
            credentials=[valid_credential],
        )
        
        assert result.is_valid
        assert result.organization_name == "The New York Times"
        assert result.role == "Senior Photographer"
    
    def test_verify_chain_wrong_subject(self, manager, valid_credential):
        """Wrong subject fails verification."""
        result = manager.verify_chain(
            signer_did="did:vouch:wrong_person",
            credentials=[valid_credential],
        )
        
        assert not result.is_valid
        assert "Subject mismatch" in result.errors[0]
    
    def test_verify_chain_expired(self, manager, org_keypair, org_did, employee_did):
        """Expired credential fails verification."""
        expired = issue_credential(
            issuer_key=org_keypair,
            issuer_did=org_did,
            subject_did=employee_did,
            role="Photographer",
            expiry=datetime.now(timezone.utc) - timedelta(days=1),
        )
        
        result = manager.verify_chain(
            signer_did=employee_did,
            credentials=[expired],
        )
        
        assert not result.is_valid
        assert "expired" in result.errors[0].lower()
    
    def test_verify_chain_unknown_issuer(self, manager, org_keypair, employee_did):
        """Unknown issuer fails verification."""
        credential = issue_credential(
            issuer_key=org_keypair,
            issuer_did="did:vouch:unknown_org",
            subject_did=employee_did,
            role="Photographer",
            expiry=datetime.now(timezone.utc) + timedelta(days=30),
        )
        
        result = manager.verify_chain(
            signer_did=employee_did,
            credentials=[credential],
        )
        
        assert not result.is_valid
        assert "not a verified organization" in result.errors[0].lower()
    
    def test_display_string(self, manager, employee_did, valid_credential):
        """Verification result has display string."""
        result = manager.verify_chain(
            signer_did=employee_did,
            credentials=[valid_credential],
        )
        
        assert result.display_string == "The New York Times - Senior Photographer"


# =============================================================================
# Test Revocation
# =============================================================================

class TestRevocation:
    """Tests for credential revocation."""
    
    def test_not_revoked_by_default(self):
        """Credentials are not revoked by default."""
        crl = RevocationList()
        assert not crl.is_revoked_sync("test_hash")
    
    @pytest.mark.asyncio
    async def test_revoke_credential(self, valid_credential):
        """Revoking credential adds to CRL."""
        crl = RevocationList()
        
        await crl.revoke(valid_credential.credential_hash, "terminated")
        
        assert crl.is_revoked_sync(valid_credential.credential_hash)
    
    @pytest.mark.asyncio
    async def test_verify_chain_checks_revocation(self, manager, employee_did, valid_credential):
        """Verification checks revocation list."""
        # Revoke the credential
        await manager.revocation_list.revoke(valid_credential.credential_hash, "terminated")
        
        result = manager.verify_chain(
            signer_did=employee_did,
            credentials=[valid_credential],
        )
        
        assert not result.is_valid
        assert "revoked" in result.errors[0].lower()


# =============================================================================
# Run Tests
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
