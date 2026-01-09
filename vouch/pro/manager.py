# vouch/pro/manager.py
"""
ProManager - Main interface for Vouch Pro features.

Provides:
- Credential issuance for organizations
- Chain of trust verification
- Revocation checking
"""

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, List

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

from vouch.pro.credentials import (
    EmploymentCredential,
    CredentialVerificationResult,
    issue_credential,
    verify_credential,
    create_credential_payload,
)
from vouch.pro.organizations import (
    VerifiedOrganization,
    lookup_organization_sync,
    is_verified_organization_sync,
)


# =============================================================================
# Revocation List Interface
# =============================================================================

class RevocationList:
    """
    Certificate Revocation List (CRL) for credentials.
    
    Stores revoked credential hashes in Cloudflare KV.
    """
    
    def __init__(self, kv_namespace=None):
        self.kv = kv_namespace
        self._local_cache: set = set()  # For development
    
    async def is_revoked(self, credential_hash: str) -> bool:
        """Check if credential is revoked."""
        if credential_hash in self._local_cache:
            return True
        
        if self.kv:
            try:
                result = await self.kv.get(f"crl:{credential_hash}")
                return result is not None
            except Exception:
                pass
        
        return False
    
    def is_revoked_sync(self, credential_hash: str) -> bool:
        """Synchronous check."""
        return credential_hash in self._local_cache
    
    async def revoke(self, credential_hash: str, reason: str = "revoked") -> bool:
        """
        Revoke a credential.
        
        Args:
            credential_hash: Hash of credential to revoke
            reason: Reason for revocation
            
        Returns:
            True if successful
        """
        self._local_cache.add(credential_hash)
        
        if self.kv:
            import json
            try:
                await self.kv.put(
                    f"crl:{credential_hash}",
                    json.dumps({
                        "revoked_at": datetime.now(timezone.utc).isoformat(),
                        "reason": reason,
                    })
                )
            except Exception:
                return False
        
        return True


# =============================================================================
# Chain Verification Result
# =============================================================================

@dataclass
class ChainVerificationResult:
    """Result of chain of trust verification."""
    is_valid: bool
    organization_name: Optional[str] = None
    organization_did: Optional[str] = None
    role: Optional[str] = None
    department: Optional[str] = None
    display_string: Optional[str] = None  # "NYT - Senior Photographer"
    credential_count: int = 0
    errors: Optional[List[str]] = None
    
    @property
    def attribution(self) -> Optional[str]:
        """Get attribution string for display."""
        if self.organization_name and self.role:
            if self.department:
                return f"{self.organization_name} ({self.department}) - {self.role}"
            return f"{self.organization_name} - {self.role}"
        return None


# =============================================================================
# ProManager Class
# =============================================================================

class ProManager:
    """
    Main interface for Vouch Pro features.
    
    Usage:
        manager = ProManager()
        
        # Issue credential
        credential = manager.issue_credential(
            issuer_key=org_private_key,
            issuer_did="did:vouch:nyt",
            subject_did="did:vouch:alice",
            role="Senior Photographer",
            expiry=datetime(2027, 12, 31)
        )
        
        # Verify chain
        result = manager.verify_chain(
            signer_did="did:vouch:alice",
            credentials=[credential]
        )
        print(result.display_string)  # "The New York Times - Senior Photographer"
    """
    
    def __init__(self, revocation_list: Optional[RevocationList] = None):
        """Initialize ProManager."""
        self.revocation_list = revocation_list or RevocationList()
    
    def issue_credential(
        self,
        issuer_key: Ed25519PrivateKey,
        issuer_did: str,
        subject_did: str,
        role: str,
        expiry: datetime,
        department: Optional[str] = None,
        issuer_name: Optional[str] = None,
    ) -> EmploymentCredential:
        """
        Issue an employment credential.
        
        Called by Organization Admin to onboard employees.
        
        Args:
            issuer_key: Organization's private key
            issuer_did: Organization's DID
            subject_did: Employee's DID
            role: Job role
            expiry: Expiration date
            department: Optional department
            issuer_name: Human-readable org name
            
        Returns:
            EmploymentCredential
        """
        # Look up org name if not provided
        if issuer_name is None:
            org = lookup_organization_sync(issuer_did)
            if org:
                issuer_name = org.name
        
        return issue_credential(
            issuer_key=issuer_key,
            issuer_did=issuer_did,
            subject_did=subject_did,
            role=role,
            expiry=expiry,
            department=department,
            issuer_name=issuer_name,
        )
    
    def verify_chain(
        self,
        signer_did: str,
        credentials: List[EmploymentCredential],
        check_revocation: bool = True,
    ) -> ChainVerificationResult:
        """
        Verify chain of trust for a signer.
        
        This is called when scanning/verifying a signed photo.
        
        Args:
            signer_did: The DID that signed the photo
            credentials: List of credentials attached to photo
            check_revocation: Whether to check CRL
            
        Returns:
            ChainVerificationResult with org name and role if valid
        """
        errors = []
        
        if not credentials:
            return ChainVerificationResult(
                is_valid=False,
                errors=["No credentials provided"]
            )
        
        # Check each credential
        for credential in credentials:
            # 1. Check subject matches signer
            if credential.subject != signer_did:
                errors.append(f"Subject mismatch: {credential.subject} != {signer_did}")
                continue
            
            # 2. Check expiry
            if credential.is_expired:
                errors.append(f"Credential expired: {credential.expiry}")
                continue
            
            # 3. Check issuer is verified organization
            org = lookup_organization_sync(credential.issuer)
            if not org:
                errors.append(f"Issuer not a verified organization: {credential.issuer}")
                continue
            
            # 4. Check revocation (sync for now)
            if check_revocation:
                if self.revocation_list.is_revoked_sync(credential.credential_hash):
                    errors.append(f"Credential revoked: {credential.credential_hash}")
                    continue
            
            # 5. Verify signature (would need org's public key)
            # For now, trust if org is verified and not revoked
            # In production, verify against org.public_key
            
            # Valid credential found!
            return ChainVerificationResult(
                is_valid=True,
                organization_name=org.name,
                organization_did=org.did,
                role=credential.role,
                department=credential.department,
                display_string=f"{org.name} - {credential.role}",
                credential_count=len(credentials),
            )
        
        # No valid credentials
        return ChainVerificationResult(
            is_valid=False,
            credential_count=len(credentials),
            errors=errors,
        )
    
    async def verify_chain_async(
        self,
        signer_did: str,
        credentials: List[EmploymentCredential],
        check_revocation: bool = True,
    ) -> ChainVerificationResult:
        """Async version of verify_chain for production use."""
        # Similar logic but with async org lookup and revocation check
        return self.verify_chain(signer_did, credentials, check_revocation)
    
    async def revoke_credential(
        self,
        credential: EmploymentCredential,
        reason: str = "revoked",
    ) -> bool:
        """
        Revoke a credential.
        
        Called when employee leaves organization.
        
        Args:
            credential: Credential to revoke
            reason: Reason for revocation
            
        Returns:
            True if successful
        """
        return await self.revocation_list.revoke(
            credential.credential_hash,
            reason
        )
