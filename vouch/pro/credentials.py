# vouch/pro/credentials.py
"""
Employment Credentials for Organization Chain of Trust.

An EmploymentCredential proves that a person (subject) works for
an organization (issuer). This enables delegated verification:

    Vouch -> Org -> Employee -> Signs Photo

The photo carries its own "proof of employment" locally.
"""

import json
import hashlib
import base64
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Literal
from enum import Enum

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization


# =============================================================================
# Types
# =============================================================================

class CredentialType(str, Enum):
    """Types of credentials that can be issued."""
    EMPLOYMENT = "EmploymentCredential"
    CONTRACTOR = "ContractorCredential"
    CONTRIBUTOR = "ContributorCredential"


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class EmploymentCredential:
    """
    Represents an employment credential issued by an organization.
    
    Attributes:
        type: Credential type (EmploymentCredential)
        issuer: Organization's DID (e.g., did:vouch:nyt)
        subject: Employee's DID (e.g., did:vouch:alice)
        role: Job role (e.g., "Senior Photographer")
        department: Optional department
        expiry: When credential expires (ISO 8601)
        issued_at: When credential was issued
        credential_hash: Hash for revocation lookup
        signature: Signature from issuer's private key
    """
    type: str
    issuer: str  # Organization's DID
    subject: str  # Employee's DID
    role: str
    expiry: str  # ISO 8601
    issued_at: str  # ISO 8601
    credential_hash: str
    signature: str
    department: Optional[str] = None
    issuer_name: Optional[str] = None  # Human-readable org name
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {k: v for k, v in asdict(self).items() if v is not None}
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), separators=(',', ':'))
    
    @classmethod
    def from_json(cls, json_str: str) -> "EmploymentCredential":
        """Create from JSON string."""
        data = json.loads(json_str)
        return cls(**data)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EmploymentCredential":
        """Create from dictionary."""
        return cls(**data)
    
    @property
    def is_expired(self) -> bool:
        """Check if credential has expired."""
        try:
            expiry_dt = datetime.fromisoformat(self.expiry.replace('Z', '+00:00'))
            return datetime.now(timezone.utc) > expiry_dt
        except (ValueError, AttributeError):
            return True
    
    @property
    def display_string(self) -> str:
        """Human-readable display (e.g., 'New York Times - Senior Photographer')."""
        org = self.issuer_name or self.issuer
        return f"{org} - {self.role}"


@dataclass
class CredentialVerificationResult:
    """Result of credential verification."""
    is_valid: bool
    credential: Optional[EmploymentCredential] = None
    issuer_name: Optional[str] = None
    role: Optional[str] = None
    display_string: Optional[str] = None  # "NYT - Senior Photographer"
    error: Optional[str] = None
    warnings: List[str] = field(default_factory=list)


# =============================================================================
# Credential Issuance
# =============================================================================

def create_credential_payload(
    issuer: str,
    subject: str,
    role: str,
    expiry: str,
    issued_at: str,
    department: Optional[str] = None,
) -> bytes:
    """Create the canonical payload to sign."""
    payload = {
        "type": CredentialType.EMPLOYMENT.value,
        "issuer": issuer,
        "subject": subject,
        "role": role,
        "expiry": expiry,
        "issued_at": issued_at,
    }
    if department:
        payload["department"] = department
    
    # Use sorted keys for canonical JSON
    return json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')


def issue_credential(
    issuer_key: Ed25519PrivateKey,
    issuer_did: str,
    subject_did: str,
    role: str,
    expiry: datetime,
    department: Optional[str] = None,
    issuer_name: Optional[str] = None,
) -> EmploymentCredential:
    """
    Issue an employment credential to an employee.
    
    Used by Organization Admin to onboard employees.
    
    Args:
        issuer_key: Organization's private key
        issuer_did: Organization's DID (e.g., did:vouch:nyt)
        subject_did: Employee's DID
        role: Job role (e.g., "Senior Photographer")
        expiry: When credential expires
        department: Optional department
        issuer_name: Human-readable org name
        
    Returns:
        EmploymentCredential ready to embed in media signatures
    """
    issued_at = datetime.now(timezone.utc).isoformat()
    expiry_str = expiry.isoformat()
    
    # Create payload
    payload = create_credential_payload(
        issuer=issuer_did,
        subject=subject_did,
        role=role,
        expiry=expiry_str,
        issued_at=issued_at,
        department=department,
    )
    
    # Sign with issuer's private key
    signature_bytes = issuer_key.sign(payload)
    signature_b64 = base64.b64encode(signature_bytes).decode('ascii')
    
    # Create credential hash (for revocation lookup)
    credential_hash = hashlib.sha256(payload).hexdigest()[:16]
    
    return EmploymentCredential(
        type=CredentialType.EMPLOYMENT.value,
        issuer=issuer_did,
        subject=subject_did,
        role=role,
        expiry=expiry_str,
        issued_at=issued_at,
        credential_hash=credential_hash,
        signature=signature_b64,
        department=department,
        issuer_name=issuer_name,
    )


def verify_credential(
    credential: EmploymentCredential,
    issuer_public_key: Ed25519PublicKey,
) -> bool:
    """
    Verify a credential's signature.
    
    Args:
        credential: The credential to verify
        issuer_public_key: Issuer's public key
        
    Returns:
        True if signature is valid
    """
    try:
        # Recreate payload
        payload = create_credential_payload(
            issuer=credential.issuer,
            subject=credential.subject,
            role=credential.role,
            expiry=credential.expiry,
            issued_at=credential.issued_at,
            department=credential.department,
        )
        
        # Decode signature
        signature_bytes = base64.b64decode(credential.signature)
        
        # Verify
        issuer_public_key.verify(signature_bytes, payload)
        return True
        
    except Exception:
        return False
