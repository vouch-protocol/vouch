# vouch/pro/__init__.py
"""
Vouch Pro - Premium features for organizations and enterprise.

Features:
- Organization Chain of Trust
- Employment Credentials
- Delegated Verification
- Credential Revocation (CRL)
"""

from vouch.pro.credentials import (
    EmploymentCredential,
    CredentialType,
    issue_credential,
    verify_credential,
)

from vouch.pro.manager import ProManager

from vouch.pro.organizations import (
    VerifiedOrganization,
    lookup_organization,
    is_verified_organization,
)

__all__ = [
    # Credentials
    "EmploymentCredential",
    "CredentialType", 
    "issue_credential",
    "verify_credential",
    
    # Manager
    "ProManager",
    
    # Organizations
    "VerifiedOrganization",
    "lookup_organization",
    "is_verified_organization",
]
