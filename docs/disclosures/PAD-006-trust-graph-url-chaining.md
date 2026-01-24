# Defensive Disclosure: URL-Based Credential Chaining ("Trust Graph")

**Disclosure ID:** PAD-006  
**Publication Date:** January 10, 2026  
**Author:** Ramprasad Anandam Gaddam  
**Status:** Public Domain / Prior Art  

---

## Abstract

This disclosure describes a method for encoding and resolving a hierarchical Chain of Trust through a single URL, enabling verification of organizational credentials without requiring pre-downloaded registries or custom applications.

---

## Problem Statement

Verifying an organization's employee (e.g., "Alice at The New York Times") typically requires:

1. **Complex PKI Lookup**: Certificate chain validation against trusted roots
2. **Governance Frameworks**: Pre-downloaded trust registries (heavy on mobile)
3. **Custom Applications**: Specialized apps to traverse credential chains
4. **Online Connectivity**: Real-time access to issuer verification endpoints

These requirements create friction for:
- Mobile verification (limited storage, intermittent connectivity)  
- Physical media (QR codes on printed documents)
- Cross-platform interoperability (different apps for different issuers)

---

## Disclosed Method

We disclose a transport mechanism that encodes a hierarchical Chain of Trust into a singular, resolvable Uniform Resource Locator (URL).

### Mechanism

```
┌─────────────────────────────────────────────────────────────┐
│                  TRUST GRAPH URL FLOW                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  THE ARTIFACT:                                              │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  QR Code / Short Link                                │   │
│  │  vouch.me/v/abc123                                   │   │
│  └─────────────────────────────────────────────────────┘   │
│                           │                                 │
│                           ▼                                 │
│  THE FETCH:                                                 │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  GET vouch.me/v/abc123                               │   │
│  │  Accept: application/ld+json                         │   │
│  └─────────────────────────────────────────────────────┘   │
│                           │                                 │
│                           ▼                                 │
│  THE RESPONSE (JSON-LD Credential Chain):                   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  {                                                   │   │
│  │    "@context": ["https://www.w3.org/2018/credentials/v1"],│
│  │    "credentialChain": [                              │   │
│  │      { ROOT: Protocol validates Org DID },           │   │
│  │      { INTERMEDIATE: Org certifies Employee DID },   │   │
│  │      { LEAF: Employee Key signs Content }            │   │
│  │    ]                                                 │   │
│  │  }                                                   │   │
│  └─────────────────────────────────────────────────────┘   │
│                           │                                 │
│                           ▼                                 │
│  CLIENT VALIDATION:                                         │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  1. Verify ROOT: Is Org in trusted directory?        │   │
│  │  2. Verify INTERMEDIATE: Is credential unexpired?    │   │
│  │  3. Verify LEAF: Does signature match content?       │   │
│  │  4. Display: "✅ Alice @ New York Times"             │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Credential Chain Structure

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://vouch-protocol.com/v1"
  ],
  "type": "VouchCredentialChain",
  "credentialChain": [
    {
      "type": "OrganizationCredential",
      "issuer": "did:vouch:protocol",
      "credentialSubject": {
        "id": "did:vouch:nyt",
        "name": "The New York Times",
        "domain": "nytimes.com",
        "verificationMethod": "https://nytimes.com/.well-known/vouch.json"
      },
      "proof": { "type": "Ed25519Signature2020", ... }
    },
    {
      "type": "EmploymentCredential", 
      "issuer": "did:vouch:nyt",
      "credentialSubject": {
        "id": "did:key:z6MkhaXgBZD...",
        "role": "Senior Photographer",
        "department": "Editorial"
      },
      "expirationDate": "2027-01-08T00:00:00Z",
      "proof": { "type": "Ed25519Signature2020", ... }
    },
    {
      "type": "ContentSignature",
      "signer": "did:key:z6MkhaXgBZD...",
      "contentHash": "sha256:a7b3c9d2...",
      "signedAt": "2026-01-08T12:00:00Z",
      "proof": { "type": "Ed25519Signature2020", ... }
    }
  ]
}
```

### Validation Algorithm

```python
def validate_chain(chain_url: str) -> VerificationResult:
    # 1. Fetch chain from URL
    response = fetch(chain_url, accept="application/ld+json")
    chain = response.json()["credentialChain"]
    
    # 2. Validate ROOT (Organization is trusted)
    org_cred = chain[0]
    if not is_in_trusted_directory(org_cred["credentialSubject"]["id"]):
        return VerificationResult(valid=False, error="Unknown organization")
    if not verify_signature(org_cred):
        return VerificationResult(valid=False, error="Invalid org signature")
    
    # 3. Validate INTERMEDIATE (Employee credential)
    emp_cred = chain[1]
    if emp_cred["issuer"] != org_cred["credentialSubject"]["id"]:
        return VerificationResult(valid=False, error="Issuer mismatch")
    if is_expired(emp_cred["expirationDate"]):
        return VerificationResult(valid=False, error="Credential expired")
    if not verify_signature(emp_cred):
        return VerificationResult(valid=False, error="Invalid employee signature")
    
    # 4. Validate LEAF (Content signature)
    content_sig = chain[2]
    if content_sig["signer"] != emp_cred["credentialSubject"]["id"]:
        return VerificationResult(valid=False, error="Signer mismatch")
    if not verify_signature(content_sig):
        return VerificationResult(valid=False, error="Invalid content signature")
    
    # 5. SUCCESS
    return VerificationResult(
        valid=True,
        signer=emp_cred["credentialSubject"]["id"],
        organization=org_cred["credentialSubject"]["name"],
        role=emp_cred["credentialSubject"]["role"]
    )
```

### Benefits

| Aspect | Traditional PKI | Trust Graph URL |
|--------|-----------------|-----------------|
| Pre-download required | Yes (root certs) | No |
| Custom app needed | Often | No (browser works) |
| Offline verification | Partial | Full (chain cached) |
| Mobile-friendly | Limited | Yes |
| QR code compatible | Complex | Simple |

### Security Considerations

1. **URL Integrity**: Short URL service must be trusted (or use content-addressed URLs)
2. **Chain Freshness**: Client should check credential expiration dates
3. **Revocation Checking**: CRL or OCSP-like endpoint for revoked credentials
4. **Cache Control**: Appropriate HTTP headers to balance freshness vs. availability

---

## Prior Art Declaration

This disclosure is published to establish prior art and prevent patent monopolization. The described method is hereby released into the public domain under the Creative Commons CC0 1.0 Universal dedication.

Any party implementing similar functionality after January 10, 2026 cannot claim novelty for patent purposes.

---

## Implementation Reference

Reference implementation available in:
- `vouch/pro/manager.py` - Credential chain assembly
- `cloudflare-worker/src/worker.js` - URL resolution endpoint
- `vouch/media/native.py` - Chain embedding in signatures

Repository: https://github.com/vouch-protocol/vouch
