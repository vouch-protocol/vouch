# Defensive Disclosure: Hybrid Identity Bootstrapping via SSH Piggybacking

**Disclosure ID:** PAD-008  
**Publication Date:** January 10, 2026  
**Author:** Ramprasad Anandam Gaddam  
**Status:** Public Domain / Prior Art  

---

## Abstract

This disclosure describes a method for achieving "Zero-Config" identity verification by leveraging existing SSH keys as the root of trust, with dynamic resolution against third-party authorities like GitHub or GitLab.

---

## Problem Statement

Adopting new cryptographic identity protocols in enterprise environments is hindered by **"Key Fatigue"**:

- Users must generate, secure, and register new private keys
- Multiple key management systems create confusion
- Lost keys lead to loss of identity continuity
- Shadow IT risk: users create unofficial keys
- Existing SSH keys (already deployed for Git) are ignored

The **"One Identity, One Key"** model prevents interoperability with legacy infrastructure, blocking adoption.

---

## Disclosed Method

We disclose a method for "Zero-Config" identity verification that bootstraps a new protocol on top of existing SSH authentication infrastructure.

### Mechanism

```
┌─────────────────────────────────────────────────────────────┐
│                  SSH PIGGYBACK FLOW                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  CLIENT SIDE:                                               │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  User's existing SSH Agent                           │   │
│  │  (Standard for Git operations)                       │   │
│  │       │                                              │   │
│  │       ▼                                              │   │
│  │  Signing Agent: "Sign this payload with SSH key"     │   │
│  │       │                                              │   │
│  │       ▼                                              │   │
│  │  Output: Signature + SSH Key Fingerprint             │   │
│  └─────────────────────────────────────────────────────┘   │
│                           │                                 │
│                           ▼                                 │
│  VERIFICATION SERVER (Dynamic Resolution):                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                                                      │   │
│  │  Step A: Receive Signature + Key Fingerprint         │   │
│  │       │                                              │   │
│  │       ▼                                              │   │
│  │  Step B: Query Third-Party API                       │   │
│  │       │  GET github.com/users/{each}/keys            │   │
│  │       │  Find: "Who owns fingerprint ABC123?"        │   │
│  │       │                                              │   │
│  │       ▼                                              │   │
│  │  Step C: Receive Identity                            │   │
│  │       │  Response: "User: ramprasad"                 │   │
│  │       │                                              │   │
│  │       ▼                                              │   │
│  │  Step D: Implicit Authorization                      │   │
│  │          "Is 'ramprasad' in 'optum' org?"            │   │
│  │          GET github.com/orgs/optum/members/ramprasad │   │
│  │                                                      │   │
│  └─────────────────────────────────────────────────────┘   │
│                           │                                 │
│                           ▼                                 │
│  RESULT:                                                    │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  ✅ Verified: ramprasad (Optum)                      │   │
│  │  Source: GitHub SSH Key                              │   │
│  │  No pre-registration required!                       │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Key Innovation: Third-Party as Trusted Oracle

Instead of maintaining a proprietary key registry:

```
Traditional:       User → Register Key → Protocol DB → Verify
SSH Piggyback:     User → Existing SSH → GitHub API → Verify
```

GitHub/GitLab becomes the **trusted oracle** for key-to-user mapping.

### Dynamic Resolution Algorithm

```python
async def resolve_identity(signature: bytes, key_fingerprint: str) -> Identity:
    """
    Just-in-Time identity resolution via third-party API.
    No pre-registration required.
    """
    
    # Step A: Verify signature cryptographically
    if not verify_ssh_signature(signature, key_fingerprint):
        return Identity(verified=False, error="Invalid signature")
    
    # Step B: Enumerate known platforms
    platforms = ["github.com", "gitlab.com", "bitbucket.org"]
    
    for platform in platforms:
        # Query: "Who owns this SSH key?"
        owner = await lookup_key_owner(platform, key_fingerprint)
        
        if owner:
            # Step C: We found the owner!
            identity = Identity(
                verified=True,
                username=owner.username,
                platform=platform,
                email=owner.email,
            )
            
            # Step D: Check org membership (if needed by policy)
            if policy.requires_org_membership:
                is_member = await check_org_membership(
                    platform, 
                    policy.organization, 
                    owner.username
                )
                identity.is_org_member = is_member
            
            return identity
    
    # Key not found on any platform
    return Identity(verified=False, error="SSH key not registered on known platforms")
```

### Benefits

| Aspect | Traditional | SSH Piggyback |
|--------|-------------|---------------|
| **New key required** | Yes | No |
| **Registration step** | Required | None |
| **Day 1 coverage** | 0% | 100% |
| **Key management** | Duplicated | Reuse existing |
| **Enterprise adoption** | Slow | Instant |

### Supported Third-Party Oracles

| Platform | Key Lookup Endpoint | Org Check Endpoint |
|----------|--------------------|--------------------|
| GitHub | `GET /users/{u}/keys` | `GET /orgs/{o}/members/{u}` |
| GitLab | `GET /users/{id}/keys` | `GET /groups/{g}/members` |
| Bitbucket | `GET /users/{u}/ssh-keys` | `GET /workspaces/{w}/members` |

### Caching Strategy

```
SSH Fingerprint → User Mapping
├─ Cache TTL: 1 hour (balance freshness vs. rate limits)
├─ Invalidation: On 401/403 from API
└─ Fallback: Vouch Registry for non-platform keys
```

---

## Security Considerations

1. **Trust Model**: Trusting GitHub/GitLab as key attribution oracle
2. **Account Compromise**: If user's GitHub is compromised, identity is compromised
3. **Rate Limiting**: Batch lookups to avoid API rate limits
4. **Offline Mode**: Cache known mappings for offline verification
5. **Platform Diversity**: Support multiple platforms to avoid single point of failure

---

## Prior Art Declaration

This disclosure is published to establish prior art and prevent patent monopolization. The described method is hereby released into the public domain under the Creative Commons CC0 1.0 Universal dedication.

Any party implementing similar functionality after January 10, 2026 cannot claim novelty for patent purposes.

---

## Implementation Reference

Reference implementation in:
- `github-app/main.py` - `HybridVerifier` class
- `github-app/main.py` - `GitHubClient.get_user_ssh_keys()` method

Repository: https://github.com/vouch-protocol/vouch
