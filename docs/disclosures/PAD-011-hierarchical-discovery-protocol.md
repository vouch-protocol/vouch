# Defensive Disclosure: Hierarchical Discovery Protocol for Local Provenance Services

**Disclosure ID:** PAD-011  
**Publication Date:** January 24, 2026  
**Author:** Ramprasad Anandam Gaddam  
**Status:** Public Domain / Prior Art  

---

## Abstract

A client-side negotiation protocol that enables web applications to automatically discover and utilize the most secure available signing provider on a user's device. The protocol defines a **"Hierarchy of Trust"** where the application sequentially attempts to handshake with: (1) A Local Native Bridge (highest security), (2) A Browser Extension (medium security), and (3) A Cloud/Software Fallback (lowest security). This ensures backward compatibility while seamlessly upgrading security for users with native hardware support, without requiring any code changes or user configuration.

---

## Problem Statement

Web applications currently rely on hardcoded integration points for identity:

- **Single Provider Lock-in:** Applications are built for one provider (e.g., "Login with X")
- **No Upgrade Path:** Users with hardware security keys cannot leverage them if the app only supports software wallets
- **Manual Configuration:** Users must configure each application separately
- **Discovery Failure:** There is no standard mechanism for a web page to ask, "Does this user have a hardware-backed C2PA signer installed locally?"
- **Graceful Degradation:** Applications cannot fall back to less secure options when preferred options are unavailable

---

## Disclosed Method

We disclose the **"Universal Adapter Discovery Protocol"** for hierarchical provider selection.

### Discovery Hierarchy

```
┌─────────────────────────────────────────────────────────────────────────┐
│              HIERARCHICAL DISCOVERY PROTOCOL                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  Level 1: LOCAL NATIVE BRIDGE (Highest Security)                 │   │
│  │  ────────────────────────────────────────────────────────────    │   │
│  │  Probe: HEAD/GET to http://127.0.0.1:7823/status                 │   │
│  │  Timeout: 2000ms                                                  │   │
│  │                                                                   │   │
│  │  Security Properties:                                             │   │
│  │  ✅ Keys in OS Keyring (hardware-backed possible)                │   │
│  │  ✅ Human-in-the-Loop consent                                    │   │
│  │  ✅ Cross-application identity                                   │   │
│  │  ✅ C2PA media signing                                           │   │
│  │                                                                   │   │
│  │  If found: BIND SESSION → Level 1 provider                       │   │
│  │  If not found: Fall through to Level 2                           │   │
│  └───────────────────────────┬─────────────────────────────────────┘   │
│                              │ PROBE FAILED                             │
│                              ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  Level 2: BROWSER EXTENSION (Medium Security)                    │   │
│  │  ────────────────────────────────────────────────────────────    │   │
│  │  Probe: Check for window.vouch global object                     │   │
│  │  Timeout: Synchronous check                                       │   │
│  │                                                                   │   │
│  │  Security Properties:                                             │   │
│  │  ⚠️ Keys in IndexedDB (browser-sandboxed)                       │   │
│  │  ⚠️ Extension-only consent                                       │   │
│  │  ❌ Browser-isolated identity                                    │   │
│  │  ❌ Text-only signing (no C2PA)                                  │   │
│  │                                                                   │   │
│  │  If found: BIND SESSION → Level 2 provider                       │   │
│  │  If not found: Fall through to Level 3                           │   │
│  └───────────────────────────┬─────────────────────────────────────┘   │
│                              │ PROBE FAILED                             │
│                              ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  Level 3: CLOUD/SOFTWARE FALLBACK (Lowest Security)              │   │
│  │  ────────────────────────────────────────────────────────────    │   │
│  │  Probe: Check configuration for cloud endpoint                   │   │
│  │  Timeout: Network-dependent                                       │   │
│  │                                                                   │   │
│  │  Security Properties:                                             │   │
│  │  ❌ Keys on remote server                                        │   │
│  │  ❌ Network-dependent                                            │   │
│  │  ❌ Privacy implications                                         │   │
│  │  ⚠️ Useful for onboarding                                        │   │
│  │                                                                   │   │
│  │  If found: BIND SESSION → Level 3 provider                       │   │
│  │  If not found: THROW VouchServiceNotFoundError                   │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Discovery Algorithm

```typescript
async function discoverProvider(): Promise<VouchProvider> {
    // Level 1: Try Local Bridge (Highest Security)
    try {
        const response = await fetch('http://127.0.0.1:7823/status', {
            method: 'GET',
            signal: AbortSignal.timeout(2000)
        });
        
        if (response.ok) {
            const status = await response.json();
            if (status.status === 'ok') {
                return {
                    level: 1,
                    type: 'bridge',
                    capabilities: ['sign', 'signMedia', 'c2pa', 'consent'],
                    security: 'hardware-backed'
                };
            }
        }
    } catch (e) {
        // Bridge not available, continue to Level 2
    }

    // Level 2: Try Browser Extension (Medium Security)
    if (typeof window !== 'undefined' && window.vouch) {
        return {
            level: 2,
            type: 'extension',
            capabilities: ['sign'],
            security: 'browser-sandboxed'
        };
    }

    // Level 3: Cloud Fallback (Lowest Security)
    if (config.cloudEndpoint) {
        return {
            level: 3,
            type: 'cloud',
            capabilities: ['sign'],
            security: 'remote'
        };
    }

    // No provider found
    throw new VouchServiceNotFoundError();
}
```

### Capability Handshake

After discovery, the client and provider exchange capabilities:

```json
{
    "version": "1.0.0",
    "provider": "bridge",
    "capabilities": {
        "sign": true,
        "signMedia": true,
        "c2pa": true,
        "consent": "always",
        "algorithms": ["Ed25519", "ECDSA-P256"],
        "mediaTypes": ["image/jpeg", "image/png", "video/mp4"],
        "maxFileSize": 104857600
    },
    "identity": {
        "did": "did:key:z6Mkv...",
        "fingerprint": "abc123"
    }
}
```

---

## Novel Claims

### Claim 1: Hierarchical Security Escalation
A discovery sequence for establishing a cryptographic session that prioritizes local OS-level daemons over browser-level extensions without user intervention, automatically selecting the most secure available option.

### Claim 2: Transparent Failover
A single application codebase can dynamically support both "High Assurance" (Hardware Key via Bridge) and "Low Assurance" (Software Key via Extension) users without conditional logic in the application layer.

### Claim 3: Reserved Port Auto-Discovery
The use of a standardized localhost port (7823) as a well-known service endpoint for cryptographic signing, enabling zero-configuration discovery analogous to mDNS/Bonjour for local services.

### Claim 4: Capability Negotiation Protocol
A handshake mechanism where the discovered provider advertises its capabilities (supported algorithms, media types, consent modes), allowing the client to adapt its behavior accordingly.

### Claim 5: Progressive Enhancement for Security
Users who install the Bridge daemon automatically get upgraded security (hardware-backed keys, C2PA support) on existing applications without the application needing to update.

### Claim 6: Probe Timeout Cascading
A tiered timeout strategy where faster probes (2s for localhost) are attempted first, with slower network probes only attempted after local options are exhausted.

### Claim 7: Session Binding with Provider Affinity
Once a provider is discovered and bound to a session, subsequent operations use the same provider for consistency, preventing signature fragmentation across multiple identities.

### Claim 8: Cross-Origin Discovery Isolation
The localhost probe is exempt from CORS restrictions (same-machine origin), but the discovered provider's API must still validate CORS for actual signing operations.

---

## Use Case Scenarios

### Scenario A: Power User (Full Stack)

```
User has: Bridge Daemon + Extension installed

Discovery:
1. Probe localhost:7823 → ✅ Found
2. Return Level 1 provider

Result:
• Hardware-backed signatures
• C2PA media signing
• Consent popups
```

### Scenario B: Casual User (Extension Only)

```
User has: Extension only (no Bridge)

Discovery:
1. Probe localhost:7823 → ❌ Connection refused
2. Check window.vouch → ✅ Found
3. Return Level 2 provider

Result:
• Browser-based signatures
• Text signing only
```

### Scenario C: New User (Nothing Installed)

```
User has: No Vouch software

Discovery:
1. Probe localhost:7823 → ❌ Connection refused
2. Check window.vouch → ❌ undefined
3. Check cloud config → ✅ Configured
4. Return Level 3 provider

Result:
• Cloud-based signing
• Prompt to install Bridge for better security
```

---

## Security Considerations

| Consideration | Mitigation |
|---------------|------------|
| Localhost squatting | Port 7823 reserved, verify status response |
| Fake provider | Capability verification before use |
| Discovery timing attack | Fixed 2s timeout regardless of load |
| Provider impersonation | DID verification after handshake |
| Downgrade attack | Log provider level, warn on sudden downgrade |

---

## Implementation Reference

Reference implementation in:
- `vouch-adapter/src/index.ts` - `VouchAdapter.connect()` method
- `vouch-adapter/src/index.ts` - `tryConnectBridge()` and `tryConnectExtension()`

Repository: https://github.com/vouch-protocol/vouch

---

## Prior Art Declaration

This disclosure is published to establish prior art and prevent patent monopolization. The described method is hereby released into the public domain under the Creative Commons CC0 1.0 Universal dedication.

Any party implementing similar functionality after January 24, 2026 cannot claim novelty for patent purposes.
