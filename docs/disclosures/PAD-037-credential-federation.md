# PAD-037: Cross-Protocol Agent Credential Federation

**Identifier:** PAD-037
**Title:** Method for Bidirectional Credential Translation Between Decentralized Agent Identity and Legacy Enterprise Authentication Protocols
**Publication Date:** April 22, 2026
**Prior Art Effective Date:** April 22, 2026
**Status:** Public Disclosure (Defensive Publication)
**Category:** Identity Federation / Enterprise Integration / Authentication / Interoperability / Standards Bridge
**Author:** Ramprasad Anandam Gaddam
**Related:** PAD-001 (Cryptographic Agent Identity), PAD-003 (Vouch-Token Specification), PAD-016 (Dynamic Credential Renewal), PAD-036 (Aggregated Reputation Scoring)

---

## 1. Abstract

A system and method for enabling seamless, bidirectional credential translation between the Vouch Protocol's DID-based agent identity system and legacy enterprise authentication protocols (OAuth 2.0, OpenID Connect, SAML 2.0, API Keys, mTLS certificates, and Verifiable Credentials). The protocol solves the **enterprise adoption barrier**: organizations with existing authentication infrastructure cannot adopt agent identity protocols that require wholesale replacement of their auth stack.

The system introduces a **Federation Envelope** architecture with five interlocking mechanisms:

1. **Credential Translation Engine (CTE):** A stateless translation layer that converts Vouch Tokens (PAD-003) into protocol-native credentials (OAuth Bearer tokens, SAML assertions, OIDC ID tokens) and vice versa, preserving the cryptographic provenance chain across the translation boundary. The CTE does not store credentials; it generates ephemeral protocol-native tokens from verified Vouch credentials on demand.

2. **Trust Anchor Mapping:** A declarative policy language for enterprises to define equivalence mappings between Vouch Protocol trust levels (DID verification, PAD-036 reputation tiers, delegation chain depth) and their native authorization scopes (OAuth scopes, SAML attributes, RBAC roles). Example: "Vouch agents with reputation tier >= 4 AND delegation depth <= 2 map to OAuth scope `data:read`."

3. **Bidirectional Provenance Preservation:** When a Vouch Token is translated into an OAuth Bearer token, the original DID, signature, and delegation chain are encoded as JWT private claims. When an OAuth token is presented by a legacy system interacting with Vouch-native agents, the CTE wraps it in a Vouch-compatible envelope with the OAuth issuer's identity used as a bridge DID (`did:web:auth.enterprise.com`).

4. **Federation Session Binding:** Translated credentials are bound to the original Vouch session via a cryptographic session token. If the Vouch credential is revoked (PAD-016 heartbeat failure, PAD-032 mortality event), all derived protocol-native tokens are automatically invalidated via session binding, preventing orphaned access tokens from persisting after identity revocation.

5. **Zero-Trust Translation Auditing:** Every credential translation event produces a signed audit record binding the input credential (Vouch Token) to the output credential (OAuth/SAML/OIDC token), enabling end-to-end audit trails that span the federation boundary.

---

## 2. Problem Statement

### 2.1 The Enterprise Auth Stack Reality

No enterprise will adopt DID-based agent identity if it means replacing their existing authentication infrastructure:

| Enterprise Auth System | Market Penetration | Replacement Cost |
|----------------------|-------------------|-----------------|
| OAuth 2.0 / OIDC | ~95% of web APIs | Months of engineering |
| SAML 2.0 | ~80% of enterprise SSO | Organizational change |
| API Keys | ~99% of developer APIs | Millions of integrations |
| mTLS | ~40% of service mesh | Infrastructure overhaul |
| Verifiable Credentials | ~5% (emerging) | Greenfield only |
| **Vouch Protocol DID** | **<1% (new)** | **Requires bridge, not replacement** |

### 2.2 Current State: No Bridge Exists

| Approach | Limitation |
|----------|-----------|
| Replace enterprise auth with DIDs | Impractical; enterprises won't rewrite auth |
| Run parallel auth systems | Double maintenance; inconsistent access control |
| Manual credential mapping | Error-prone; no provenance preservation |
| OAuth-to-DID academic proposals | No implementation; no bidirectional support |
| **This disclosure** | **Stateless translation with provenance preservation** |

### 2.3 The Provenance Gap at Federation Boundaries

When a Vouch-authenticated agent's request crosses into an OAuth-protected API, the cryptographic identity chain breaks:

```
Vouch Domain          | Federation Boundary |  OAuth Domain
                |           |
Agent DID: did:vouch:z6Mk...  |           |
Vouch Token: signed, auditable |  ??? gap ???    |  Bearer token: opaque string
Delegation chain: verified   |           |  OAuth scope: "read"
Reputation: Tier 4 (TRUSTED)  |           |  No reputation context
                |           |
Full provenance available    | Provenance lost  |  No provenance
```

The enterprise loses all the trust signals that Vouch provides, reducing agent interactions to bare OAuth scope checks.

---

## 3. Solution (The Invention)

### 3.1 Federation Envelope Architecture

```
+---------------------------------------------------------------+
| Vouch-Native Agent                      |
| DID: did:vouch:z6MkAgent123                 |
| Vouch Token: [signed intent + delegation + reputation]   |
+------------------------------+--------------------------------+
                |
                v
+---------------------------------------------------------------+
| Credential Translation Engine (CTE)             |
|                                |
| 1. Verify Vouch Token (PAD-003 validation)         |
| 2. Check reputation (PAD-036 query)             |
| 3. Apply Trust Anchor Mapping                |
| 4. Generate protocol-native credential           |
| 5. Embed provenance as private claims            |
| 6. Bind to federation session                |
| 7. Emit audit record                    |
+------------------------------+--------------------------------+
                |
        +---------------+---------------+
        |        |        |
        v        v        v
    +-----------+  +-----------+  +-----------+
    | OAuth 2.0 |  | SAML 2.0 |  | OIDC   |
    | Bearer  |  | Assertion |  | ID Token |
    | Token   |  |      |  |      |
    +-----------+  +-----------+  +-----------+
        |        |        |
        v        v        v
    Enterprise APIs Enterprise SSO Enterprise IdP
```

### 3.2 Credential Translation: Vouch to OAuth 2.0

**Input:** Vouch Token (PAD-003)

**Output:** OAuth 2.0 Bearer Token (JWT)

```json
{
 "header": {
  "alg": "ES256",
  "typ": "at+jwt",
  "kid": "cte-signing-key-001"
 },
 "payload": {
  "iss": "https://federation.vouch-protocol.com",
  "sub": "did:vouch:z6MkAgent123",
  "aud": "https://api.enterprise.com",
  "exp": 1713783660,
  "iat": 1713783600,
  "scope": "data:read api:query",
  "client_id": "vouch-agent-z6MkAgent123",

  "vouch_provenance": {
   "vouch_token_hash": "sha256:H(original_vouch_token)",
   "agent_did": "did:vouch:z6MkAgent123",
   "delegation_depth": 1,
   "delegation_root": "did:vouch:z6MkOperator789",
   "reputation_tier": 4,
   "reputation_score": 87.3,
   "vouch_signature_alg": "Ed25519",
   "federation_session_id": "fed-sess-2026-04-22-001"
  }
 },
 "signature": "CTE_signs_with_ES256"
}
```

**Provenance Preservation:** The `vouch_provenance` claim embeds the complete identity chain. Enterprise APIs can:
- Ignore it (backward compatible; works as standard OAuth token)
- Inspect it (enhanced trust decisions using reputation data)
- Verify it (reconstruct and validate the original Vouch Token)

### 3.3 Credential Translation: OAuth to Vouch

When a legacy OAuth-authenticated system needs to interact with Vouch-native agents:

```json
{
 "vouch_federation_envelope": {
  "envelope_type": "oauth_bridge",
  "bridge_did": "did:web:auth.enterprise.com",
  "original_credential": {
   "type": "oauth2_bearer",
   "issuer": "https://auth.enterprise.com",
   "subject": "service-account-inventory-bot",
   "scopes": ["inventory:read", "inventory:write"],
   "token_hash": "sha256:H(original_bearer_token)"
  },
  "vouch_mapping": {
   "mapped_did": "did:web:auth.enterprise.com:service-account-inventory-bot",
   "trust_level": "federation_bridge",
   "capabilities": ["inventory:read", "inventory:write"],
   "max_delegation_depth": 0,
   "reputation_source": "enterprise_internal"
  },
  "federation_session_id": "fed-sess-2026-04-22-002",
  "cte_signature": "ed25519:CTE_signs_envelope"
 }
}
```

### 3.4 Trust Anchor Mapping Language

Enterprises define credential equivalence policies:

```yaml
federation_policy:
 name: "enterprise-vouch-integration-v1"
 issuer_did: "did:web:api.enterprise.com"

 vouch_to_oauth_mappings:
  - name: "trusted-agent-full-access"
   conditions:
    reputation_tier: ">= 4"
    delegation_depth: "<= 2"
    delegation_root_did: "did:vouch:z6MkApprovedOperator*"
    credential_age_hours: "<= 24"
   grants:
    oauth_scopes: ["data:read", "data:write", "api:query", "api:mutate"]
    token_lifetime_seconds: 3600
    refresh_allowed: true

  - name: "provisional-agent-read-only"
   conditions:
    reputation_tier: ">= 2"
    delegation_depth: "<= 1"
   grants:
    oauth_scopes: ["data:read", "api:query"]
    token_lifetime_seconds: 300
    refresh_allowed: false

  - name: "unknown-agent-sandbox"
   conditions:
    reputation_tier: ">= 0"
   grants:
    oauth_scopes: ["sandbox:read"]
    token_lifetime_seconds: 60
    refresh_allowed: false

 oauth_to_vouch_mappings:
  - name: "enterprise-service-accounts"
   conditions:
    oauth_issuer: "https://auth.enterprise.com"
    required_scopes: ["service:verified"]
   grants:
    vouch_trust_level: "federation_bridge"
    max_delegation_depth: 0

 revocation_policy:
  on_vouch_heartbeat_failure: "revoke_all_derived_tokens"
  on_vouch_mortality_event: "revoke_and_audit"
  on_oauth_token_revocation: "invalidate_federation_session"
```

### 3.5 Federation Session Binding

All translated credentials are bound to a cryptographic session:

```json
{
 "federation_session": {
  "session_id": "fed-sess-2026-04-22-001",
  "vouch_credential_hash": "sha256:H(vouch_token)",
  "derived_credentials": [
   {
    "protocol": "oauth2",
    "token_hash": "sha256:H(oauth_bearer_token)",
    "issued_at": "2026-04-22T10:00:00Z",
    "expires_at": "2026-04-22T11:00:00Z",
    "target_system": "api.enterprise.com"
   }
  ],
  "binding_mechanism": "session_id_embedded_in_all_derived_tokens",
  "revocation_webhook": "https://federation.vouch-protocol.com/v1/sessions/fed-sess-001/revoke"
 }
}
```

**Revocation Cascade:** If PAD-016 heartbeat fails or PAD-032 mortality triggers:
1. Vouch credential is revoked.
2. Federation session is invalidated.
3. All derived OAuth/SAML/OIDC tokens are revoked via the revocation webhook.
4. Enterprise token introspection endpoints return `active: false`.

### 3.6 Supported Protocol Translations

| Source | Target | Translation Method |
|--------|--------|-------------------|
| Vouch Token | OAuth 2.0 Bearer (JWT) | JWT with `vouch_provenance` private claims |
| Vouch Token | SAML 2.0 Assertion | SAML assertion with Vouch attribute statement |
| Vouch Token | OIDC ID Token | ID token with Vouch claims in `vouch` namespace |
| Vouch Token | mTLS Client Cert | Ephemeral X.509 cert with DID in SAN extension |
| Vouch Token | API Key | API key mapped to DID in CTE's session store |
| Vouch Token | Verifiable Credential | VC with DID subject and Vouch proof |
| OAuth 2.0 | Vouch Federation Envelope | Bridge DID derived from OAuth issuer |
| SAML 2.0 | Vouch Federation Envelope | Bridge DID derived from SAML IdP EntityID |
| API Key | Vouch Federation Envelope | Bridge DID derived from API key issuer |

### 3.7 Translation Audit Trail

Every credential translation produces a signed audit record:

```json
{
 "translation_audit": {
  "audit_id": "audit-2026-04-22-a7f3c2e1",
  "timestamp": "2026-04-22T10:00:00Z",
  "direction": "vouch_to_oauth",
  "input_credential": {
   "type": "vouch_token",
   "agent_did": "did:vouch:z6MkAgent123",
   "token_hash": "sha256:H(vouch_token)"
  },
  "output_credential": {
   "type": "oauth2_bearer",
   "token_hash": "sha256:H(oauth_token)",
   "scopes_granted": ["data:read", "api:query"],
   "expires_at": "2026-04-22T11:00:00Z"
  },
  "policy_applied": "trusted-agent-full-access",
  "reputation_at_translation": 87.3,
  "federation_session_id": "fed-sess-2026-04-22-001",
  "cte_signature": "ed25519:CTE_signs_audit"
 }
}
```

---

## 4. Prior Art Differentiation

| System | Bidirectional Translation | Provenance Preservation | Session Binding | Reputation-Aware | Agent-Specific |
|--------|--------------------------|------------------------|----------------|-----------------|---------------|
| OAuth 2.0 Token Exchange (RFC 8693) | Unidirectional (OAuth-to-OAuth) | No | No | No | No |
| SAML-to-OIDC bridges | Unidirectional | Partial (attribute mapping) | No | No | No |
| W3C DID-OIDC bridge proposals | Research only | Theoretical | No | No | No |
| Keycloak identity brokering | Unidirectional (IdP-to-IdP) | No | Basic session | No | No |
| **This disclosure** | **Yes (6 protocol pairs)** | **Yes (private claims)** | **Yes (cascade revocation)** | **Yes (PAD-036)** | **Yes** |

Key differentiators:
1. **No existing system** provides bidirectional credential translation between DID-based agent identity and OAuth/SAML/OIDC with cryptographic provenance preservation across the translation boundary.
2. **No existing system** implements a declarative trust anchor mapping language that converts agent reputation tiers and delegation chain depth into protocol-native authorization scopes.
3. **No existing system** provides cascade revocation where identity lifecycle events (heartbeat failure, mortality) automatically invalidate all derived protocol-native tokens across multiple enterprise systems.
4. **No existing system** embeds the complete DID provenance chain (delegation root, reputation, signature algorithm) as verifiable private claims within standard OAuth/OIDC tokens.

---

## 5. Technical Implementation

### 5.1 Data Model

```
Key: federation:session:{session_id} - Hash (vouch_hash, status, created, expires)
Key: federation:session:{session_id}:tokens - Set of derived token hashes
Key: federation:policy:{enterprise_did} - Trust anchor mapping YAML
Key: federation:audit:{audit_id} - Hash (direction, input, output, policy, signature)
Key: federation:bridge_did:{oauth_issuer} - Mapped bridge DID
Key: federation:revocation:{token_hash} - Hash (revoked_at, reason, session_id)
```

### 5.2 Performance Targets

| Metric | Target |
|--------|--------|
| Translation latency (Vouch to OAuth) | < 10ms |
| Translation latency (OAuth to Vouch) | < 15ms |
| Revocation cascade latency | < 100ms to all derived tokens |
| Concurrent federation sessions | >= 100,000 |
| Audit record write throughput | >= 50,000/second |

---

## 6. Claims Summary

The following aspects are disclosed as prior art:

1. A bidirectional credential translation engine that converts DID-based agent identity tokens into protocol-native credentials (OAuth 2.0, SAML 2.0, OIDC, mTLS, API Keys, W3C VC) and vice versa, enabling agent identity to function within existing enterprise authentication infrastructure without replacement.

2. A provenance preservation mechanism that embeds the complete DID identity chain (agent DID, delegation root, delegation depth, reputation tier, signature algorithm) as verifiable private claims within translated protocol-native tokens, maintaining audit trail continuity across federation boundaries.

3. A declarative trust anchor mapping language that enables enterprises to define conditional equivalence rules between Vouch Protocol trust levels (reputation tiers, delegation depth, credential age) and native authorization scopes (OAuth scopes, SAML attributes, RBAC roles).

4. A federation session binding mechanism with cascade revocation, where all derived protocol-native tokens are automatically invalidated when the source Vouch credential is revoked due to heartbeat failure (PAD-016) or mortality event (PAD-032).

5. A zero-trust translation audit trail producing signed records for every credential translation event, enabling end-to-end audit trails that span the federation boundary between DID-native and legacy authentication domains.

---

## Prior Art Declaration

This document is published as a defensive prior art disclosure under the Apache 2.0 license. The methods and systems described herein are hereby placed into the public domain to prevent patent monopolization. Any party implementing similar functionality after the publication date of this document cannot claim novelty for patent purposes.

**Reference Implementation:** https://github.com/vouch-protocol/vouch

---

## Update (April 27, 2026): Data Integrity Embodiment & JCS-Determinism Strengthening

The Credential Federation protocol translates between Vouch credentials
and legacy enterprise authentication protocols. This disclosure
additionally covers two refinements arising from the v1.0 specification:

**Embodiment broadening:** The Vouch credential side of the translation
boundary may be a Verifiable Credential secured by a W3C Data
Integrity proof (`eddsa-jcs-2022` or `hybrid-eddsa-mldsa44-jcs-2026`) in
addition to the originally-described JWS form. The Credential Translation
Engine, Trust Anchor Mapping, and Bidirectional Provenance Preservation
mechanisms operate identically against either form, since both expose
the issuer DID, the intent payload, and the temporal claims to the
translation layer.

**JCS determinism strengthening:** The VC embodiment enables the
Federation Envelope to preserve the issuer's original signed canonical
form (the JCS-canonicalized credential bytes) when translating into
legacy protocols. A legacy verifier receiving an OAuth Bearer token can,
if it implements the Vouch Federation extension, recover and
independently verify the original Data Integrity proof against the
issuer's Multikey verification method, without trusting the Credential
Translation Engine's serializer. This determinism property strengthens
the bidirectional provenance preservation claim by eliminating a
previously-implicit dependency on the federation gateway as a serialization
oracle. Both refinements are disclosed as additional prior art for the
same inventive cross-protocol federation mechanism.
