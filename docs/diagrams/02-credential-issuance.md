# 2.5 Credential Issuance Flow

End-to-end path from an application's intent to a signed W3C Verifiable
Credential with a Data Integrity proof attached as a sibling object.

Same path works for the default `eddsa-jcs-2022` cryptosuite and the
hybrid `hybrid-eddsa-mldsa44-jcs-2026` profile; the only difference is
whether ML-DSA-44 also signs the canonical bytes.

```mermaid
sequenceDiagram
    autonumber
    participant App as Application Code
    participant SDK as Vouch SDK<br/>(vouch.vc)
    participant JCS as JCS Canonicalizer<br/>(RFC 8785)
    participant Sgn as Signer / Identity Sidecar
    participant Out as Signed Credential

    App->>SDK: build_vouch_credential(<br/>issuer_did, intent={action, target, resource},<br/>valid_seconds=300, ...)
    SDK->>SDK: validate intent<br/>(action, target, resource required)
    SDK-->>App: unsigned VC dict<br/>{@context, type, issuer,<br/>validFrom, validUntil, credentialSubject}
    App->>Sgn: sign_credential(unsigned_vc)
    Sgn->>Sgn: attach proof options<br/>(type, cryptosuite, verificationMethod,<br/>proofPurpose, created)
    Sgn->>JCS: canonicalize(vc + proof options,<br/>excluding proofValue)
    JCS-->>Sgn: deterministic byte sequence<br/>(byte-identical across Python / TS / Go)
    Sgn->>Sgn: SHA-256 digest of canonical bytes
    Sgn->>Sgn: Ed25519 sign(digest)
    opt hybrid profile
        Sgn->>Sgn: ML-DSA-44 sign(same digest)<br/>(PAD-040 same-bytes property)
        Sgn->>Sgn: concat ed25519_sig || mldsa44_sig
    end
    Sgn->>Sgn: multibase base58btc encode<br/>(prefix "z")
    Sgn->>Out: VC with proof sibling object
    Note over Out: { "@context": [...],<br/>  "type": ["VerifiableCredential", "VouchCredential"],<br/>  "credentialSubject": { intent: {...} },<br/>  "proof": {<br/>    "type": "DataIntegrityProof",<br/>    "cryptosuite": "eddsa-jcs-2022",<br/>    "verificationMethod": "did:web:agent.example#key-1",<br/>    "proofValue": "z..." } }
```

## What it answers

- What does `build_vouch_credential` actually return? An unsigned VC dict
  (no proof yet), ready for the signer to attach a Data Integrity proof.
- What gets signed? The JCS canonical bytes of the VC plus the proof
  options (everything except `proofValue` itself).
- Why JCS? It is byte-deterministic, so Python / TypeScript / Go all
  produce the same bytes for the same input. Verification across languages
  is then trivially correct.
- What changes for hybrid PQ? Both Ed25519 and ML-DSA-44 sign the SAME
  canonical-bytes digest. The two raw signatures are concatenated; the
  whole blob is base58-encoded into one `proofValue`. The credential
  structure is otherwise unchanged.
