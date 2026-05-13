# PAD-058: Automated DID Rotation and Verifier Broadcast Pipeline Triggered by Static Detection of Cryptographic Identity Material in Source Repositories

**Identifier:** PAD-058
**Title:** Synchronous Leak-Detection-to-Rotation Pipeline for Decentralized Identifiers, with Dual-Signed Migration Credentials Bridging Classical and Post-Quantum Keypairs
**Publication Date:** May 14, 2026
**Prior Art Effective Date:** May 14, 2026
**Status:** Public Disclosure (Defensive Publication)
**Category:** Key Management / Incident Response / DevSecOps / Decentralized Identifiers / Post-Quantum Migration
**Author:** Ramprasad Anandam Gaddam
**License:** Apache 2.0
**Related:** PAD-001 (Cryptographic Agent Identity), PAD-016 (Dynamic Credential Renewal), PAD-031 (Canary Provenance Honeypots), PAD-040 (Hybrid Composite Signature), PAD-041 (Multikey Algorithm-Agnostic Verification), PAD-046 (Algorithm Quorum)

---

## 1. Abstract

A method that closes the loop between generic secret-scanning
infrastructure and decentralized-identifier key management. On
detection of cryptographic identity material in a source repository
— specifically Vouch-Protocol-shaped Ed25519 private JWKs,
seed material in environment-variable configurations, hybrid
post-quantum private keypairs, or DID Documents mistakenly carrying
private key material — the system executes a deterministic pipeline:

1. mark the leaked DID compromised in the protocol's revocation registry;
2. provision a fresh keypair through the operator's KMS or HSM;
3. publish an updated DID Document carrying both old and new
   verification methods, then remove the old method after a grace
   window;
4. issue a **dual-signed migration credential** signed by both the
   old key (proving control transfer is authorized) and the new key
   (establishing continuity of identity);
5. broadcast the rotation event to known verifiers via webhook /
   signed Pub-Sub / append-only ledger;
6. update the BitstringStatusList associated with the issuer to flag
   credentials issued by the leaked key with a "rotated, verify with
   caution" indicator.

The novel contribution is the **synchronous binding of generic leak
detection to identity-system rotation**: detection happens during
the same `git push` that introduced the leak, and the full rotation
cascade completes before the leaked key can be operationally
misused. The migration credential's dual-signature scheme
additionally supports the classical-to-hybrid-PQ transition: where
the leaked key was classical Ed25519, the new key may be hybrid
Ed25519+ML-DSA-44, and the migration credential is signed by the
old classical key plus the new hybrid key — preserving lineage
across the cryptosuite upgrade in a single rotation event.

---

## 2. Problem Statement

### 2.1 Generic Secret Scanners Miss Vouch-Shaped Material

Conventional secret scanners (TruffleHog, gitleaks, GitHub's native
secret scanning, detect-secrets) detect AWS keys, GitHub personal-
access tokens, Stripe secrets, and similar high-entropy strings with
known prefixes. Decentralized-identifier private key material has a
different shape:

- Ed25519 JWKs: JSON objects with `"kty":"OKP","crv":"Ed25519","d":...`
  where `d` is a 32-byte base64url string.
- Seed env vars: `VOUCH_ED25519_SEED=<64-char hex>` or
  `ED25519_PRIVATE_KEY_HEX=<64-char hex>`.
- DID Documents that mistakenly include `privateKeyJwk` or
  `privateKeyMultibase` in a `verificationMethod` entry (intended for
  publication, but private material accidentally retained).
- Hybrid post-quantum private keys: a concatenation of an Ed25519
  seed and an ML-DSA-44 secret key, totalling 2,560 bytes.

Generic scanners do not recognize these shapes. A leaked private
JWK in a public repository passes typical CI checks unnoticed.

### 2.2 Detection Without Rotation Is Insufficient

Even where a scanner detects Vouch-shaped material, the response is
ordinarily a human-readable alert that a developer must act on:
generate a new key, update the deployment, push a new DID Document,
notify verifiers. In practice this multi-hour-to-multi-day process is
the dominant period in which leaked keys are abused.

### 2.3 Rotation Without Identity Continuity Breaks Verifiers

A naive rotation — "delete the old verification method from the DID
Document and publish a new one" — creates verifier confusion:
in-flight credentials signed by the old key fail verification with no
indication that they were once valid. Verifiers cannot distinguish
"forged with a stolen key" from "legitimately signed before rotation
and not yet expired."

### 2.4 Post-Quantum Transition Compounds the Problem

The post-quantum migration (Section 13 of the Vouch specification,
the `hybrid-eddsa-mldsa44-jcs-2026` cryptosuite) introduces hybrid
keypairs that combine classical Ed25519 and ML-DSA-44 material. A
leak that occurs during the migration window may expose only the
classical portion, only the PQ portion, or both, with different
remediation requirements for each case. Generic rotation tools do not
distinguish these cases.

---

## 3. Disclosed Method

### 3.1 Architecture

```
+----------------+      +--------------------+      +-------------------+
| Git push /     |----->| vouch scan         |----->| Detection event   |
| CI run         |      | (leak scanner)     |      | (typed payload)   |
+----------------+      +--------------------+      +---------+---------+
                                                              |
                                                              v
                              +-------------------------------+-------------------------------+
                              | Rotation Pipeline (deterministic, idempotent)                |
                              |                                                              |
                              | 1. Revocation registry: mark leaked DID compromised          |
                              | 2. KMS / HSM: provision fresh keypair (matching cryptosuite) |
                              | 3. DID Document: add new VM first; schedule old VM removal   |
                              | 4. Migration credential: dual-signed by old + new keys       |
                              | 5. Verifier broadcast: webhook / Pub-Sub / ledger            |
                              | 6. BitstringStatusList: flag old key's credentials           |
                              +-------------------------------+-------------------------------+
                                                              |
                                                              v
                                                  +----------------------+
                                                  |  Known verifiers     |
                                                  |  receive update,     |
                                                  |  invalidate caches,  |
                                                  |  re-verify in-flight |
                                                  +----------------------+
```

### 3.2 Detection: Vouch-Aware Pattern Set

The leak scanner recognizes the following patterns. Detection occurs
locally in a developer's IDE, in CI for every push, or in a hosted
continuous monitor receiving repository webhooks.

```
1.  Ed25519 JWK with private component:
    \"kty\"\s*:\s*\"OKP\".*\"crv\"\s*:\s*\"Ed25519\".*\"d\"\s*:\s*\"[A-Za-z0-9_-]{43,44}\"

2.  Multibase-encoded Ed25519 private key:
    \"privateKeyMultibase\"\s*:\s*\"z[1-9A-HJ-NP-Za-km-z]{45,52}\"

3.  Seed environment variable patterns:
    (VOUCH_ED25519_SEED|ED25519_SEED|ED25519_PRIVATE_KEY)[\s=]+[0-9a-fA-F]{64}

4.  Hybrid PQ private keypair signature (concatenation):
    \"privateKeyHybridMultibase\"\s*:\s*\"u[A-Za-z0-9_-]{3408,3420}\"

5.  DID Document with a verificationMethod carrying privateKeyJwk:
    \"verificationMethod\"\s*:\s*\[.*\"privateKeyJwk\"

6.  Vouch-specific config files: vouch.json, agent.jwk, *.vouch.key
    (filenames recognized regardless of content)

7.  Mnemonic phrase patterns (12 / 24 words) near a vouch-sidecar config:
    BIP-39 wordlist match within N lines of a vouch-sidecar reference
```

Each match produces a structured detection event:

```json
{
    "detection_id": "det_8c3a...",
    "kind": "vouch_ed25519_private_jwk",
    "severity": "critical",
    "file": "config/agent.json",
    "line": 14,
    "matched_hash": "sha256:7f...4a",
    "candidate_did": "did:web:agent.example.com",
    "detected_at": "2026-05-14T08:31:17Z"
}
```

### 3.3 Rotation Pipeline: Six Deterministic Stages

A detection event triggers the pipeline. Stages run sequentially with
checkpoint persistence so that a partial failure (e.g., the KMS is
momentarily unavailable in stage 2) can resume from the last completed
checkpoint without re-executing prior stages.

#### Stage 1: Revocation registry update

The leaked DID is marked compromised. For Vouch:

```python
registry.revoke(RevocationRecord(
    did=detection.candidate_did,
    revoked_at=int(time.time()),
    reason="key_compromised_leak_detected",
    revoked_by=detection.detector_did,
    detection_id=detection.detection_id,
))
```

#### Stage 2: Fresh keypair provisioning

A new keypair is generated. **Cryptosuite policy: never downgrade.**
If the leaked key was classical Ed25519, the replacement is at least
classical Ed25519 (or stronger). If the leaked key was hybrid
Ed25519+ML-DSA-44, the replacement MUST be hybrid (or stronger
quorum). Where the operator's policy permits an opportunistic upgrade,
a classical-only key compromised during the post-quantum transition
window MAY be replaced with a hybrid keypair.

```python
old_suite = detect_cryptosuite(detection.matched_material)
new_suite = max(old_suite, operator_policy.minimum_cryptosuite)
new_keypair = kms.provision(suite=new_suite)
```

#### Stage 3: DID Document update — additive first, removal scheduled

The DID Document is updated in two atomic edits:

**3a.** Add the new verification method **first** to the
`verificationMethod` array and to the appropriate verification
relationship arrays (`assertionMethod`, `authentication`). At this
point both old and new methods are present; verifiers can accept
either. This is the brief overlap window.

**3b.** Schedule removal of the old verification method after a
configurable grace window. Default: 5 minutes for high-stakes
deployments; 24 hours for routine rotations where in-flight
credentials must continue to verify briefly.

The DID Document update is itself signed by the issuer of the DID
Document (the operator), not by the leaked key. For did:web, the
update is published via the operator's HTTPS endpoint.

#### Stage 4: Migration credential — dual-signed

A **migration credential** is issued. It is a Verifiable Credential
with:

- `issuer`: the DID being rotated
- `credentialSubject.id`: the same DID (self-referential, asserting
  identity continuity)
- `credentialSubject.priorVerificationMethod`: the old verification
  method id
- `credentialSubject.nextVerificationMethod`: the new verification
  method id
- `credentialSubject.rotationReason`: `key_compromised_leak_detected`
- `credentialSubject.detectionId`: the detection event ID
- `credentialSubject.effectiveAt`: timestamp when the new VM became
  authoritative
- `proof`: an **array** of two Data Integrity proofs:
  - one signed by the **old key** (using its current cryptosuite)
  - one signed by the **new key** (using its current cryptosuite)

The dual-signature scheme proves that:
1. The party who held the old key authorized the rotation (otherwise
   the old-key signature could not be produced).
2. The new key represents the same identity (otherwise the new-key
   signature would not bind to this subject DID).

A verifier inspecting a credential signed by the **old** key after
its retirement consults the migration credential, accepts the
identity continuity, and SHOULD raise the credential's status to
"rotated, verify with caution" rather than reject outright.

The cross-suite case (old classical + new hybrid) is the same flow:
the old-key proof uses `eddsa-jcs-2022`, the new-key proof uses
`hybrid-eddsa-mldsa44-jcs-2026`. The migration credential carries
both as separate entries in the `proof` array. The Multikey
multicodec discrimination (PAD-041) handles which proof a verifier
checks against which key.

#### Stage 5: Verifier broadcast

The rotation event is broadcast to known verifiers. Channels (in
order of preference):

1. **Webhook**: HTTP POST to each verifier's registered
   rotation-event endpoint, carrying the signed migration credential
   and updated DID Document URL. Verifiers acknowledge.
2. **Signed Pub-Sub**: publish to a topic the verifier subscribes to.
   The Pub-Sub message is itself signed by the operator's DID.
3. **Append-only ledger** (optional, for multi-organization
   deployments): the rotation event is appended to a public ledger
   verifiers poll. The ledger entry is signed by the operator.

Each broadcast is idempotent. A verifier receiving the same rotation
event twice processes it once.

#### Stage 6: BitstringStatusList update

For every BitstringStatusList associated with the rotating issuer, the
bits corresponding to credentials signed by the leaked key are
flagged. The exact semantics depend on the deployment's policy:

- **Strict**: set the bit to "revoked." All credentials by the leaked
  key are immediately invalid.
- **Cautious** (recommended for short-validity-window credentials):
  set a separate "rotated" bit (using a status purpose distinct from
  the default revocation). Verifiers see the rotation flag but may
  accept the credential if it is within its `validUntil` and the
  migration credential confirms continuity.

The choice between strict and cautious is operator policy, not
protocol mandate.

### 3.4 End-to-End Latency

The full pipeline (stages 1 through 6) is designed to complete within
60 seconds of detection for routine deployments and within 10 seconds
for high-stakes deployments using pre-provisioned standby keys. Most
of the latency is KMS round-trip and DID Document propagation; the
cryptographic operations are sub-millisecond.

### 3.5 Migration Credential Format (Concrete Example)

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://vouch-protocol.com/contexts/v1"
  ],
  "type": ["VerifiableCredential", "VouchMigrationCredential"],
  "issuer": "did:web:agent.example.com",
  "validFrom": "2026-05-14T08:31:50Z",
  "credentialSubject": {
    "id": "did:web:agent.example.com",
    "priorVerificationMethod": "did:web:agent.example.com#key-1",
    "nextVerificationMethod": "did:web:agent.example.com#key-2",
    "rotationReason": "key_compromised_leak_detected",
    "detectionId": "det_8c3a87f2",
    "effectiveAt": "2026-05-14T08:31:55Z"
  },
  "proof": [
    {
      "type": "DataIntegrityProof",
      "cryptosuite": "eddsa-jcs-2022",
      "created": "2026-05-14T08:31:50Z",
      "verificationMethod": "did:web:agent.example.com#key-1",
      "proofPurpose": "assertionMethod",
      "proofValue": "z3..."
    },
    {
      "type": "DataIntegrityProof",
      "cryptosuite": "hybrid-eddsa-mldsa44-jcs-2026",
      "created": "2026-05-14T08:31:51Z",
      "verificationMethod": "did:web:agent.example.com#key-2",
      "proofPurpose": "assertionMethod",
      "proofValue": "u..."
    }
  ]
}
```

The two proofs cover the same canonical JCS bytes of the credential
(with `proof` excluded). A verifier validates each proof
independently and accepts the migration when both succeed.

---

## 4. Distinction from Prior Art

### 4.1 vs. Generic Secret Scanners (TruffleHog, gitleaks, GitHub Secret Scanning)

Generic scanners detect secrets. PAD-058 closes the loop into
identity-system rotation. The scanners are components of PAD-058's
detection stage, not substitutes for the pipeline.

### 4.2 vs. Manual Key Rotation Playbooks

Existing key-rotation playbooks (PKI, SSH, GPG, cloud KMS) document
manual or semi-automated rotation procedures. They do not bind to
detection events from leak scanners, and they do not produce
identity-continuity credentials that bridge old and new keys. PAD-058
is the synchronous, automated, identity-aware version.

### 4.3 vs. PAD-016 (Dynamic Credential Renewal / Heartbeat)

PAD-016 renews credentials on a schedule under the assumption that
the issuing key is uncompromised. It does not address the case where
the issuing key itself must change. PAD-058 is the exceptional path:
when the key changes mid-life, the Heartbeat protocol of PAD-016
resumes against the new key after the migration credential
establishes continuity.

### 4.4 vs. PAD-031 (Canary Provenance Honeypots)

PAD-031 plants fake credentials in repositories as honeypots to
detect adversaries. PAD-058 detects **real** credentials that were
leaked by mistake and rotates them. The two compose: a honeypot from
PAD-031 may co-exist with the PAD-058 scanner; the scanner can
distinguish honeypot DIDs (registered as such) from real DIDs and
escalate the latter to rotation.

### 4.5 vs. Algorithm Migration Without Leak

Cryptosuite migration in the absence of a leak (a planned
classical-to-PQ migration on schedule) is a related but distinct
flow. PAD-058's migration credential format and dual-signature
mechanism MAY be reused for planned migrations; this disclosure does
not claim the planned-migration case as novel (it is implicit in any
multikey cryptosuite specification). The novel claim is the
**synchronous binding of automatic detection to automatic rotation**,
which the planned-migration case does not exhibit.

### 4.6 vs. PAD-046 (Algorithm Quorum Verification)

PAD-046 covers M-of-N cryptosuite quorum at verification time.
PAD-058 references PAD-046 for the "stronger replacement" rule (where
operator policy may require quorum-strong keypairs as replacements
for compromised keys), but PAD-058 does not re-claim quorum
verification.

### 4.7 vs. PAD-041 (Multikey Algorithm-Agnostic Verification)

PAD-041 enables verifiers to discriminate cryptosuites by Multikey
multicodec prefix. PAD-058 uses PAD-041 to handle cross-suite
migration credentials (old proof in one suite, new proof in another).
PAD-058 does not re-claim Multikey discrimination.

---

## 5. Claims

The defensive disclosure asserts public prior art for:

1. A method for binding detection of cryptographic identity material
   in source repositories to automated rotation of the corresponding
   Decentralized Identifier, executed as a single synchronous
   pipeline triggered by the detection event.
2. The specific detection pattern set for Vouch-Protocol-shaped
   material (Ed25519 JWKs, seed env vars, hybrid PQ keypair
   signatures, mistakenly-private DID Documents, vouch-specific
   filenames, mnemonic phrases proximate to vouch-sidecar configs).
3. The six-stage rotation pipeline: revocation, fresh keypair,
   additive DID Document update with scheduled removal, dual-signed
   migration credential, verifier broadcast, BitstringStatusList
   flag.
4. The **dual-signature migration credential** as the mechanism for
   identity continuity across rotation, where the credential
   carries a `proof` array containing one Data Integrity proof from
   the old key and one from the new key, both over the same canonical
   payload.
5. The cross-cryptosuite case of the dual-signed migration credential
   where the old-key proof and the new-key proof use different
   cryptosuites (classical and hybrid PQ), establishing identity
   continuity across the post-quantum transition in a single
   rotation event.
6. The **never-downgrade** rule for replacement keypairs and the
   policy for opportunistic upgrade (classical → hybrid) at
   rotation time.
7. The verifier broadcast protocol carrying the signed migration
   credential through webhook / signed Pub-Sub / append-only ledger
   channels, with idempotent processing semantics.
8. The end-to-end latency bound: rotation pipeline completion within
   seconds of detection, contrasted with the multi-hour-to-multi-day
   manual baseline.

---

## 6. Reference Implementation Sketch

Implementation will land in two open-source components and one
commercial component:

- **OSS**: `vouch scan <path>` — the Python CLI scanner, ships in the
  Vouch Python SDK. Implements the detection pattern set of §3.2.
  Exits non-zero if any matches found. Emits the structured
  detection-event JSON.
- **OSS**: Vouch Gatekeeper GitHub App extension — runs `vouch scan`
  on every PR diff; posts a check-run with file:line; fails the
  check on critical-severity matches.
- **Commercial (Vouch Pro)**: the **hosted continuous monitor** and
  the **rotation pipeline**. Subscribes to repository webhooks,
  scans force-pushed history, executes the full six-stage pipeline,
  manages the dual-signed migration credentials, broadcasts to
  registered verifiers.

The Pro component is operational infrastructure (state management,
SLAs, customer integrations) on top of open primitives. The
disclosure does not claim the commercial component's specific
features; it claims the **pattern** that the Pro component implements.

---

## 7. Security Considerations

### 7.1 Trust in the Detection Source

The pipeline trusts the detection event. A malicious detector could
trigger rotation of an uncompromised key (denial-of-service against
the legitimate operator). Defenses:

- Detection events MUST be signed by the detector's DID; only
  trusted-principal detectors trigger rotation.
- Operators MAY require multi-detector quorum before rotation
  triggers (M-of-N detectors must agree).
- Operators SHOULD set a cooldown period after a successful rotation
  to prevent rapid re-trigger.

### 7.2 KMS Availability

Stage 2 depends on KMS / HSM availability. The pipeline MUST be
resilient to KMS unavailability: the partial pipeline checkpoint
allows resumption when the KMS recovers. The leaked key remains
revoked (Stage 1 completes regardless), so the failure mode is
"identity is temporarily unavailable for new signing," not
"compromised identity continues operating."

### 7.3 Race Between Detection and Exploitation

If the attacker exploits the leaked key during the window between
leak commit and Stage 1 completion, those credentials enter
in-flight verification. The migration credential and the
BitstringStatusList flag give verifiers the option to reject those
credentials retroactively (cautious mode). Operators with
zero-tolerance for exploited credentials SHOULD configure strict
mode and accept the resulting in-flight credential invalidation.

### 7.4 DID Document Update Atomicity

Stage 3 publishes an updated DID Document. did:web's update mechanism
is HTTPS file replacement, which is not atomic for cached copies.
Verifiers with cached DID Documents must be invalidated; this is the
broadcast in Stage 5. Operators using did:web SHOULD set short cache
TTLs on the DID Document HTTPS response.

### 7.5 Migration Credential Replay

A migration credential, once issued, is permanent. It cannot be
"reversed" if the operator changes their mind. Operators SHOULD treat
rotation as irreversible and ensure detection events are correct
before triggering Stage 1. The cooldown of §7.1 helps catch
accidental triggers.

### 7.6 Disclosure of Leaked Material

The detection event includes a hash of the leaked material (for
cross-referencing) but MUST NOT include the leaked material itself.
The pipeline's logs and audit records MUST treat leaked material as
sensitive data and avoid persistence.

---

## 8. Privacy Considerations

The pipeline operates on the operator's own keys and DIDs. It does
not collect, store, or transmit third-party data. The detection
events processed by the pipeline are limited to material that
matches the operator-controlled detection-pattern set; pattern
matching is deterministic and does not involve ML inference on
repository contents.

For a hosted continuous monitor (the Pro component), the monitor
SHOULD process repository contents in-memory only and persist only
the detection event payload (hashes, not material). Customer
repositories remain in the customer's GitHub / GitLab account; the
monitor is a reader, not a copy.

---

## 9. Conclusion

This disclosure establishes public prior art for the **synchronous
detection-to-rotation pipeline for Decentralized Identifier private
key material**, including the dual-signed migration credential
format that preserves identity continuity across rotation events,
the cross-cryptosuite case bridging classical and post-quantum
keypairs in a single rotation, the never-downgrade replacement
policy, and the verifier broadcast protocol that propagates the
rotation through known relying parties within seconds of detection.

The author publishes this disclosure under Apache 2.0 (the
reference implementations to follow) and CC0 (this disclosure
document itself) to maintain free availability to the open
decentralized-identity community and to prevent appropriation of the
pattern by patent claims from any third party.

---

## 10. References

- [PAD-001] Cryptographic Agent Identity (Gaddam, December 2025)
- [PAD-016] Dynamic Credential Renewal / Heartbeat Protocol (Gaddam, February 2026)
- [PAD-031] Canary Provenance Honeypots (Gaddam, April 2026)
- [PAD-040] Hybrid Composite Signature Bound to Same Canonical Bytes (Gaddam, April 2026)
- [PAD-041] Multikey Algorithm-Agnostic Verification Method Resolution (Gaddam, April 2026)
- [PAD-046] Algorithm Quorum Verification via M-of-N Cryptosuite Diversity (Gaddam, April 2026)
- [VOUCH-SPEC] Vouch Protocol Specification, v0.1-draft, §11.2 (Credential Status), §13 (Crypto-Agility)
- [W3C-VC-2.0] Verifiable Credentials Data Model 2.0
- [W3C-DID-CORE] Decentralized Identifiers (DIDs) v1.0
- [VC-BITSTRING-STATUS-LIST] Bitstring Status List v1.0
- [NIST-FIPS-204] Module-Lattice-Based Digital Signature Standard (ML-DSA)
- [RFC 8785] JSON Canonicalization Scheme
