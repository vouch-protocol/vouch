# GDPR — Vouch Protocol™ mapping

**Status:** Skeleton. The mappings below are draft and require legal
review for any production compliance claim.

## Summary

**Where Vouch helps:**
- **Article 5(1)(f) — Integrity and confidentiality (security of processing):**
  Cryptographic per-action signing provides tamper-evident audit trails.
- **Article 5(2) — Accountability:** The credential chain provides
  cryptographic provenance of who authorised which processing operation.
- **Article 25 — Data protection by design and by default:** The
  Identity Sidecar pattern is a design-time control that bounds an
  agent's capabilities; the State Verifiability layer continuously
  validates the boundary.
- **Article 32 — Security of processing:** Per-action signing,
  delegation chains, and revocation provide layered controls.
- **Article 33 — Notification of data breach:** The Heartbeat
  Protocol's silent-failure detection (canary commit/reveal) provides
  faster detection of an agent under adversarial control.

**Where Vouch does NOT address:**
- Data subject rights (Articles 12–22): access, rectification, erasure,
  portability, objection, automated decision-making explanations.
  These are deployment-level concerns, not protocol-level.
- Lawful basis of processing (Article 6). Vouch records *who* processed
  data, not whether the processing had a lawful basis.
- Cross-border transfer mechanisms (Chapter V).
- Records of processing activities (Article 30) — Vouch credentials
  are evidence the deployment can include in its Article 30 records,
  but the record itself is the controller's responsibility.

**Minimum conformance level recommended: L2.** Production GDPR contexts
require capability bounds (Sidecar) and revocation (BitstringStatusList).
L3 is appropriate for high-risk processing.

## Requirements mapping

| Article | Requirement (paraphrased) | Vouch mechanism | Spec section |
|---|---|---|---|
| 5(1)(f) | Integrity and confidentiality | Data Integrity proofs over JCS-canonicalised payloads | §5, §6 |
| 5(2) | Demonstrate accountability | Delegation chains; cryptographically verifiable audit | §9, §15.4 (Merkle roots) |
| 25(1) | Data protection by design | Identity Sidecar pattern; intent allow-list | §10 |
| 25(2) | Data protection by default | Default minimum credential validity (300s); narrowed delegation scope | §5.4, §9 (narrowing rule) |
| 32(1)(b) | Ongoing confidentiality and integrity | Per-action signing; Heartbeat renewal | §5, §15 |
| 32(1)(d) | Regular testing | Cross-language test vectors run in CI | §16 (informative); test-vectors/ |
| 33 | Notification of breach within 72h | Canary commit/reveal detects silent failure; BitstringStatusList enables rapid revocation | §15.4, §11 |
| 35 | Data protection impact assessment | Vouch credentials provide ex-post audit evidence supporting DPIA | (deployment work) |

## Deployment checklist

- [ ] Deploy at conformance Level 2 or higher (Sidecar + delegation + revocation)
- [ ] Configure the Sidecar allow-list to enumerate data-processing actions
- [ ] Set credential validity windows to the shortest reasonable for the action class
- [ ] Configure BitstringStatusList polling at ≤300s for any production deployment
- [ ] Document the delegation chain root principals in the data controller's records
- [ ] Map the protocol's `intent.action` vocabulary to the controller's Article 30 register

## Open questions / gaps

- **Data subject right to erasure (Article 17):** Vouch credentials embed
  the agent's DID and a content hash. They do not embed the data
  subject's personal data directly, but they reference it. If the data
  subject requests erasure, the deployment must (a) erase the underlying
  data and (b) decide whether to revoke or retain the historical
  credentials referencing it. Protocol guidance is needed.
- **Right to explanation (Article 22):** When an agent's action affects
  a data subject, Vouch records *that* the agent acted but not *why* (no
  reasoning chain). Deployments processing Article 22 data must supplement
  Vouch with a separate explanation log.
- **Cross-border transfers:** Vouch credentials travel with the action.
  If the action crosses an EU border, the credential's metadata travels
  too. Deployment must apply Chapter V transfer mechanisms.
