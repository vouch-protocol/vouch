# HIPAA (US Health Insurance Portability and Accountability Act) — Vouch Protocol™ mapping

**Status:** Skeleton. The mappings below are draft and require legal
review for any production compliance claim. HIPAA enforcement is
context-specific; mappings here are illustrative.

## Summary

**Where Vouch helps:**
- **Security Rule (45 CFR §164.308–318):** Access control, audit
  controls, integrity controls, and transmission security are all
  directly supported by cryptographic per-action signing + Sidecar
  capability bounds + delegation chain audit.
- **Audit trail (§164.312(b)):** Vouch Credentials produce an
  immutable, tamper-evident audit trail per action. The
  Heartbeat Protocol's action Merkle root summarises interval history
  cryptographically.
- **Minimum-necessary rule (§164.502(b)):** Delegation chains with the
  resource-narrowing rule ensure that sub-agents cannot exceed the
  minimum-necessary scope handed down by their parent.

**Where Vouch does NOT address:**
- The Privacy Rule's substantive provisions: permitted uses and
  disclosures, patient rights, business associate agreements. Vouch
  is a layer beneath the policy decisions, not a substitute for them.
- Breach notification (45 CFR §164.400–414). Vouch's silent-failure
  detection (canary chain) provides earlier signals, but the
  notification process itself is a deployment-level workflow.
- The PHI itself: Vouch credentials contain identity and intent, not
  the protected health information that the agent is operating on.
- HITRUST CSF or similar control-framework assessments.

**Minimum conformance level recommended: L3** for any deployment where
an agent autonomously accesses PHI without per-action human review. L2
may be sufficient for human-in-the-loop deployments.

## Requirements mapping (selected, not exhaustive)

| Citation | Requirement (paraphrased) | Vouch mechanism | Spec section |
|---|---|---|---|
| §164.308(a)(1)(ii)(A) | Risk analysis | Credential audit trail supports analysis of who/what/when | §5, §15.4 |
| §164.308(a)(3) | Workforce security; sanctions for unauthorised access | Trusted-principal anchoring + delegation chain identifies actor; revocation enforces sanction | §9, §11 |
| §164.308(a)(4)(ii)(C) | Access establishment and modification | Sidecar allow-list + delegation scope manage access at agent-action granularity | §10, §9 |
| §164.312(a)(1) | Unique user identification | DID + verification method per agent and principal | §7 |
| §164.312(b) | Audit controls | Per-action signed credentials with cryptographic integrity | §5 |
| §164.312(c)(1) | Integrity controls | Data Integrity proof over JCS-canonicalised payloads | §6 |
| §164.312(e)(1) | Transmission security | Credentials in transit are tamper-evident by design; deployments add TLS as usual | §5 (transport-independent), deployment |

## Deployment checklist

- [ ] Deploy at conformance Level 3
- [ ] Map agent action vocabulary to PHI categories (read PHI, write PHI, transmit PHI, etc.)
- [ ] Configure delegation chains with the principal (covered entity) at root, agent and sub-agents as leaves
- [ ] Enforce minimum-necessary at the Sidecar allow-list (deny default; explicit allow per action class)
- [ ] Retain credentials for the audit period mandated by §164.316(b) (six years)
- [ ] Pair Vouch with the deployment's existing PHI encryption-at-rest (Vouch does not encrypt PHI itself)
- [ ] Document the Business Associate Agreement coverage of the Vouch deployment, if any

## Open questions / gaps

- **PHI in credentials:** Vouch credentials normally do not contain
  PHI. If a deployment includes PHI in the `intent.target` or
  `intent.resource` field (e.g., a patient identifier in a URI), the
  credentials themselves become PHI and must be handled under the
  Security Rule. Recommend opaque identifiers in intent fields.
- **De-identification (Safe Harbor / Expert Determination):** Vouch
  audit trails should reference patient records by opaque identifiers,
  not directly by 18 Safe Harbor identifiers.
- **Patient rights to access (§164.524):** Vouch credentials are
  records *about the agent's actions*, not records *about the patient*.
  The deployment must decide whether these are within scope of patient
  access rights.
- **Right to amendment (§164.526):** Vouch credentials are
  cryptographically immutable. A patient request to amend a record
  cannot alter the historical credential; the deployment must record
  the amendment as a separate, linked action.
