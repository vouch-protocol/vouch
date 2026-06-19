# EU AI Act (Regulation 2024/1689) — Vouch Protocol™ mapping

**Status:** Skeleton. The mappings below are draft and require legal
review for any production compliance claim.

## Summary

**Where Vouch helps:**
- **Article 12 — Record-keeping (high-risk AI systems):** Vouch
  credentials are an automatically generated, tamper-evident record of
  every action a high-risk AI system takes.
- **Article 13 — Transparency and provision of information to deployers:**
  The credential's `intent` field documents what the agent is being
  asked to do; the delegation chain documents who authorised it.
- **Article 14 — Human oversight:** Trusted-principal anchoring places
  a human (or human-controlled key) at the root of every chain.
- **Article 15 — Accuracy, robustness, cybersecurity:** Per-action
  signing + Sidecar capability bounds + Heartbeat continuous attestation
  collectively contribute to the cybersecurity requirement.
- **Article 50 — Transparency obligations for certain AI systems:**
  Vouch credentials provide a verifiable claim of "this action was taken
  by an AI agent" rather than a human.

**Where Vouch does NOT address:**
- Risk classification (Annex III). Whether an AI system is high-risk
  is determined by its use case, not by the identity protocol.
- Bias mitigation, fairness assessment, training data quality.
- Conformity assessment procedures (Article 43).
- Post-market monitoring (Article 72) — Vouch provides per-action
  records that *feed* post-market monitoring but is not itself a
  monitoring framework.

**Minimum conformance level recommended: L3** for high-risk AI systems
under Article 6(2). L2 may be sufficient for limited-risk systems.

## Requirements mapping

| Article | Requirement (paraphrased) | Vouch mechanism | Spec section |
|---|---|---|---|
| 12(1) | Automatically generate logs of events ("logs") | Per-action Vouch Credentials | §5 |
| 12(2)(b) | Logs identify situations resulting in high risk or substantial modification | Behavioural attestation + canary chain signals drift | §15.3, §15.4 |
| 13(1) | High-risk AI systems designed and developed so deployers can interpret output | Credential's `intent` field describes the action in deployer-readable terms | §5.4 |
| 14(1) | Designed to be effectively overseen by natural persons | Trusted-principal anchoring; revocation invalidates compromised agents | §9 (root anchoring), §11 |
| 15(1) | Appropriate level of accuracy, robustness, cybersecurity | Cryptographic per-action attestation; Identity Sidecar capability bound | §6, §10 |
| 15(5) | Resilience against unauthorised third-party attempts | Sidecar + allow-list + delegation narrowing + heartbeat | §10, §9, §15 |
| 50(1) | Persons exposed to AI must be informed | Credential's issuer DID + intent provide machine-verifiable AI attribution | §5, §7 |

## Deployment checklist

- [ ] Deploy at conformance Level 3 if the AI system is high-risk (Annex III)
- [ ] Configure validator quorum across at least three role-specialised validators
- [ ] Set heartbeat interval to ≤ 60 seconds for high-risk deployments
- [ ] Enable the dual-proof post-quantum profile (the AI Act's "cybersecurity" requirement implies long-term integrity guarantees)
- [ ] Retain credentials for the duration mandated by Article 12 of the AI Act, in the deployment's chosen storage
- [ ] Map the protocol's `intent.action` vocabulary to the deployment's risk-class catalogue

## Open questions / gaps

- **Conformity assessment:** Vouch is an open protocol; a deployment's
  AI system using Vouch must still undergo Article 43 conformity
  assessment for its use case. The protocol itself does not undergo
  AI Act conformity assessment.
- **Annex III classification:** Whether deploying Vouch + an agent
  raises or lowers the system's risk classification is a use-case
  question, not a protocol question.
- **AI literacy (Article 4):** Deployers must ensure staff are
  AI-literate. Vouch produces machine-readable artefacts; the human-
  readable interpretation is the deployment's responsibility.
