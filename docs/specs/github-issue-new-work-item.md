# Vouch Protocol: Continuous State Verifiability for Autonomous AI Agents

> **Paste-ready body for the W3C CCG New Work Item submission.** File this Issue at
> <https://github.com/w3c-ccg/community/issues/new>, with the title:
>
> `[New Work Item] Vouch Protocol: Continuous State Verifiability for Autonomous AI Agents`
>
> Before posting, replace the **[paste Google Drive shareable link after upload]**
> placeholder.

---

## Include Link to Abstract or Draft

- **Community Group Report draft (canonical, markdown):** <https://github.com/vouch-protocol/vouch/blob/main/docs/specs/w3c-cg-report.md>
- **One-page executive summary:** <https://github.com/vouch-protocol/vouch/blob/main/docs/specs/cg-report-executive-summary.md>
- **DOCX for offline review (Google Drive):** *[paste Google Drive shareable link after upload]*
- **Reference implementations:** Python (`vouch-protocol` on PyPI), TypeScript (`@vouch-protocol/core` on npm), Go (`go-sidecar`). All in <https://github.com/vouch-protocol/vouch>.
- **Cross-language test vectors:** <https://github.com/vouch-protocol/vouch/tree/main/test-vectors>
- **Companion website (non-technical overview and hosted assistant):** <https://vouch-protocol.com>

## List Owners

**Lead:** Ramprasad Gaddam, ram@vouch-protocol.com, GitHub `@rampyg`. Responsible for advancing the work item, editorial responsibility for the Report, and coordinating contributors.

**Co-owner and co-sponsor:** Manu Sporny (Digital Bazaar), msporny@digitalbazaar.com, GitHub `@msporny`.

## Work Item Questions

### 1. Explain what you are trying to do using no jargon or acronyms.

AI agents are starting to take real actions on people's behalf: file an insurance claim, send an email, transfer money, schedule a meeting. When an agent acts, the service on the receiving end (and the people who will be accountable for the outcome later) need to be able to answer four questions:

- Was it really this agent?
- Did the right person give it permission?
- Was the permission for this specific action, against this specific record?
- Is the agent still healthy and within bounds right now, not just when it was first set up?

There is no standard way to answer those four questions today.

This work proposes a small set of building blocks. Each agent has an identifier that the agent's owner controls. The agent attaches a tamper-evident ticket to every action it takes, saying what it is doing and for whom. The receiving service checks the ticket without needing to trust the agent. A long-running agent keeps proving "I am still authorized and behaving" through a regular renewal cycle, rather than the world assuming it is still good. All the pieces are built from existing internet standards. The new contribution is the set of rules that compose those pieces for the AI-agent case.

### 2. How is it done today, and what are the limits of the current practice?

AI agents today are authorized through a mix of long-lived API keys, OAuth bearer tokens, mTLS client certificates, and (increasingly) short-lived JWTs. Mature operators handle this well: AWS KMS, Azure Key Vault, GCP KMS, and enterprise KMS systems rotate keys on 30 / 60 / 90-day cadences; OAuth scopes bind tokens to permission classes; OAuth token exchange (RFC 8693) records delegation server-side; mTLS pins a client identity to a certificate. These are real, working primitives. The limits are specific to the AI-agent use case rather than to those primitives in general:

- **Authorization is granted at the session or key level, not at the action level.** An OAuth token with the `email.read` scope can read any message the user owns. The receiving service cannot tell, from the token alone, whether the agent meant to read this specific thread for that specific purpose. The per-action intent (which action, which target, which resource URI) is not part of the wire format. Audit teams who need "the agent did X, against record Y, authorized for purpose Z" typically reconstruct that link from out-of-band logs.

- **Key rotation depends on operator policy, not on the credential.** Industry best practice (KMS-managed auto-rotation, 90-day TLS certificate lifetimes, enterprise rotation policies) is real and effective. The rotation cadence is, however, invisible to the receiving service: a verifier seeing a token cannot tell "this is fresh" from "this has been valid for 89 days." A leaked key remains live for the rotation interval (typically days to months) once leaked, unless the leak is detected and the operator triggers an early rotation. Smaller deployments, dev environments, and many third-party SaaS integrations lack rotation discipline entirely.

- **Bearer tokens leak through new surfaces in the AI-agent setting.** Logs, copy-paste, and accidental commits are the well-known cases. The new case is prompt-injected language models: an attacker who can inject text into an agent's context can sometimes convince the model to print its own secrets, regardless of how careful the operator was at the platform layer. Standard bearer-token models do not address this surface.

- **Delegation does not produce a cryptographic chain that a third party can verify.** OAuth on-behalf-of and token exchange record delegation in the issuer's database. Revoking or auditing the chain requires contacting the issuer. There is no in-band, self-contained proof that a verifier can validate without round-tripping to the auth server, which makes cross-organization delegation hard.

- **No continuous-trust signal tied to the credential.** Platform-level heartbeats (Kubernetes liveness, load-balancer health checks) tell a verifier that the *process* is alive. They do not tell the verifier that the *agent's authorization to keep acting* is still warranted: that its behavior is still within bounds, that its model has not been silently substituted, that it is still inside its trust budget. A long-running AI agent is, in current practice, treated as trusted from the moment its key is issued until the key is rotated or the session is explicitly terminated.

Adjacent W3C work (Verifiable Credentials 2.0, Data Integrity, DIDs) provides the right building blocks for closing these gaps, but no published specification has arranged them for the autonomous-agent case. Vendor-specific solutions exist (Anthropic, OpenAI, and Google each have proprietary tool-call signing schemes) but they do not interoperate.

### 3. What is new in your approach and why do you think it will be successful?

The novel contributions are:

1. **Identity-Sidecar pattern (Report Section 10).** The agent's signing key lives in a separate process that the language model cannot read from. The model proposes an action; the sidecar evaluates the action against a pre-declared allow-list; the sidecar signs only if the action is on the list. Even a fully prompt-injected language model cannot leak the key (it does not hold it) or sign for an action outside the allow-list (the sidecar refuses, structurally).

2. **Continuous State Verifiability via the Heartbeat Protocol (Report Section 11).** A long-running agent renews its short-lived authorization on a regular interval (default 60 seconds), submitting behavioral attestation evidence with each renewal. Trust decays automatically if the heartbeat lapses. This inverts the standard PKI model from "trusted until revoked" to "untrusted until renewed."

3. **Dual-Proof Post-Quantum Profile (Report Section 13).** A credential can carry two independent Data Integrity proofs on the same canonical bytes: one classical Ed25519, one post-quantum ML-DSA-44. Verifiers choose which proofs they require. A deployment can migrate from classical-only signatures to post-quantum signatures by adding a second proof on the same credential, with no wire-format change for the receiver.

Why this work is positioned to succeed:

- It **composes with existing W3C work** rather than displacing it. Verifiable Credentials 2.0, Data Integrity, DIDs, Multikey, and BitstringStatusList already exist and are well-supported. This work arranges them for the AI-agent case.
- It **ships working reference code** in Python, TypeScript, and Go before submission, with cross-language interoperability test vectors. Implementers can adopt from day one.
- It **addresses a problem the industry is encountering now**: agent identity, agent accountability, and an audit trail for AI-driven actions. Regulators in the EU (AI Act), the US (NSM-10, NIST 800-63), and across regulated industries (HIPAA, GDPR, financial-services audit) are asking related questions that this work helps answer.
- It **treats post-quantum migration as a Day-1 design constraint** rather than a retrofit. The dual-proof profile lets a deployment migrate without a wire-format change for the receiver.

### 4. How are you involving participants from multiple skill sets and global locations?

**By skill set.**

- *Technical:* three reference implementations in Python, TypeScript, and Go produce byte-identical credentials for the same input; a STRIDE-shaped security model and a LINDDUN-shaped privacy model are both authored into the Report; cross-language test vectors are published.
- *Product:* three conformance levels (L1 credential, L2 sidecar + delegation + revocation, L3 state-verifiable + post-quantum) allow incremental adoption. A six-step onboarding guide walks first-time implementers from local Python REPL through hosted production.
- *Design and UX:* a public website with an in-browser AI assistant, a VS Code extension for in-editor snippets, and packaged knowledge bundles for Claude, OpenAI, and Gemini lower the cost of asking questions in any AI tool a developer already uses.
- *Governance and compliance:* explicit mappings of each Vouch primitive to GDPR articles, HIPAA Privacy Rule requirements, EU AI Act provisions, and NIST 800-63 controls.
- *Marketing:* not yet covered. An honest gap that CCG incubation is well-placed to attract.

**By geography.** The editor is based in India (APAC) and contributes regulated-healthcare and financial-services perspective from professional work. The co-sponsor is based in the Americas (Digital Bazaar). Reference contributors and test-vector validators are welcome from anywhere. Calls and reviews can be scheduled APAC-, Europe-, or Americas-friendly.

This submission is itself an act of participation-widening: filing the work item is how the editor invites the CCG community to contribute, comment, and co-own. The editor commits to responding to every line-level comment received in the early weeks on the public-credentials list.

### 5. What actions are you taking to make this work item accessible to a non-technical audience?

- A **one-page executive summary** in plain language (`docs/specs/cg-report-executive-summary.md`) for an executive, regulator, or non-technical stakeholder.
- A **public website** at <https://vouch-protocol.com> that explains the protocol through concrete examples (a healthcare-claims agent, an automated trading agent) rather than through specification text.
- A **hosted AI assistant** at <https://vouch-protocol.com/ask> that answers Vouch-related questions in natural language and cites which document each answer came from. A non-technical reader can ask "what does this mean for me as a compliance officer?" and get a grounded answer without reading the specification.
- **Compliance mapping documents** (`docs/compliance/gdpr.md`, `hipaa.md`, `eu-ai-act.md`, `nist-800-63.md`) written for compliance professionals, mapping each Vouch primitive to the regulatory requirement it satisfies.
- A **"principal audit interface" requirement** in Section 14.6 of the Report: any human whose authority is being exercised by an agent should be able to see what has been signed on their behalf through a non-technical UI, without reading specification text.
- A **blog** at <https://vouch-protocol.com/blog> with longer-form articles on the protocol's motivation, deployment scenarios, and operational considerations, written for the audience that does not implement protocols but lives with their consequences.
