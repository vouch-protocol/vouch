/**
 * Vouch Protocol FAQ content
 *
 * Single-page FAQ organized by audience. Each section has audience tag,
 * title, and an array of Q&A entries. Answers may include inline links
 * [text](url) which the renderer parses.
 *
 * Goal: document what is *actually shipped* in the repo so the editor
 * (or any reader) can use this to recollect / onboard after time away.
 *
 * Every claim here is cross-checked against:
 *  vouch-protocol/CHANGELOG.md (current: v1.6.0)
 *  vouch-protocol/vouch/ (Python SDK)
 *  vouch-protocol/packages/sdk-ts/ (TypeScript SDK)
 *  vouch-protocol/go-sidecar/ (Go sidecar)
 *  vouch-protocol/vouch-shield (sibling repo)
 *  vouch-protocol/docs/specs/ (local-only spec drafts)
 */

export interface FAQItem {
  q: string;
  a: string;
  /** Optional cross-link to a Help/Guides anchor for deeper reading. */
  helpLinks?: { label: string; href: string }[];
  /** Optional metadata footnote: spec section, PAD reference, shipped-in version. */
  meta?: string;
}

export interface FAQSection {
  /** Section slug (URL anchor) */
  id: string;
  /** Mono uppercase audience tag, e.g., "For Developers" */
  audience: string;
  /** Serif section title, e.g., "Getting Vouch into your codebase" */
  title: string;
  /** Top-level agent domain for the page toggle. Defaults to 'agents' (software agents). */
  domain?: 'agents' | 'robotics';
  items: FAQItem[];
}

export const FAQ_SECTIONS: FAQSection[] = [
  // =====================================================================
  // ABOUT VOUCH
  // =====================================================================
  {
    id: 'about',
    audience: 'About Vouch',
    title: 'What the protocol is and why it exists',
    items: [
      {
        q: 'What is Vouch Protocol?',
        a: `Vouch is a digital signature layer for AI agents. When your agent does something on your behalf (sends an email, transfers money, files a claim, queries a database), Vouch lets it cryptographically sign that action so anyone, anywhere, can later prove who did what and with whose permission.

Think of it as a tamper-proof receipt for every move an autonomous AI makes. The receipt is human-readable, cryptographically signed, and works across whatever framework you use to build agents (LangChain, CrewAI, MCP, anything).`,
        helpLinks: [{ label: 'See it: an agent that must state why', href: '/demos/#reasoned-action' }],
      },
      {
        q: 'What problem does it solve?',
        a: `AI agents are doing real work now: they submit insurance claims, place trades, file regulatory reports, access patient records. When something goes wrong (and eventually something will), you need to know exactly which agent took which action, who authorized it, and whether the agent had permission.

The tools we built for humans (API keys, login sessions, OAuth tokens) were not designed for this. They prove someone has access. They don't prove what the agent intended to do, who delegated the action down to it, or whether the agent is still behaving correctly.

Vouch fixes this by turning every agent action into a signed receipt. Identity, intent, target, and the chain of permissions are all cryptographically bound together. If your CFO asks "did our agent really wire that money?", you can prove it in seconds, with math, not log files.`,
        helpLinks: [{ label: 'See it: veto an irreversible action before it runs', href: '/demos/#deliberation' }],
      },
      {
        q: 'How is this different from OAuth, API keys, or JWTs?',
        a: `Three big differences:

**1. The agent owns its identity.** With API keys, someone hands the agent a string. With Vouch, the agent generates its own cryptographic identity. Nobody, including the issuer, can impersonate it or take it away from afar.

**2. Every action carries its intent.** An API key just says "I'm allowed in." A Vouch credential says "I am Agent A, I want to submit *this specific claim* to *this specific URL*, at *this specific time*, and here is the chain of humans who approved it." Replaying the credential against any other resource literally cannot work.

**3. Trust expires fast and renews continuously.** A bearer token is good until someone remembers to revoke it. Vouch flips this: agents are untrusted by default and must renew their credentials on a heartbeat. If an agent goes silent (crashed, compromised, network split), its permissions expire on their own. No manual cleanup.`,
      },
      {
        q: 'Can I use Vouch in production today?',
        a: `**Yes, for what most teams need.** Signing your agent's actions, verifying them anywhere, building permission chains between multiple agents, revoking compromised credentials, and being post-quantum ready: all shipped, all tested across Python, TypeScript, and Go, all have published test vectors. Build on it today.

**The "continuous trust scoring" layer now ships in the Python SDK.** That's the part where the credential's trust value decays over time, multiple validators can agree on whether your agent is behaving correctly while it's running, and a missed heartbeat is cryptographically detectable. The six new modules (trust entropy decay, behavioral attestation digest, canary commit/reveal chain, Merkle trees, heartbeat orchestration, validator quorum) animate the SessionVoucher format end-to-end. TypeScript and Go ports of these runtime pieces are not yet shipped; the data formats are already cross-language.

**Vouch Shield**, our optional runtime middleware that checks every tool call against your permission rules, is also production-ready (TypeScript library).`,
      },
      {
        q: 'Who is behind Vouch?',
        a: `Vouch is a personal open-source project from [Ramprasad Gaddam](https://github.com/vouch-protocol), an AI engineering director with 20+ years in regulated industries (healthcare and manufacturing), 20 patents in cryptography and AI, and active membership in The Linux Foundation, C2PA, the Content Authenticity Initiative, DIF, and IEEE.

It is not affiliated with or endorsed by any employer.`,
      },
      {
        q: 'Where does the name come from?',
        a: `To vouch for someone is to publicly stand behind them and take responsibility if they let you down. A Vouch credential does the same thing in code: an agent stands behind its own action, and the chain of people who delegated to it stands behind the agent.`,
      },
      {
        q: 'Is Vouch free? What is the license?',
        a: `Yes, fully free and open-source. **Apache 2.0** for all code and the specification. **CC0** (public domain) for the 55 design disclosures we've published. Use it in commercial products, fork it, sell things built on top of it. We just ask that you don't try to patent the ideas back at us.`,
      },
      {
        q: 'Where can I read the formal specification?',
        a: `Most people never need to. The FAQ and [Guides](/help/) cover everything you'll use day to day. But if you want the formal version, an executive summary is available [here](https://github.com/vouch-protocol/vouch/blob/main/docs/specs/cg-report-executive-summary.md).`,
      },
    ],
  },

  // =====================================================================
  // CORE CONCEPTS
  // =====================================================================
  {
    id: 'concepts',
    audience: 'How It Works',
    title: 'The pieces, explained simply',
    items: [
      {
        q: 'What is a DID, in plain English?',
        a: `A DID (Decentralized Identifier) is a username your agent gives itself, backed by a cryptographic key only your agent holds. No registrar, no central authority can take it away.

Think of it like a passport you issue to yourself, where the passport's authenticity is proven by math, not by a government stamp. Vouch uses two flavours:

- **did:web** looks like \`did:web:agent.example.com\` and points to a small JSON file on your domain. Use this when you own a domain.
- **did:key** looks like \`did:key:z6Mk...\` and the public key is baked into the identifier itself. Use this for quick experiments or self-contained agents that don't need a website.`,
      },
      {
        q: 'What is a Verifiable Credential?',
        a: `A Verifiable Credential is a small piece of signed JSON that says "the holder of this DID claims X." For Vouch, X is something like "I, Agent A, am about to submit claim HC-001 to the insurance system at this URL."

The credential is signed by whoever issues it (the agent itself, a human delegator, or a validator). Anyone with the issuer's public key can verify the signature later. Tamper with even one character and the signature breaks.

A Vouch credential is just a Verifiable Credential with an \`intent\` field that pins down what the agent is doing and to what.`,
      },
      {
        q: 'What is a Data Integrity proof?',
        a: `It is the cryptographic signature glued to the side of a Verifiable Credential. Vouch uses the Data Integrity mechanism, which keeps the credential as plain readable JSON and attaches the proof as a separate object next to it. You can open a Vouch credential in any text editor and read it.

By default Vouch uses Ed25519 (fast, well-known elliptic-curve signatures). If you need post-quantum protection, switch to the hybrid cryptosuite that signs with both Ed25519 *and* ML-DSA-44 (a NIST-approved post-quantum algorithm).`,
      },
      {
        q: 'Why do you talk about "JCS canonicalization"?',
        a: `It is a fancy name for "write this JSON the exact same way every time." JCS (RFC 8785) gives every implementation the same recipe: sort keys alphabetically, format numbers the same way, no random whitespace. Same JSON in, same bytes out.

This matters because signatures are over bytes, not over abstract JSON. If your Python signs the credential but the bytes look different when TypeScript serializes the same data, the signature breaks. JCS makes that impossible. It is the reason a Vouch credential signed in Python can be verified in TypeScript or Go without any conversion.`,
      },
      {
        q: 'What is the Identity Sidecar pattern, and why should I care?',
        a: `It is a deployment trick that keeps your agent's private signing key away from the language model.

Here is the problem: your LLM-driven agent has tools, and a prompt-injection attack could trick it into leaking anything in its context window. If the private key is in that context, the attacker now controls your agent's identity.

The fix: run a small separate process (the "sidecar") that owns the key. When the agent wants to sign something, it asks the sidecar over a local connection. The sidecar signs, returns the credential, and never exposes the key to the LLM. Vouch ships a small Go binary you can run as the sidecar.`,
      },
      {
        q: 'What is the Heartbeat Protocol?',
        a: `It is a dead-man's-switch for long-running agents. Every few minutes (you pick the interval) the agent has to actively renew its credentials. If it crashes, gets disconnected, or is taken over, the renewals stop and its permissions expire on their own. No human has to remember to revoke anything.

The credential format for these renewals ships today (it is called SessionVoucher). The runtime that actually drives the heartbeats and coordinates with multiple validators is on the roadmap, not built yet.`,
      },
      {
        q: 'What is a delegation chain?',
        a: `A chain of permission slips that tracks "who let whom do what." Imagine you tell your assistant "please book my flight." Your assistant tells an AI travel agent "please find flights." The travel agent tells a payment agent "please charge this card." Three steps, three permission grants.

A Vouch delegation chain captures all three steps cryptographically. Each step narrows the permission (the travel agent can find flights but not, say, sell your house). At the end, anyone looking at the action can walk the chain backward to the human who started it. "The AI did it" becomes "Person X delegated to assistant Y who delegated to agent Z, and here is each signed step." Real accountability.

Beyond narrowing static fields, a link can carry executable caveats: live conditions ("only for shipped orders", "under the customer's lifetime spend", "business hours only") that accumulate down the chain and that no downstream holder can drop. Try it in the interactive demo, where a rule the CEO sets still blocks an agent two hops away.`,
        helpLinks: [{ label: 'See it: the delegation-envelope demo', href: '/demos/#caveats' }],
      },
      {
        q: 'Can Vouch prove an agent has a track record it cannot fake?',
        a: `Yes, this ships as outcome evidence (the \`vouch.accountability\` module). It separates two questions that often get blurred: "is this really agent X?" and "does X have a record of being right?" Identity answers the first. Outcome evidence answers the second.

It works in two steps. First the agent commits a verdict, prediction, or recommendation and signs it before the result is known. The commitment can carry only a salted fingerprint of the call, so the content stays private until later while still being locked in. Then, once the outcome is observable, a settlement record (which can be signed by a neutral third party) reveals the original call and binds the real result to it. Anyone can recompute the fingerprint and check it matches, and a settlement dated before its commitment is rejected. So a winning call cannot be invented after the fact, and a losing one cannot quietly disappear.

This is the evidence layer underneath reputation. Vouch reputation is itself evidence-backed: a score recomputed from signed receipts, not a number a server keeps.`,
        helpLinks: [{ label: 'Outcome evidence how-to', href: '/help/#outcome-evidence' }],
        meta: 'Shipped on main - vouch.accountability, PAD-071',
      },
      {
        q: 'How does Vouch reputation avoid being gamed?',
        a: `Reputation is computed from signed receipts, each tied to a real interaction, by a public function anyone can rerun. The relying party the agent acted on signs the result of an action, a settled prediction signs whether it came true, and an authority signs a penalty. The score is the weighted, time-decayed aggregate of those across dimensions like reliability, performance, and compliance.

A consumer does not trust a server's number: it fetches the receipts and recomputes the score itself. Anonymous star ratings carry almost no weight, and a human review only counts when it is bound to proof the rater actually used the agent. An agent can prove it clears a bar, say a composite of at least 75, without revealing its score, and a receipt issued in error can be disputed and dropped by an arbiter.`,
        helpLinks: [{ label: 'Evidence-backed reputation', href: '/help/#reputation-evidence' }],
        meta: 'Shipped on main - vouch.receipts, vouch.reputation_aggregate, vouch.reputation_ledger',
      },
    ],
  },

  // =====================================================================
  // ACCOUNTABLE AUTONOMY
  // =====================================================================
  {
    id: 'accountable-autonomy',
    audience: 'Accountable autonomy',
    title: 'Bounding and recording what an authorized agent does',
    items: [
      {
        q: 'Identity proves who acted. What stops an authorized agent from doing something harmful?',
        a: `A misaligned agent can take an action that is inside its authority and still catastrophic. Vouch does not read the agent's mind. It does what institutions have always done with authorized actors: five Python SDK modules make each action state its reason (\`vouch.reasoning\`), slow down the irreversible ones behind a veto (\`vouch.deliberation\`), stay inside an authority that cannot be broadened (\`vouch.caveats\`), come from a decision that is reproducible (\`vouch.provenance\`), and land in a public append-only log (\`vouch.transparency\`). Together they make harm hard to hide even for a misaligned agent.`,
        helpLinks: [{ label: 'See all four in the browser', href: '/demos/' }],
        meta: 'Shipped - vouch.reasoning, deliberation, caveats, provenance, transparency',
      },
      {
        q: 'How does an agent prove why it acted, without being able to fake the reason?',
        a: `\`vouch.reasoning\` (Reasoned Action Proofs) has the agent state its justification before acting, tie each reason to a real artifact by that artifact's hash, and escrow the justification before execution. An auditor can then prove the reasoning was not fabricated (each anchor must resolve and hash-match a real message or delegation), not rewritten after the fact (it must recompute to the committed digest), and committed before the action. It does not make deception impossible; it puts the agent on the record, so a false justification is provable.`,
        helpLinks: [{ label: 'See it: reasoned action', href: '/demos/#reasoned-action' }],
      },
      {
        q: 'Can I make an agent wait, or let a human veto, before it does something irreversible?',
        a: `Yes, with \`vouch.deliberation\`. A reversible action runs instantly. An irreversible one (wiring funds, deleting without backup, publishing) must commit and broadcast a signed intent with a challenge window and a set of authorized objectors, wait out the window, and survive any veto before a verifier accepts it. The agent cannot shorten the window (the verifier checks the elapse) and cannot clear its own veto (the veto authority is a separate DID). This gives regulatory human-oversight requirements a machine-checkable hook.`,
        helpLinks: [{ label: 'See it: the deliberation window', href: '/demos/#deliberation' }],
      },
      {
        q: 'Can a permission carry a live condition that a sub-agent two hops down cannot drop?',
        a: `Yes, with executable caveats (\`vouch.caveats\`). Beyond narrowing static fields, a delegation link can carry conditions ("only for shipped orders", "under the customer's lifetime spend", "business hours only"). Caveats accumulate down the chain, so a rule the grantor sets binds every descendant, and no holder in between can drop it because the verifier requires the presented chain to root at the grantor. Every verifier must evaluate every accumulated caveat, offline, with no policy server.`,
        helpLinks: [{ label: 'See it: the delegation envelope', href: '/demos/#caveats' }],
      },
      {
        q: 'Can I prove an agent output came from a specific model and context, not a hallucination?',
        a: `\`vouch.provenance\` binds an output to a fingerprint of the model weights and a Merkle root over the context it was grounded in, plus the sampler settings. An auditor can re-fetch the sources to reproduce the context root (catching a fabricated or substituted context) and re-run the model on the same seed to byte-compare the output. It does not read the model's mind; it makes the provenance of a decision reproducible and its inputs non-repudiable, and it is the anchor point for zero-knowledge proofs of inference later.`,
        helpLinks: [{ label: 'See it: the provenance', href: '/demos/#provenance' }],
      },
      {
        q: 'How do I make agent actions publicly auditable so none can be hidden or rewritten?',
        a: `\`vouch.transparency\` submits consequential actions to an append-only RFC 6962 Merkle log that signs its size and root as a Signed Tree Head. A verifier can demand an inclusion proof that a specific action is in the log, and a monitor can demand a consistency proof that an older tree head is a strict prefix of a newer one. So the log cannot silently omit an action or rewrite history, and comparing tree heads across observers catches a split view. It is the same discipline Certificate Transparency brought to misissuance.`,
        helpLinks: [{ label: 'See it: the transparency log', href: '/demos/#transparency' }],
      },
    ],
  },

  // =====================================================================
  // CONFORMANCE
  // =====================================================================
  {
    id: 'conformance',
    audience: 'Conformance',
    title: 'Proving an implementation is conformant',
    items: [
      {
        q: 'What does Vouch conformance mean?',
        a: `Conformance proves that an implementation, an SDK, a fork, or a port, produces byte-correct protocol output and supports the required feature sets. It is graded in three cumulative levels. L1 Credential: canonicalization, eddsa-jcs-2022 sign and verify, the validity window, and nonce replay resistance. L2 Structural-Security: everything in L1 plus BitstringStatusList revocation, delegation narrowing with the five-link depth bound, the Identity Sidecar allow and deny behaviour, and a hash-linked audit trail. L3 State Verifiable plus Post-Quantum: everything in L2 plus the hybrid dual-proof, the Heartbeat renewal chain, and an M-of-N validator quorum. This is separate from robotics regulatory conformance, which grades a robot against a regulation.`,
        meta: 'Spec section 17',
      },
      {
        q: 'How do I test my implementation?',
        a: `Run the reference runner. It checks your implementation against the levels and reports the highest it fully satisfies: \`python -m vouch.conformance\`. It runs the checks in-process against the SDK and prints a per-check pass or fail with the highest passing level.`,
      },
      {
        q: 'Is there a verified badge?',
        a: `The self-test proves conformance to yourself. A hosted verifier is coming that turns it into a Vouch-verified, re-checkable result: it issues fresh random challenges, re-checks every response server-side with the canonical core, and mints a signed credential unique to your implementation. Because it recomputes every expected answer, a pass cannot be faked by replaying the public test vectors. Until it is live, the conformance page carries a self-declaration and shows what a verified pass will earn.`,
      },
    ],
  },

  // =====================================================================
  // EMBODIED AGENTS (ROBOTICS)
  // =====================================================================
  {
    id: 'robotics',
    audience: 'Embodied agents (robotics)',
    title: 'Identity and accountability for robots',
    domain: 'robotics',
    items: [
      {
        q: 'Does Vouch work for robots and embodied agents?',
        a: `Yes, and it ships today. A robot is an agent with a body, so identity, accountability, and continuous trust matter even more once an agent can cause physical harm. Everything Vouch does for software agents applies, and the \`vouch.robotics\` module adds six capabilities for the parts that only exist when an agent is embodied. They are open formats plus reference implementations, built on the same \`eddsa-jcs-2022\` Verifiable Credentials as the rest of Vouch, so a robotics credential signed in one language verifies in every other.`,
        helpLinks: [{ label: 'Robotics quickstart', href: '/help/#robotics' }, { label: 'Robotics overview', href: '/robotics/' }],
        meta: 'Shipped - vouch.robotics (Python, TypeScript, Go, Rust core), PAD-064/067/069/070',
      },
      {
        q: 'What exactly can Vouch do for a robot?',
        a: `Six capabilities, each a signed credential anyone can verify: hardware-rooted identity, model and config provenance, physical capability scope, a robot-to-robot handshake, a black box with a kill switch, and a scannable passport. Each capability has its own questions in the sections below, and its own guide under Help.`,
        helpLinks: [{ label: 'Robotics capabilities', href: '/help/#robotics-capabilities' }],
        meta: 'Shipped - vouch.robotics, PAD-064/067/069/070',
      },
      {
        q: 'Which languages can I use the robotics capabilities from?',
        a: `All of them. The six capabilities are implemented once in the Rust core and exposed through the same UniFFI and WebAssembly wrappers as the rest of Vouch, plus byte-identical reference implementations in Python, TypeScript, and Go. So you can build and verify them from Python, TypeScript, Go, Swift, Kotlin/JVM, .NET, C/C++, or the browser, and a credential signed in one verifies in all the others.`,
        helpLinks: [{ label: 'Robotics quickstarts', href: '/help/#robotics' }],
        meta: 'Shipped - vouch.robotics across every SDK',
      },
      {
        q: 'How is a robot’s identity different from a software agent’s?',
        a: `It adds a hardware root. A software agent has a DID and a signing key; a robot has those plus a binding signed by a TPM or secure element, so its identity is tied to one physical device. Everything else (delegation chains, revocation, the continuous-trust heartbeat) applies to the robot unchanged.`,
      },
    ],
  },

  // =====================================================================
  // ROBOTICS: HARDWARE-ROOTED IDENTITY
  // =====================================================================
  {
    id: 'robotics-identity',
    audience: 'Robotics: hardware identity',
    title: 'Hardware-rooted identity',
    domain: 'robotics',
    items: [
      {
        q: 'How does hardware-rooted identity stop a robot from being cloned?',
        a: `A robot self-issues a \`RobotIdentityCredential\` with its own key, and its hardware root (a TPM or secure element) signs a binding over the robot's DID and key, embedded as \`hardwareRoot.attestation\`. Copy the software identity to a different machine and the hardware attestation no longer matches the binding, so verification fails. The identity is tied to one piece of silicon.`,
        helpLinks: [{ label: 'Hardware-rooted identity guide', href: '/help/#robotics-identity' }],
        meta: 'Shipped - vouch.robotics.identity, PAD-064',
      },
      {
        q: 'What does verifying a robot identity actually check?',
        a: `Two independent signatures. First the credential proof, that the robot's own key signed the document. Second the hardware attestation, that the hardware root signed the canonical binding of the robot DID and key. Verification fails closed on a wrong type, an invalid proof, a missing or non-Ed25519 hardware key, or an attestation that does not match the binding.`,
        helpLinks: [{ label: 'Hardware-rooted identity guide', href: '/help/#robotics-identity' }],
        meta: 'Shipped - vouch.robotics.identity, PAD-064',
      },
      {
        q: 'Do I need a real TPM to develop with robot identity?',
        a: `No. The reference SDKs include a \`SoftwareRootOfTrust\` that stands in for the TPM during development and tests, and a \`HardwareRootOfTrust\` interface a real TPM or secure-element backend implements for production. The credential format is identical either way; only where the attestation is signed changes.`,
        helpLinks: [{ label: 'Robotics quickstart', href: '/help/#robotics-quickstart-python' }],
        meta: 'Shipped - vouch.robotics.identity',
      },
    ],
  },

  // =====================================================================
  // ROBOTICS: MODEL AND CONFIG PROVENANCE
  // =====================================================================
  {
    id: 'robotics-provenance',
    audience: 'Robotics: provenance',
    title: 'Model and config provenance',
    domain: 'robotics',
    items: [
      {
        q: 'Can I prove what model and safety policy a robot ran, even after an OTA update?',
        a: `Yes, via a \`ModelProvenanceAttestation\` recording the model name, weights hash, safety policy, and config hash. On an over-the-air update the robot re-signs a new attestation with a \`supersedes\` link to the previous one, forming a tamper-evident chain you can walk to answer "what was running at any past time."`,
        helpLinks: [{ label: 'Provenance guide', href: '/help/#robotics-provenance' }, { label: 'See it: reproduce and replay a decision', href: '/demos/#provenance' }],
        meta: 'Shipped - vouch.robotics.provenance, PAD-065',
      },
      {
        q: 'What is the config hash, and why can any verifier reproduce it?',
        a: `The config hash is the multibase SHA-256 of the JCS-canonical config object. Because JCS canonicalization is byte-identical across languages, any verifier holding the expected config recomputes the same hash. Supply the config to the verifier and it checks the recorded hash reproduces, so a robot running a different config than the one attested is detectable.`,
        helpLinks: [{ label: 'Provenance guide', href: '/help/#robotics-provenance' }],
        meta: 'Shipped - vouch.robotics.provenance, PAD-065',
      },
      {
        q: 'How does the supersedes chain answer "what was running at time T"?',
        a: `Each attestation carries the id of the one it replaces. Following the \`supersedes\` links backward gives an ordered, signed history of every model and config the robot ran, each with its own validity window. To answer a question about a past moment, you find the attestation whose window covers it.`,
        meta: 'Shipped - vouch.robotics.provenance, PAD-065',
      },
    ],
  },

  // =====================================================================
  // ROBOTICS: PHYSICAL CAPABILITY SCOPE
  // =====================================================================
  {
    id: 'robotics-capability',
    audience: 'Robotics: physical scope',
    title: 'Physical capability scope',
    domain: 'robotics',
    items: [
      {
        q: 'How are a robot’s physical limits enforced?',
        a: `A \`PhysicalCapabilityScope\` credential carries the limits, max force, max speed, a tighter cap near humans, allowed zones, and shift windows. A controller calls \`check_physical_action\` with a proposed action before the actuator moves, and gets back whether it is allowed plus a reason for each violated dimension.`,
        helpLinks: [{ label: 'Capability scope guide', href: '/help/#robotics-capability' }],
        meta: 'Shipped - vouch.robotics.capability, PAD-066',
      },
      {
        q: 'What happens if an action exceeds the scope, or if a dimension is not set?',
        a: `An action that exceeds any granted dimension is rejected, with a reason naming the dimension (for example "near_humans speed_exceeded"). A dimension that is not present in the scope is unconstrained by design: if a scope sets no \`maxForceN\`, force is not bounded by that credential.`,
        helpLinks: [{ label: 'Capability scope guide', href: '/help/#robotics-capability' }],
        meta: 'Shipped - vouch.robotics.capability, PAD-066',
      },
      {
        q: 'Can a sub-task escalate the physical limits it was delegated?',
        a: `No. Delegation is narrow-only, enforced by \`attenuates(parent, child)\`. A child scope may shrink numeric caps, subset the allowed zones, and fit each window inside a parent window, but a child that raises a cap, drops a cap the parent set, adds a zone outside the parent set, or widens a window is rejected. This is the privilege-escalation guard.`,
        helpLinks: [{ label: 'Capability scope guide', href: '/help/#robotics-capability' }],
        meta: 'Shipped - vouch.robotics.capability, PAD-066',
      },
      {
        q: 'How does the slower speed near people work?',
        a: `The scope can carry both a general \`maxSpeedMps\` and a tighter \`maxSpeedNearHumansMps\`. When an action is flagged as near humans, the near-humans cap applies instead of the general one, so the same robot is allowed to move faster in a clear aisle than next to a person.`,
        meta: 'Shipped - vouch.robotics.capability, PAD-066',
      },
    ],
  },

  // =====================================================================
  // ROBOTICS: ROBOT-TO-ROBOT HANDSHAKE
  // =====================================================================
  {
    id: 'robotics-handshake',
    audience: 'Robotics: handshake',
    title: 'Robot-to-robot handshake',
    domain: 'robotics',
    items: [
      {
        q: 'How do two robots from different fleets cooperate safely?',
        a: `Through a three-message handshake (HELLO, ACCEPT, CONFIRM). The initiator proposes a scope and a fresh nonce; the responder verifies the HELLO signature, checks the initiator's \`did:web\` domain against its \`TrustPolicy\`, and replies with a session scope. No central broker is needed.`,
        helpLinks: [{ label: 'Handshake guide', href: '/help/#robotics-handshake' }],
        meta: 'Shipped - vouch.robotics.handshake, PAD-067',
      },
      {
        q: 'Why is the session scope the intersection and not the union of what each robot offers?',
        a: `Because cooperation should never grant more than both sides already allow. The bounded session scope is the intersection of the initiator's proposed scope and the responder's offered scope, so neither robot can widen the other's authority by asking. A robot that proposes more than its peer offers simply gets the overlap.`,
        helpLinks: [{ label: 'Handshake guide', href: '/help/#robotics-handshake' }],
        meta: 'Shipped - vouch.robotics.handshake, PAD-067',
      },
      {
        q: 'What stops a replayed or tampered handshake message?',
        a: `Each message is an \`eddsa-jcs-2022\` signed object, so altering any field breaks its signature. The initiator's nonce is echoed in the ACCEPT and checked, binding the acceptance to that specific HELLO, and the CONFIRM is checked against the agreed session id and nonce. A replayed or edited message fails verification.`,
        meta: 'Shipped - vouch.robotics.handshake, PAD-067',
      },
    ],
  },

  // =====================================================================
  // ROBOTICS: BLACK BOX AND KILL SWITCH
  // =====================================================================
  {
    id: 'robotics-blackbox',
    audience: 'Robotics: black box and kill switch',
    title: 'Black box and kill switch',
    domain: 'robotics',
    items: [
      {
        q: 'Can a robot’s black box be audited for tampering without reading the logs?',
        a: `Yes, that separation is the whole point. The black box is an append-only, AES-256-GCM-encrypted, hash-linked chain. Anyone can verify the chain is intact (no entry was altered, nothing was reordered) without holding the key, while only the key holder can decrypt the payloads. Tamper-evidence and confidentiality are independent.`,
        helpLinks: [{ label: 'Black box and kill switch guide', href: '/help/#robotics-blackbox' }],
        meta: 'Shipped - vouch.robotics.blackbox, PAD-069',
      },
      {
        q: 'What is in a black-box entry, and how is it linked?',
        a: `Each entry carries a sequence number, a timestamp, the event name, the encrypted payload (the blob is nonce, then ciphertext, then authentication tag), a \`prevHash\` linking it to the previous entry, and an \`entryHash\` over its own canonical body. Altering any recorded field breaks \`entryHash\`; reordering breaks \`prevHash\`.`,
        helpLinks: [{ label: 'Black box and kill switch guide', href: '/help/#robotics-blackbox' }],
        meta: 'Shipped - vouch.robotics.blackbox, PAD-069',
      },
      {
        q: 'Can I stop a robot remotely and prove who issued the stop?',
        a: `Yes. The kill switch is a signed \`KillSwitchCredential\` that names the target robot, the reason, and the issuer. The credential is a permanent, verifiable record of who triggered the stop and over what scope.`,
        helpLinks: [{ label: 'Black box and kill switch guide', href: '/help/#robotics-blackbox' }],
        meta: 'Shipped - vouch.robotics.blackbox, PAD-068',
      },
      {
        q: 'Can I stop a rogue actor from forging an emergency stop?',
        a: `Yes. Verification of a kill switch can require the issuer DID to be on an attested-authority allowlist. A credential signed by anyone not on the list is rejected, so only an attested authority can trigger a stop that controllers will honor.`,
        meta: 'Shipped - vouch.robotics.blackbox, PAD-068',
      },
    ],
  },

  // =====================================================================
  // ROBOTICS: SCANNABLE PASSPORT
  // =====================================================================
  {
    id: 'robotics-passport',
    audience: 'Robotics: passport',
    title: 'Scannable passport',
    domain: 'robotics',
    items: [
      {
        q: 'Can someone scan a robot to check it is legitimate, offline?',
        a: `Yes. The passport is a signed \`RobotPassport\` encoded into a \`vouch-passport:\` URI for a QR code or NFC tag, so a scanner verifies the signature locally with no network call. It surfaces the robot's owner, authorized actions, certification, and current standing.`,
        helpLinks: [{ label: 'Passport guide', href: '/help/#robotics-passport' }],
        meta: 'Shipped - vouch.robotics.passport, PAD-070',
      },
      {
        q: 'What happens if a passport is expired, suspended, or decommissioned?',
        a: `An expired passport fails verification outright. A suspended or decommissioned passport still verifies cryptographically, but its status is surfaced in the result, so the scanner can refuse cooperation rather than treating a withdrawn robot as silently inactive.`,
        helpLinks: [{ label: 'Passport guide', href: '/help/#robotics-passport' }],
        meta: 'Shipped - vouch.robotics.passport, PAD-070',
      },
      {
        q: 'What is inside the vouch-passport URI?',
        a: `The multibase bytes of the JCS-canonical passport credential, behind the \`vouch-passport:\` scheme. The encoding is deterministic, so a passport encoded in one language decodes and verifies in another, and a reader needs only the issuer's public key to check it, no network and no lookup.`,
        meta: 'Shipped - vouch.robotics.passport, PAD-070',
      },
    ],
  },

  // =====================================================================
  // ROBOTICS: LIVING TRUST HEARTBEAT
  // =====================================================================
  {
    id: 'robotics-liveness',
    audience: 'Robotics: living trust',
    title: 'Living trust heartbeat',
    domain: 'robotics',
    items: [
      {
        q: 'How does a robot keep its trust alive over time?',
        a: `It periodically self-signs a \`RobotHeartbeatCredential\` carrying a motion digest of what it physically did over the interval, plus whether it stayed inside its \`PhysicalCapabilityScope\`. \`is_live\` treats the robot as trusted only while a fresh and in-envelope heartbeat exists, so a robot that goes dark or steps outside its limits loses trust automatically. This inverts "trusted until revoked" to "untrusted until renewed" for a physical machine.`,
        helpLinks: [{ label: 'Living trust guide', href: '/help/#robotics-liveness' }],
        meta: 'Shipped - vouch.robotics.liveness',
      },
      {
        q: 'What is in the motion digest?',
        a: `Plain aggregates over the interval: the sample count, peak force in newtons, peak speed in m/s, peak speed while a human was near, a count of zone breaches, the total breach count, and a \`withinEnvelope\` flag. A \`MotionCollector\` records each commanded motion and checks it against the signed scope to count breaches.`,
        helpLinks: [{ label: 'Living trust guide', href: '/help/#robotics-liveness' }],
        meta: 'Shipped - vouch.robotics.liveness',
      },
      {
        q: 'Why is a breach treated as loss of trust even when the heartbeat is fresh?',
        a: `\`is_live\` requires both freshness and conformance. A recent heartbeat whose digest reports a breach returns not-live, so a robot that exceeded its force, speed, near-human, or zone limits is untrusted until it is brought back inside its envelope, regardless of how recently it checked in.`,
        meta: 'Shipped - vouch.robotics.liveness',
      },
    ],
  },

  // =====================================================================
  // ROBOTICS: CREDENTIAL REVOCATION
  // =====================================================================
  {
    id: 'robotics-revocation',
    audience: 'Robotics: revocation',
    title: 'Credential revocation',
    domain: 'robotics',
    items: [
      {
        q: 'How do I revoke one robot credential without killing the whole robot?',
        a: `Attach a BitstringStatusList \`credentialStatus\` entry with \`attach_credential_status\`, publish the status list, and flip the bit to revoke. \`check_credential_status\` then reports whether that specific capability, provenance, or identity credential is revoked, leaving the robot's other credentials valid.`,
        helpLinks: [{ label: 'Revocation guide', href: '/help/#robotics-revocation' }],
        meta: 'Shipped - vouch.robotics.revocation',
      },
      {
        q: 'How do I kill a compromised or captured robot entirely?',
        a: `A robot DID is an ordinary DID, so the existing \`RevocationRegistry\` revokes it at the DID level and the \`.well-known\` distribution path carries the kill to verifiers. Vouch re-exports the registry from \`vouch.robotics\` so the robot and agent revocation paths are the same.`,
        helpLinks: [{ label: 'Revocation guide', href: '/help/#robotics-revocation' }],
        meta: 'Shipped - vouch.robotics.revocation',
      },
      {
        q: 'How is revocation different from the kill switch?',
        a: `The kill switch is an immediate emergency stop for a running robot. Revocation invalidates credentials so future verification fails. They are complementary: stop the robot now with the kill switch, and revoke its credentials so it cannot be trusted again later.`,
        meta: 'Shipped - vouch.robotics.revocation',
      },
    ],
  },

  // =====================================================================
  // ROBOTICS: ACCOUNTABLE SAFETY RECORD
  // =====================================================================
  {
    id: 'robotics-safety-record',
    audience: 'Robotics: safety record',
    title: 'Accountable safety record',
    domain: 'robotics',
    items: [
      {
        q: 'How does a robot carry a trustworthy safety history?',
        a: `Every safety-relevant event (incident, near-miss, manual override, kill-switch trigger, envelope breach) is appended to a hash-linked \`SafetyEventLog\` with a severity band. The chain is tamper-evident, so no event can be altered or removed without detection, and \`verify_safety_log\` confirms the chain is intact.`,
        helpLinks: [{ label: 'Safety record guide', href: '/help/#robotics-safety-record' }],
        meta: 'Shipped - vouch.robotics.safety_record',
      },
      {
        q: 'What is the portable safety record?',
        a: `A signed \`RobotSafetyRecordCredential\` that summarizes a stretch of the ledger into counts by event type and by severity, the period covered, and the ledger head hash that anchors the summary. It travels with the robot across owners, insurers, and regulators as one verifiable artifact.`,
        helpLinks: [{ label: 'Safety record guide', href: '/help/#robotics-safety-record' }],
        meta: 'Shipped - vouch.robotics.safety_record',
      },
      {
        q: 'Can a robot hide an incident from its safety record?',
        a: `Not without detection. The summary is anchored to the ledger head hash, and the ledger is an append-only hash chain, so altering or dropping an event breaks the chain and changes the head, which no longer matches the signed summary.`,
        meta: 'Shipped - vouch.robotics.safety_record',
      },
    ],
  },

  // =====================================================================
  // ROBOTICS: PERCEPTION PROVENANCE
  // =====================================================================
  {
    id: 'robotics-perception',
    audience: 'Robotics: perception',
    title: 'Perception provenance',
    domain: 'robotics',
    items: [
      {
        q: 'Can a robot prove what its cameras and lidar actually saw?',
        a: `Yes. At capture, the robot signs a \`PerceptionProvenanceCredential\` binding the frame's hash, the sensor id, the modality, and the capture time to its DID. A verifier that holds the frame recomputes its hash and checks it matches, so a substituted or edited frame is detectable.`,
        helpLinks: [{ label: 'Perception provenance guide', href: '/help/#robotics-perception' }],
        meta: 'Shipped - vouch.robotics.perception',
      },
      {
        q: 'How is the sequence of frames kept tamper-evident?',
        a: `Each frame's provenance record is hash-linked to the previous one in a \`PerceptionLog\`, the same append-only chain the black box uses. Altering or dropping a frame breaks the chain, and \`verify_perception_log\` detects it. An attestation can carry the chain head to anchor a whole segment of frames.`,
        helpLinks: [{ label: 'Perception provenance guide', href: '/help/#robotics-perception' }],
        meta: 'Shipped - vouch.robotics.perception',
      },
      {
        q: 'Are the raw frames stored in the credential?',
        a: `No. Only the frame hash and the metadata are carried, so the log stays small and the raw sensor data lives wherever the deployment keeps it. The hash is enough to prove, later, that a given frame is the one the robot attested.`,
        meta: 'Shipped - vouch.robotics.perception',
      },
    ],
  },

  // =====================================================================
  // ROBOTICS: OFFLINE DELEGATION LEASE
  // =====================================================================
  {
    id: 'robotics-lease',
    audience: 'Robotics: offline lease',
    title: 'Offline delegation lease',
    domain: 'robotics',
    items: [
      {
        q: 'How does a robot act safely where there is no connectivity?',
        a: `An authority issues a \`DelegationLeaseCredential\` that bounds what the robot may physically do, a force, speed, near-humans, and zone scope, for a fixed short window. The robot verifies the signature, that the window is current, and that a proposed action fits the scope, all offline with no network call.`,
        helpLinks: [{ label: 'Offline lease guide', href: '/help/#robotics-lease' }],
        meta: 'Shipped - vouch.robotics.lease',
      },
      {
        q: 'How does this work across vendors?',
        a: `Leases nest, and each sub-grant can only narrow the one above it. A vendor leases to an integrator, the integrator to an operator, the operator to the robot, and every link is verifiable and bounded. \`verify_delegation_lease\` checks that a child lease attenuates its parent, so no link can widen authority.`,
        helpLinks: [{ label: 'Offline lease guide', href: '/help/#robotics-lease' }],
        meta: 'Shipped - vouch.robotics.lease',
      },
      {
        q: 'What stops an expired lease from being used?',
        a: `Verification checks the window: a lease that has expired or is not yet valid fails. Because leases are short-lived by design, the exposure from a compromised or stale lease is bounded to its window.`,
        meta: 'Shipped - vouch.robotics.lease',
      },
    ],
  },

  // =====================================================================
  // ROBOTICS: PHYSICAL QUORUM
  // =====================================================================
  {
    id: 'robotics-quorum',
    audience: 'Robotics: physical quorum',
    title: 'Physical quorum',
    domain: 'robotics',
    items: [
      {
        q: 'Can I require more than one approval before a robot does something dangerous?',
        a: `Yes. A physical quorum is a cryptographic two-person rule: a high-consequence action is authorized only when at least M of an attested set of N approvers have each signed an approval over the same action. \`verify_action_authorization\` counts the distinct valid approvers and authorizes only when the threshold is met.`,
        helpLinks: [{ label: 'Physical quorum guide', href: '/help/#robotics-quorum' }],
        meta: 'Shipped - vouch.robotics.physical_quorum',
      },
      {
        q: 'Can one approver just sign twice to reach the threshold?',
        a: `No. The verifier counts DISTINCT approvers, so a single approver counts once no matter how many approvals it submits. Approvals from outside the attested approver set, for a different action, or carrying a reject decision are all ignored.`,
        helpLinks: [{ label: 'Physical quorum guide', href: '/help/#robotics-quorum' }],
        meta: 'Shipped - vouch.robotics.physical_quorum',
      },
    ],
  },

  // =====================================================================
  // ROBOTICS: LIFECYCLE AND DECOMMISSIONING
  // =====================================================================
  {
    id: 'robotics-lifecycle',
    audience: 'Robotics: lifecycle',
    title: 'Lifecycle and decommissioning',
    domain: 'robotics',
    items: [
      {
        q: 'How do I prove a robot changed hands legitimately when it is resold?',
        a: `The current owner signs a \`RobotOwnershipTransferCredential\` handing the robot to the new owner. Linking each transfer to the previous one forms a chain of custody, and \`verify_custody_chain\` checks that every link's new owner matches the next link's seller and that only the current owner could sign each transfer.`,
        helpLinks: [{ label: 'Lifecycle guide', href: '/help/#robotics-lifecycle' }],
        meta: 'Shipped - vouch.robotics.lifecycle',
      },
      {
        q: 'How does a robot rotate its key without losing its history?',
        a: `The robot's current key signs a \`RobotKeyRotationCredential\` that authorizes the new key. Because the old key vouches for the new one, anyone who trusted the old key can follow \`verify_key_history\` to the current key, for a routine rotation or after a compromise.`,
        helpLinks: [{ label: 'Lifecycle guide', href: '/help/#robotics-lifecycle' }],
        meta: 'Shipped - vouch.robotics.lifecycle',
      },
      {
        q: 'What happens when a robot is retired?',
        a: `An owner or authority signs a \`RobotDecommissionCredential\` recording the reason and final disposition. After that, a verifier should refuse to trust the robot. With a trusted-authority set, only an attested authority can retire it.`,
        meta: 'Shipped - vouch.robotics.lifecycle',
      },
    ],
  },

  // =====================================================================
  // ROBOTICS: REGULATORY CONFORMANCE
  // =====================================================================
  {
    id: 'robotics-conformance',
    audience: 'Robotics: conformance',
    title: 'Regulatory conformance',
    domain: 'robotics',
    items: [
      {
        q: 'Can I check a robot against a safety regulation automatically?',
        a: `Yes. A conformance profile maps the robot's credentials to the clauses of a regulation, and \`check_conformance(credentials, profile_id)\` returns a report saying which clauses the presented credentials satisfy, each one cited. Built-in reference profiles cover ISO 10218-1/-2, ISO/TS 15066, the EU Machinery Regulation 2023/1230, the EU AI Act high-risk requirements, and UL 3300.`,
        helpLinks: [{ label: 'Conformance guide', href: '/help/#robotics-conformance' }],
        meta: 'Shipped - vouch.robotics.conformance',
      },
      {
        q: 'How does an auditor consume the result?',
        a: `The robot, its owner, or an assessing authority signs a \`RobotConformanceAttestation\` with \`build_conformance_attestation\`. It embeds the report and binds it by digest, so an auditor verifies the signature and the digest with \`verify_conformance_attestation\` and knows the report was not altered.`,
        meta: 'Shipped - vouch.robotics.conformance',
      },
      {
        q: 'Are the built-in profiles legal advice?',
        a: `No. The profiles are a reference crosswalk to make conformance verifiable in the open. A deployment confirms each mapping against the current text of the regulation for its market before relying on it.`,
        meta: 'Shipped - vouch.robotics.conformance',
      },
    ],
  },

  // =====================================================================
  // ROBOTICS: POST-QUANTUM
  // =====================================================================
  {
    id: 'robotics-pq',
    audience: 'Robotics: post-quantum',
    title: 'Post-quantum signing',
    domain: 'robotics',
    items: [
      {
        q: 'Why do robot credentials need post-quantum signatures?',
        a: `A robot fielded today runs for ten to twenty years, longer than classical Ed25519 is expected to stay safe. A robot identity signed now could be forged once a quantum computer arrives. Signing robot credentials with the hybrid cryptosuite (\`hybrid-eddsa-mldsa44-jcs-2026\`, a classical signature alongside an ML-DSA-44 signature) keeps them unforgeable across the robot's whole service life. Use \`sign_pq\` to sign.`,
        helpLinks: [{ label: 'Post-quantum guide', href: '/help/#robotics-pq' }],
        meta: 'Shipped - vouch.robotics.pq',
      },
      {
        q: 'Do I have to migrate every robot at once?',
        a: `No. \`verify_robot_credential\` accepts a classical or a hybrid proof and detects which from the credential, so a fleet moves to post-quantum gradually while the classical credentials already in the field keep verifying. \`migrate_to_pq\` re-signs a fielded robot's classical credential under a post-quantum key when you are ready.`,
        meta: 'Shipped - vouch.robotics.pq',
      },
      {
        q: 'Does a verifier need the post-quantum key?',
        a: `To verify a hybrid credential, yes: pass the ML-DSA-44 public key (raw bytes or a multikey) to \`verify_pq\` or \`verify_robot_credential\`. Both the classical and the post-quantum signature must validate for the credential to pass.`,
        meta: 'Shipped - vouch.robotics.pq',
      },
      {
        q: 'Can I verify a robot credential from .NET, Java, Swift, or C++?',
        a: `Yes. The reference SDKs (Python, TypeScript, Go, Rust) carry the full robotics surface, and the C, C++, .NET, JVM, and Swift wrappers expose a curated consumer surface over the same core: verify a robot credential (classical or hybrid, auto-detected), mint and verify identity, conformance, passport, action check, and post-quantum sign. In .NET, JVM, and Swift these are a \`VouchRobotics\` class; in C++ a \`vouch::robotics\` namespace. Output is byte-identical across languages.`,
        meta: 'Shipped - C, C++, .NET, JVM, Swift',
      },
    ],
  },

  // =====================================================================
  // ROBOTICS: CROSS-EMBODIMENT CONTINUITY
  // =====================================================================
  {
    id: 'robotics-embodiment',
    audience: 'Robotics: embodiment',
    title: 'Cross-embodiment continuity',
    domain: 'robotics',
    items: [
      {
        q: 'Can one AI agent move between robot bodies and stay accountable?',
        a: `Yes. An embodiment credential binds the agent (a mind with its own identity) to a specific body and that body's hardware root for a period, signed by the agent's own key. Linking each embodiment to the previous one forms a continuity chain that \`verify_continuity_chain\` walks to confirm the same accountable agent persisted across bodies, re-binding to each body's hardware root. It is the inverse of the ownership custody chain: there one body passes between owners, here one mind passes between bodies.`,
        helpLinks: [{ label: 'Cross-embodiment guide', href: '/help/#robotics-embodiment' }],
        meta: 'Shipped - vouch.robotics.embodiment',
      },
      {
        q: 'How do you stop the same agent running on two bodies at once?',
        a: `\`check_no_fork\` confirms no two embodiments place the agent in different bodies with overlapping active time windows. A clean handover sets one body's window to end where the next begins, so there is no overlap; two bodies active at the same time is reported as a fork.`,
        meta: 'Shipped - vouch.robotics.embodiment',
      },
    ],
  },

  // =====================================================================
  // ROBOTICS: PHYSICAL CUSTODY HANDOFF
  // =====================================================================
  {
    id: 'robotics-custody',
    audience: 'Robotics: custody',
    title: 'Physical custody handoff',
    domain: 'robotics',
    items: [
      {
        q: 'Can I trace who held a physical item across humans and robots?',
        a: `Yes. Each handoff is a \`CustodyHandoffCredential\` signed by the receiver accepting custody of a task or object from a releasing actor, who may be a person or a robot. Linking each handoff (each receiver becomes the next releaser) forms a chain \`verify_handoff_chain\` walks, and \`holder_at\` returns who held the task at a given time, so a physical-world incident traces to the exact hop and actor.`,
        helpLinks: [{ label: 'Custody handoff guide', href: '/help/#robotics-custody' }],
        meta: 'Shipped - vouch.robotics.custody',
      },
      {
        q: 'If an item is damaged in transit, can I tell which hop it happened in?',
        a: `Yes. Each handoff can attest the condition of the item as received. \`locate_condition_change\` finds the first hop where the condition differs from the previous one and names the holder who was responsible while it changed, so damage or loss localizes to a specific actor rather than the whole route.`,
        meta: 'Shipped - vouch.robotics.custody',
      },
    ],
  },

  // =====================================================================
  // ROBOTICS: INFRASTRUCTURE ACCESS
  // =====================================================================
  {
    id: 'robotics-access',
    audience: 'Robotics: access',
    title: 'Infrastructure access',
    domain: 'robotics',
    items: [
      {
        q: 'How does a robot open a door or use an elevator without a shared secret?',
        a: `The infrastructure operator issues an \`InfrastructureAccessGrant\` with \`build_access_grant\`, naming the resource (a door, elevator, charger, or machine), the permitted operations, an optional zone, and a time window, signed by the operator. The robot presents an \`InfrastructureAccessRequest\` for one operation, signed by its own key. The resource runs \`authorize_access\` offline: it allows the operation only when the grant verifies under the operator key and is in window, the request verifies under the robot key, the grant and request name the same robot and resource, and the operation is one the grant permits. No shared secret and no live call to a server.`,
        helpLinks: [{ label: 'Infrastructure access guide', href: '/help/#robotics-access' }],
        meta: 'Shipped - vouch.robotics.access',
      },
      {
        q: 'Can I hand a robot a narrower slice of access than I hold?',
        a: `Yes. \`attenuates_grant\` confirms a sub-grant only narrows what it inherits: the same resource, a subset of the operations, and the same zone. A grant can be passed down the chain and checked at each step so no one widens it, and because the grant and the matching request are both signed, the pair is a tamper-evident, attributable record of exactly what access was used and when.`,
        meta: 'Shipped - vouch.robotics.access',
      },
    ],
  },

  // =====================================================================
  // ROBOTICS: FUSED-SENSOR PROVENANCE
  // =====================================================================
  {
    id: 'robotics-fusion',
    audience: 'Robotics: fusion',
    title: 'Fused-sensor provenance',
    domain: 'robotics',
    items: [
      {
        q: 'A robot acts on fused sensor data, not one frame. Can I prove where a fused result came from?',
        a: `Yes. \`build_fused_attestation\` signs a \`FusedPerceptionAttestation\` that binds the hash of the fused output (a world model, an occupancy grid, or a pose) to the ordered list of input frame hashes and the fusion method that produced it. \`verify_fused_attestation\` checks the robot's proof and reproduces a digest over the listed inputs, so the attestation commits to exactly those inputs and that output, and a manipulated fusion result no longer matches.`,
        helpLinks: [{ label: 'Fused-sensor provenance guide', href: '/help/#robotics-fusion' }],
        meta: 'Shipped - vouch.robotics.fusion',
      },
      {
        q: 'Can I tell if a fused result quietly dropped or swapped one of its input frames?',
        a: `Yes. \`verify_fusion_inputs\` checks every input frame the attestation names against the robot's signed perception log and returns any that were never recorded, so a dropped or substituted fused input is named rather than hidden. Because the input digest is signed, adding, removing, or reordering an input also changes the digest and breaks verification.`,
        meta: 'Shipped - vouch.robotics.fusion',
      },
    ],
  },

  // =====================================================================
  // ROBOTICS: WEAR AND DEGRADATION
  // =====================================================================
  {
    id: 'robotics-wear',
    audience: 'Robotics: wear',
    title: 'Wear and degradation',
    domain: 'robotics',
    items: [
      {
        q: 'A robot wears out over its life. Can it prove its own degradation?',
        a: `Yes. \`build_wear_attestation\` signs a \`RobotWearAttestation\` carrying a normalized wear level (0 for as-new, 1 for fully worn) and optional detailed metrics like actuator wear, calibration drift, and cycle count, bound to the robot's identity. Linking each attestation to the previous one by its proof forms a hash-linked history \`verify_wear_chain\` walks, so the way a robot degraded over its life is tamper-evident.`,
        helpLinks: [{ label: 'Wear and degradation guide', href: '/help/#robotics-wear' }],
        meta: 'Shipped - vouch.robotics.wear',
      },
      {
        q: 'Can a worn robot automatically operate inside tighter limits?',
        a: `Yes. \`attenuate_for_wear\` derives a physical capability scope whose force and speed caps are scaled down by the wear level, and the result is a valid attenuation of the original scope, so the same attenuation check the rest of Vouch uses accepts it. A robot at 25 percent wear runs on a scope with three-quarters of its original caps, verifiably narrower than the limit it shipped with.`,
        meta: 'Shipped - vouch.robotics.wear',
      },
    ],
  },

  // =====================================================================
  // ROBOTICS: BYSTANDER CONSENT
  // =====================================================================
  {
    id: 'robotics-consent',
    audience: 'Robotics: consent',
    title: 'Bystander consent',
    domain: 'robotics',
    items: [
      {
        q: 'A robot with cameras records people in public. Can it prove it had a basis to?',
        a: `Yes. \`build_consent_evidence\` signs a \`BystanderConsentEvidence\` credential that binds a capture, named only by its hash, to a consent basis: an explicit token, posted notice, a legitimate interest, or a redaction the robot applied. It stores only hashes and the basis, never an image or anyone's identifying data, so the record is verifiable without retaining biometrics. \`verify_consent_evidence\` checks the robot's proof, that the basis is one an interoperable verifier accepts, and, when given the raw capture, that its hash matches.`,
        helpLinks: [{ label: 'Bystander consent guide', href: '/help/#robotics-consent' }],
        meta: 'Shipped - vouch.robotics.consent',
      },
      {
        q: 'If a person consents to being recorded, can that consent be reused for other footage?',
        a: `No, and that is the point. \`build_consent_token\` has the bystander sign over the hash of the one capture and the robot's DID, so \`verify_consent_token\` accepts it only for that capture and that robot. A token given for one recording cannot be replayed against another. The evidence commits to its tokens by their proof value, so an explicit-consent record names exactly which consents cover the capture without embedding anyone's identity.`,
        meta: 'Shipped - vouch.robotics.consent',
      },
    ],
  },

  // =====================================================================
  // FOR DEVELOPERS
  // =====================================================================
  {
    id: 'developers',
    audience: 'Building with Vouch',
    title: 'Adding Vouch to your code',
    items: [
      {
        q: 'What is the fastest way to add Vouch to my agent?',
        a: `One line. Run \`vouch init --yes\` once to provision an identity, then wrap your tools:

\`\`\`python
from vouch import protect

agent.tools = protect([charge_invoice, send_email])
\`\`\`

Every tool call is now signed in Python before it runs. There is no prompt to write and nothing for the model to remember, and identity is resolved automatically, so agent code needs no key plumbing. \`protect\` works for plain functions and for CrewAI, LangChain, AutoGen, AutoGPT, Vertex AI, Google, and ADK tools. For decorator frameworks you can also call \`<framework>.autosign()\` to sign every tool framework-wide. Verify on the receiving side with \`vouch.verify(credential)\`, or add the FastAPI \`VouchGate\` dependency to an endpoint.`,
        helpLinks: [{ label: 'Integrations', href: '/help/#integrations' }],
        meta: 'Shipped v1.6.x',
      },
      {
        q: 'What is the fastest way to start using Vouch?',
        a: `On Linux or macOS, one line installs the \`vouch\` command (on Windows, use \`pip install vouch-protocol\`):

\`\`\`bash
curl -fsSL https://vouch-protocol.com/install.sh | sh
\`\`\`

Then run \`vouch\` with no arguments and pick from a short menu: sign your git commits (a verified badge on GitHub), or give an agent its own identity. For a full agent setup with recommended defaults and no questions, run \`vouch onboard --quick\`, which writes a working identity, allow-list, verifier, and heartbeat config in one command.`,
        helpLinks: [{ label: 'Getting started', href: '/help/#quickstart-python' }],
      },
      {
        q: 'Which languages have Vouch SDKs?',
        a: `One canonical Rust core does the cryptography once, and every language is a thin wrapper over it, so a credential signed on any platform verifies on every other, byte for byte (JCS canonicalization):

- **Python**: \`pip install vouch-protocol\` (the most complete: signer, verifier, async verifier, KMS, reputation, revocation, cache, rate-limit, metrics, CLI)
- **TypeScript and Go**: the reference SDKs for Node and for the Identity Sidecar
- **Browser and Node.js (WebAssembly)**: \`npm install @vouch-protocol-official/core-wasm\`
- **.NET**: \`dotnet add package VouchProtocol.Core\`
- **Swift (iOS and macOS)**, **JVM (Java and Kotlin)**, and **C/C++**: native wrappers over the same core
- **HTTP API clients** for the Bridge service: \`npm install @vouch-protocol-official/api-client\` or \`pip install vouch-api-client\`

Every implementation passes the same cross-language test vectors at [test-vectors/](https://github.com/vouch-protocol/vouch/tree/main/test-vectors).`,
        helpLinks: [
          { label: 'Python quickstart', href: '/help/#quickstart-python' },
          { label: 'TypeScript quickstart', href: '/help/#quickstart-typescript' },
          { label: 'Go sidecar quickstart', href: '/help/#quickstart-go' },
        ],
        meta: 'Shipped v1.6.0',
      },
      {
        q: 'How do I sign a credential in Python?',
        a: `Build a signer from your identity, then pass the intent directly to \`sign\`:

\`\`\`python
from vouch import Signer, generate_identity

keys = generate_identity("agent.example.com")
signer = Signer(private_key=keys.private_key_jwk, did=keys.did)

signed = signer.sign(intent={
  "action": "submit_claim",
  "target": "claim:HC-001",
  "resource": "https://insurance.example.com/claims/HC-001",
}, valid_seconds=300)
\`\`\`

The \`signed\` dict has a \`proof\` object with a \`proofValue\` (z-base58 encoded Ed25519 signature) and verification metadata. To make an agent sign every tool call automatically, use \`protect([...])\` instead (see the question above).`,
        helpLinks: [{ label: 'Full Python quickstart', href: '/help/#quickstart-python' }],
      },
      {
        q: 'How do I sign with the hybrid post-quantum profile?',
        a: `Use \`sign_hybrid()\` instead of \`sign()\`. The required \`pqcrypto\` library is bundled with \`vouch-protocol\` by default (since v1.6.0), so nothing else to install:

\`\`\`bash
pip install vouch-protocol
\`\`\`

Then:

\`\`\`python
from vouch import Signer, generate_identity

keys = generate_identity("agent.example.com")
signer = Signer(private_key=keys.private_key_jwk, did=keys.did)

signed = signer.sign_hybrid(intent={
  "action": "submit_claim",
  "target": "claim:HC-001",
  "resource": "https://insurance.example.com/claims/HC-001",
})
\`\`\`

The resulting credential's \`proof\` field is an **array** of two Data Integrity proofs: one with \`cryptosuite: "eddsa-jcs-2022"\` (the classical Ed25519 proof) and one with \`cryptosuite: "mldsa44-jcs-2026"\` (the post-quantum ML-DSA-44 proof). Both proofs cover the same JCS-canonicalized credential bytes. Verifiers iterate the array and apply their local policy (validate either, validate both).

(The earlier v1.6.x reference implementation emits a single composite proof with \`cryptosuite: "hybrid-eddsa-mldsa44-jcs-2026"\` and a concatenated proofValue. That format is retained as a transitional alias; new implementations SHOULD emit dual proofs.)`,
        helpLinks: [{ label: 'Hybrid PQ implementation guide', href: '/help/#hybrid-pq' }],
        meta: 'Shipped v1.6.0 - Specification §13.2',
      },
      {
        q: 'How do I verify a credential signed in a different language?',
        a: `You don't need to do anything special. JCS canonicalization guarantees byte-identical signed payloads across languages, so a credential signed in Python verifies correctly in TypeScript or Go (and vice versa).

\`\`\`python
from vouch import Verifier
verifier = Verifier()
result = await verifier.verify(signed) # accepts credentials from any SDK
\`\`\`

The published test vectors at [test-vectors/hybrid-eddsa-mldsa44/](https://github.com/vouch-protocol/vouch/tree/main/test-vectors/hybrid-eddsa-mldsa44) include a Python-generated signature that is exercised by both the TypeScript and Go test suites.`,
        meta: 'PAD-039 JCS Deterministic Multi-Party Trust State',
      },
      {
        q: 'Do I need to run the Go sidecar?',
        a: `Only if you want the Identity Sidecar pattern, which is the recommended deployment for LLM-driven agents because it keeps the private key out of the LLM context window. If your code never exposes the key to the model (for example, a Python service signing on behalf of an agent), you can sign directly from the Python or TypeScript SDK.

The Go sidecar is also useful for polyglot stacks: it exposes \`POST /sign\` over HTTP, so any language can ask it to sign without having a Vouch SDK installed.`,
        helpLinks: [{ label: 'Sidecar deployment guide', href: '/help/#sidecar-deployment' }],
        meta: 'Specification §10 - PAD-003',
      },
      {
        q: 'How do I verify a delegation chain?',
        a: `Pass the chain (list of credentials, principal first, agent last) to the verifier:

\`\`\`python
from vouch import Verifier
verifier = Verifier()
result = await verifier.verify_delegation_chain([principal_vc, agent_vc, sub_agent_vc])
\`\`\`

The verifier walks every link, validates signatures, and confirms resource subset narrowing. If any link fails, the whole chain fails with a structured reason.`,
        meta: 'Specification §9 Delegation Chains',
      },
      {
        q: 'How do I use one identity across my devices without copying my private key?',
        a: `Each device makes its own key and keeps it local. Your root identity signs a scoped grant for each device, and the device signs its actions with its own key, chained under that grant. A verifier ties any action back to the trusted root. The private key never travels between devices.

\`\`\`python
from vouch import Agent, enroll_device, verify_delegated_chain

root = Agent("alice.example")
phone = Agent()  # a did:key minted on the phone
grant = enroll_device(root, device_did=phone.did, action="charge",
                      target="api.bank", resource="https://api.bank/invoices")
action = phone.sign(action="charge", target="api.bank",
                    resource="https://api.bank/invoices/42", parent_credential=grant)
result = verify_delegated_chain([grant, action],
                                trusted_roots={root.did: root.public_key_jwk})
\`\`\`

Lose a device and you revoke it with a \`DeviceRegistry\`; lose the root and you rebuild it from a threshold of Shamir shares with \`split_identity\` and \`recover_identity\`. Every SDK (Python, TypeScript, Go, JVM, .NET, C, Swift) exposes the same helpers.`,
        meta: 'Cross-device identity',
      },
      {
        q: 'Can several people jointly sign one action without any of them holding the full key?',
        a: `Yes, with FROST(Ed25519) threshold signing. A key is split among several custodians so that any threshold of them can sign together, and the full private key never exists whole at any point, not even during signing. The result is a standard Ed25519 signature, so it verifies exactly like any other credential.

\`\`\`python
from vouch import Signer, ThresholdSigner, threshold

generated = threshold.generate_key(min_signers=2, max_signers=3)
threshold_signer = ThresholdSigner(generated.shares[:2], generated.group_public_key)

signer = Signer.from_backend(
    did="did:web:agent.example",
    public_key=generated.group_public_key.public_key_jwk,
    sign=threshold_signer.sign,
)
credential = signer.sign(action="read", target="t", resource="https://x/y")
\`\`\`

This is distinct from the recovery shares above: recovery reconstructs a key once, for a deliberate restore; threshold signing never reconstructs it at all, and is meant for live, repeated signing. Every SDK (Python, TypeScript, Go, JVM, .NET, C, Swift) binds the same audited \`frost-ed25519\` core (the Zcash Foundation's RFC 9591 implementation), so every language produces byte-identical results.`,
        meta: 'FROST threshold signing',
      },
      {
        q: 'How do I make a credential revocable later?',
        a: `Attach a status entry when you issue it. That way, if you ever need to revoke it, you just flip a bit on a published list. Allocate an index from your status list, then pass the entry as \`credential_status\` to \`sign\` so the proof covers it:

\`\`\`python
from vouch import Signer, StatusList, build_status_list_entry, generate_identity

# Issuer maintains a single StatusList per status purpose (revocation or suspension).
status_list = StatusList(status_list_id="https://issuer.example/status/1")
index = status_list.allocate_index()

status_entry = build_status_list_entry(
  status_list_credential="https://issuer.example/status/1",
  status_list_index=index,
)

keys = generate_identity("issuer.example")
signer = Signer(private_key=keys.private_key_jwk, did=keys.did)

signed = signer.sign(
  intent={"action": "submit_claim", "target": "claim:HC-001",
      "resource": "https://insurance.example/claims/HC-001"},
  credential_status=status_entry,
)
\`\`\`

The TypeScript and Go SDKs expose the same API (\`buildStatusListEntry\` / \`BuildStatusListEntry\`) and accept \`credentialStatus\` / \`CredentialStatus\` on their credential builders.`,
        helpLinks: [{ label: 'BitstringStatusList how-to', href: '/help/#credential-status' }],
        meta: 'Shipped on main, in next release - Specification §11.2',
      },
      {
        q: 'How do I revoke a credential I previously issued?',
        a: `Flip the bit at that credential's index in your status list, re-sign the BitstringStatusListCredential, and republish it:

\`\`\`python
status_list.revoke(index) # set the bit

status_credential = build_status_list_credential(
  issuer_did="did:web:issuer.example",
  status_list=status_list,
)
signed_status_credential = signer.sign(status_credential)

# Publish signed_status_credential at the URL referenced by issued credentials.
\`\`\`

Verifiers fetch the updated status credential, decode the bitstring, and observe that the bit is now set. The credential itself doesn't change; only the status list does.`,
        helpLinks: [{ label: 'BitstringStatusList how-to', href: '/help/#credential-status' }],
        meta: 'Shipped on main, in next release',
      },
      {
        q: 'How does a verifier check credential status?',
        a: `Fetch the status list credential, then call \`verify_status\` with the credential's \`credentialStatus\` entry and the fetched list:

\`\`\`python
from vouch import StatusListFetcher, verify_status

fetcher = StatusListFetcher() # in-memory TTL cache, conditional GETs

status_credential = fetcher.get(
  signed["credentialStatus"]["statusListCredential"]
)

is_revoked = verify_status(
  credential_status=signed["credentialStatus"],
  status_list_credential=status_credential,
)
\`\`\`

The fetcher caches by URL with a 5-minute default TTL and issues conditional GETs (\`If-None-Match\`, \`If-Modified-Since\`) so re-validation is cheap when the issuer hasn't updated the list. Set \`force_refresh=True\` on verification failure to handle stale-cache scenarios. TypeScript and Go callers can compose the equivalent with \`fetch()\` and \`net/http.Get()\` respectively.`,
        helpLinks: [{ label: 'BitstringStatusList how-to', href: '/help/#credential-status' }],
        meta: 'Shipped on main, in next release',
      },
      {
        q: 'How do I avoid re-using a credential index after a restart?',
        a: `Use the persistence API. \`to_state_dict()\` returns a JSON-serializable dict containing the encoded bitstring **and** the allocation cursor (\`next_index\`), which is NOT recoverable from the encoded list alone:

\`\`\`python
from vouch import FilesystemStatusListStore

store = FilesystemStatusListStore("/var/lib/vouch/status-1.json")

# After every allocate / revoke, persist.
store.save(status_list)

# On startup:
status_list = store.load()
\`\`\`

\`FilesystemStatusListStore\` is a reference implementation with atomic temp-file + rename writes. Production deployments substitute Redis, Postgres, or S3 using the same state-dict API. Without persistence of \`next_index\`, an issuer restart would re-allocate already-used indices, silently overwriting prior revocations.`,
        helpLinks: [{ label: 'BitstringStatusList how-to', href: '/help/#credential-status' }],
        meta: 'Shipped on main, in next release',
      },
      {
        q: 'What framework integrations exist?',
        a: `Python integrations live under \`vouch/integrations/\`:

- **LangChain** - tool wrapper that signs tool inputs before execution
- **LangGraph** - signs tool calls and graph nodes across a LangGraph graph
- **CrewAI** - tool wrapper for crew-style multi-agent flows
- **AutoGPT** - command integration
- **AutoGen** - tool wrapper
- **Streamlit** - media-sealing UI helper
- **Vertex AI** - Google Vertex AI tool
- **Google ADK** - Agent Development Kit integration
- **Google APIs** - generic Sheets/Docs/Drive integration
- **n8n** - workflow automation node
- **Hasura** - GraphQL webhook
- **MCP** - Model Context Protocol server
- **Goose** - registers the Vouch MCP server as an extension for Block's Goose agent

**New standalone packages:** \`vouch-langchain\`, \`vouch-langgraph\` (signs LangGraph tool calls and graph nodes), \`vouch-crewai\`, \`vouch-a2a\` (binds an A2A Agent Card to a Vouch identity), \`vouch-goose\` (registers the Vouch MCP server as a Goose extension), \`vouch-mlflow\` (signs a model artifact at registration time, bound to its content digest), and \`vouch-safetensors\` (embeds a credential in the model header, complementary to OpenSSF Model Signing). Each issues a verifiable credential per tool call, with optional delegation back to a human principal.

Examples for each are in [examples/05_integrations/](https://github.com/vouch-protocol/vouch/tree/main/examples/05_integrations).

TypeScript currently has the Amnesia bridge in \`packages/sdk-ts/src/integrations/\`.`,
        helpLinks: [{ label: 'Framework integration guides', href: '/help/#integrations' }],
      },
      {
        q: 'Is there a CLI?',
        a: `Yes. Installing \`vouch-protocol\` (\`pip install vouch-protocol\`) puts a \`vouch\` command on your PATH. It covers agent identity, message signing, signed git commits, media signing, a leaked-key scanner, and human/AI code attribution.

**Identity and tokens**

- \`vouch init\` generate an agent identity (DID + Ed25519 keypair)
- \`vouch sign "<message>"\` sign a message or JSON payload, prints a Vouch-Token
- \`vouch verify <token>\` verify a Vouch-Token

**Git**

- \`vouch git init\` set up SSH commit signing and Vouch trailers
- \`vouch git status\` show your current git signing config
- \`vouch git verify\` verify commit signatures against their Vouch-DID trailers

**Media**

- \`vouch media sign <image>\` sign an image (native Vouch by default, or \`--c2pa\`)
- \`vouch media verify <image>\` verify an image's signature

**Other**

- \`vouch scan [path]\` scan for leaked Vouch private keys (PAD-058)
- \`vouch attribute ...\` per-region human/AI code authorship attribution

\`\`\`bash
vouch init
vouch sign "hello"
vouch scan .
vouch git init
vouch media sign photo.jpg
\`\`\`

There are also separate helper binaries: \`vouch-mcp\` (MCP server) and \`vouch-bridge\` (media HTTP server), plus a Go \`vouch-sidecar\` for non-Python stacks.`,
        helpLinks: [{ label: 'CLI reference', href: '/help/#cli-reference' }],
      },
      {
        q: 'Where is the browser extension?',
        a: `Source at [browser-extension/](https://github.com/vouch-protocol/vouch/tree/main/browser-extension). Manifest v3, Chrome / Edge / Brave compatible. Adds a "Sign with Vouch" context menu on selected text, a popup for identity selection and verification, and shortlink resolution via vch.sh.

Build artifacts (.crx, .zip) are produced by the GitHub Actions workflow at [.github/workflows/build-extensions.yml](https://github.com/vouch-protocol/vouch/blob/main/.github/workflows/build-extensions.yml).`,
      },
      {
        q: 'Is there a mobile SDK?',
        a: `Yes. [mobile/expo-app/](https://github.com/vouch-protocol/vouch/tree/main/mobile/expo-app) is a React Native + Expo app supporting iOS and Android. It uses device-level Secure Enclave (iOS) and Android Keystore. Capture-time photo signing with EXIF preservation and a chain of trust linking to organizational credentials.`,
      },
    ],
  },

  // =====================================================================
  // FOR OPERATORS
  // =====================================================================
  {
    id: 'operators',
    audience: 'Running in Production',
    title: 'Deployment, keys, storage, observability',
    items: [
      {
        q: 'Which KMS backends are supported?',
        a: `\`vouch/kms.py\` (16 KB) supports:

- **Memory** - in-process key storage (development only)
- **AWS KMS** - via boto3
- **GCP KMS** - via google-cloud-kms
- **Azure Key Vault** - via azure-keyvault
- **Local File** - encrypted file storage with optional passphrase

The \`RotatingKeyProvider\` class handles automatic rotation by time or by validity period. \`KeyConfig\` is the dataclass that holds JWK, DID, key ID, and validity window.`,
        helpLinks: [{ label: 'KMS integration guide', href: '/help/#kms-integration' }],
        meta: 'Shipped v1.2.0 - vouch/kms.py',
      },
      {
        q: 'What storage backends does the revocation registry support?',
        a: `\`vouch/revocation.py\` (449 lines) supports Memory and Redis backends out of the box, with an abstract \`RevocationStoreInterface\` for custom backends (HTTP remote registries, distributed key-value stores, etc.).

This is **DID-level revocation** (revoke a DID, all credentials under it become invalid). For **credential-level revocation** (revoke a single credential by index in a status bitstring), Vouch ships a BitstringStatusList implementation across all three SDKs (\`vouch.status_list\` in Python, \`packages/sdk-ts/src/status-list.ts\` in TypeScript, \`go-sidecar/signer/status_list.go\` in Go). The two mechanisms compose: BitstringStatusList for granular per-credential status, DID-level registry for "revoke everything from this compromised identity" scenarios.`,
        helpLinks: [
          { label: 'Revocation deployment', href: '/help/#revocation' },
          { label: 'Credential status (BitstringStatusList)', href: '/help/#credential-status' },
        ],
        meta: 'Shipped v1.2.0 (registry) + Unreleased (BitstringStatusList) - Specification §11.2',
      },
      {
        q: 'What storage backends does the reputation engine support?',
        a: `\`vouch/reputation.py\` (711 lines) supports four backends:

- **MemoryReputationStore** - in-process dict
- **RedisReputationStore** - via redis-py
- **KafkaReputationStore** - event-sourced via Kafka topics
- **HTTP** - remote reputation API

The engine implements exponential decay toward a baseline (default rate 0.1/day, kicks in after 7 days of inactivity), action deltas (success +1, failure -2, slash/boost configurable), and five-tier classification (untrusted < cautionary < neutral < trusted < exceptional).

Note: the Specification scope statement says reputation *algorithms* are not normative; the shipped engine is a reference implementation.`,
        helpLinks: [{ label: 'Reputation deployment', href: '/help/#reputation' }],
        meta: 'Shipped v1.2.0 (engine), v1.3.1 (Signer integration)',
      },
      {
        q: 'What caching is built in?',
        a: `\`vouch/cache.py\` (9.4 KB) ships three cache backends: Memory (LRU), Redis (distributed), and Tiered (Memory + Redis fallback). The caches are used by the verifier to cache DID Document resolutions, public key lookups, and credential-status responses.`,
        meta: 'Shipped v1.1.3 - vouch/cache.py',
      },
      {
        q: 'How does rate limiting work?',
        a: `\`vouch/ratelimit.py\` (9.5 KB) implements token-bucket rate limiting backed by Redis (distributed) or Memory (local). Per-DID, per-IP, or per-tool buckets. Configurable burst capacity and refill rate.

For more aggressive primitives, [PAD-047](https://github.com/vouch-protocol/vouch/blob/main/docs/disclosures/PAD-047-vdf-rate-limited-agent-actions.md) describes a Verifiable Delay Function (VDF) approach where minimum elapsed wall-clock time is cryptographically self-evident without trust in any clock authority.`,
        meta: 'Shipped v1.1.3 - PAD-047',
      },
      {
        q: 'How is replay attack prevention handled?',
        a: `\`vouch/nonce.py\` (7 KB) tracks recently-seen credential nonces and rejects duplicates. Memory or Redis backed, with configurable TTL (default 300 seconds). The verifier consults the nonce store on every verification.`,
        meta: 'Shipped v1.1.3',
      },
      {
        q: 'What metrics does Vouch expose?',
        a: `\`vouch/metrics.py\` (8.8 KB) emits Prometheus-compatible metrics:

\`\`\`
vouch_signatures_total      counter
vouch_verifications_total     counter
vouch_verification_success_rate  gauge
vouch_verification_latency_seconds histogram
vouch_cache_hits         counter
vouch_cache_misses        counter
vouch_credential_issuances    counter
vouch_reputation_lookups     counter
vouch_revocation_checks      counter
\`\`\`

OpenTelemetry exporters are optional via the \`[otel]\` extra.`,
        meta: 'Shipped v1.1.0',
      },
      {
        q: 'What throughput can the Python SDK handle?',
        a: `The reputation engine's three-tier storage architecture is sized for 10K-50K RPS deployments per the CHANGELOG. Signing and verification throughput depends on the chosen cryptosuite (ed25519 is fast, hybrid PQ adds ML-DSA-44's ~3ms sign cost per operation on M-series hardware). For high-throughput verifier paths, use \`async_verifier\` (\`vouch/async_verifier.py\`, 16 KB) which supports concurrent verification with caching.`,
        meta: 'Shipped v1.1.3 (async_verifier), v1.2.0 (reputation scale claims)',
      },
      {
        q: 'How do I deploy the Go sidecar?',
        a: `Build and run:

\`\`\`bash
cd go-sidecar
go build ./cmd/vouch-sidecar
./vouch-sidecar --did did:web:agent.example.com --port 8877
\`\`\`

The \`-s\` / \`--sensitive\` flag wraps the response in a JWE so the credential is encrypted in flight. The endpoint is \`POST /sign\` accepting a credential JSON body and returning the signed credential.

For containerized deployment, the [Dockerfile](https://github.com/vouch-protocol/vouch/tree/main/go-sidecar) is straightforward Go static binary in a scratch image.`,
        helpLinks: [{ label: 'Sidecar deployment guide', href: '/help/#sidecar-deployment' }],
      },
      {
        q: 'Is there a GitHub App?',
        a: `Yes. **Vouch Gatekeeper** ([github-app/](https://github.com/vouch-protocol/vouch/tree/main/github-app), FastAPI, ~1000 lines) enforces cryptographic identity and organizational policy on every PR. Listens for \`pull_request.opened\` and \`pull_request.synchronize\`. Verifies commit signatures with GitHub SSH/GPG first, falls back to the Vouch Registry. Zero-config policy is "org member with signed commit = allow." Custom policy via \`.github/vouch-policy.yml\`. Shields.io badge endpoint at \`/api/badge/{owner}/{repo}\`. Auto-opens a PR to add the protection badge on installation.`,
        helpLinks: [{ label: 'GitHub App setup guide', href: '/help/#github-app' }],
        meta: 'Shipped v1.4.0',
      },
      {
        q: 'Is there a Cloudflare Worker?',
        a: `Yes. [cloudflare-worker/](https://github.com/vouch-protocol/vouch/tree/main/cloudflare-worker) provides signature storage and shortlink redirection. Shortlinks at \`vch.sh/{id}\` redirect to \`vouch-protocol.com/v/{id}\`. Free tier (1-year expiry) and Pro tier (no expiry). Cloudflare KV bindings for storage.`,
      },
      {
        q: 'What about media provenance?',
        a: `Vouch leaves media provenance to [C2PA](https://c2pa.org) and works alongside it rather than reimplementing it. \`vouch media sign\` signs an image with native Vouch signing by default, or with C2PA Content Credentials when you pass \`--c2pa\`, and the \`vouch-bridge\` server exposes C2PA image signing over a simple HTTP API. The audio path (\`vouch/audio.py\`) implements multi-layer Hamming(7,4) watermarks with psychoacoustic masking for audio signing.`,
        meta: 'Shipped v1.5.0',
      },
      {
        q: 'How should I deploy the BitstringStatusList in production?',
        a: `Three operational pieces:

1. **Issuer-side storage**: Replace \`FilesystemStatusListStore\` (development) with a shared store so multiple issuer instances can coordinate. The state-dict API is backend-agnostic; common choices are Redis (\`SET status:1 <state-json>\`), Postgres (single row with \`UPDATE\` under SELECT FOR UPDATE), or S3 (with optimistic concurrency via ETags).

2. **Status list publishing**: Sign the \`BitstringStatusListCredential\` and serve it at a stable HTTPS URL, ideally with \`Cache-Control: max-age=...\` and \`ETag\` headers. The \`StatusListFetcher\` honors both. CDN-cacheable; the credential is public.

3. **Verifier-side caching**: The reference \`StatusListFetcher\` uses an in-memory cache, fine for single-process verifiers. For multi-instance verifier fleets, wrap it with a shared cache (Redis) so a revocation is visible across the fleet within one TTL window. On verification failure, set \`force_refresh=True\` to bypass the cache and pick up the latest list.`,
        helpLinks: [{ label: 'BitstringStatusList how-to', href: '/help/#credential-status' }],
        meta: 'Shipped on main, in next release',
      },
      {
        q: 'How big can a BitstringStatusList grow?',
        a: `The protocol minimum is 131,072 bits (16 KiB uncompressed; ~50 bytes compressed when empty). That's enough for 131,072 credentials per status list. For larger issuers, allocate a new status list when you approach exhaustion; each credential's \`credentialStatus.statusListCredential\` URL identifies which list it belongs to.

Practical operational sizing: 131,072 credentials at a 5-minute validity (typical short-lived agent credentials) means a single list covers roughly one year at 0.4 credentials/minute, or one day at ~91/minute. Plan list rotation accordingly.`,
        meta: 'BitstringStatusList §4.2',
      },
    ],
  },

  // =====================================================================
  // FOR COMPLIANCE / REGULATORY
  // =====================================================================
  {
    id: 'compliance',
    audience: 'Compliance & Regulations',
    title: 'HIPAA, SR 11-7, EU AI Act, NIST and friends',
    items: [
      {
        q: 'Does Vouch satisfy HIPAA / HITECH?',
        a: `Vouch is not a HIPAA control by itself, no specification is. But Vouch provides the cryptographic primitives that map directly onto multiple HIPAA Technical Safeguards (45 CFR 164.312):

- **Audit Controls** (§164.312(b)) - every agent action is a non-repudiable signed credential
- **Integrity** (§164.312(c)) - Data Integrity proofs detect any post-hoc modification
- **Person or Entity Authentication** (§164.312(d)) - DIDs prove agent identity cryptographically
- **Transmission Security** (§164.312(e)) - delegation chains plus optional JWE wrapping in the sidecar

For 21 CFR Part 11 (electronic records / electronic signatures), the same proofs satisfy the integrity and authenticity requirements.`,
        meta: 'Specification §1.1 - Healthcare framing',
      },
      {
        q: 'Does Vouch satisfy SR 11-7 / FFIEC AI guidance?',
        a: `SR 11-7 (Federal Reserve guidance on model risk management) and FFIEC AI guidance require a verifiable audit trail of model-driven decisions, the ability to attribute actions to specific model versions, and continuous monitoring of model behavior post-deployment.

Vouch addresses these through (a) intent-bound credentials with model-version metadata in the credential subject, (b) the Heartbeat Protocol for continuous post-deployment monitoring, and (c) reputation tracking and slashing for misbehavior detection. The [docs/THREAT_MODEL.md](https://github.com/vouch-protocol/vouch/blob/main/docs/THREAT_MODEL.md) maps Vouch primitives to SR 11-7 categories.`,
      },
      {
        q: 'Does Vouch satisfy the EU AI Act?',
        a: `The EU AI Act (applicable from 2025) imposes auditability and human-oversight obligations on high-risk AI systems. Vouch's delegation chains provide a verifiable principal-to-agent-to-sub-agent audit trail. The intent attestation in every credential satisfies the "human-interpretable record of the model's decision" requirement for high-risk systems. The Heartbeat Protocol provides the continuous monitoring required under Article 14.`,
        meta: 'Specification §1.1 EU framing',
      },
      {
        q: 'Does Vouch satisfy NIST CNSA 2.0 / NSM-10 for post-quantum migration?',
        a: `Yes, in two phases. The current revision ships an **optional** dual-proof post-quantum profile: pair the default \`eddsa-jcs-2022\` Data Integrity proof with an additional \`mldsa44-jcs-2026\` Data Integrity proof on the same credential, aligning with the NIST CNSA 2.0 phase-in. As CNSA 2.0 advances and regulator guidance matures, the dual-proof profile is expected to become RECOMMENDED for regulated sectors, then REQUIRED. Implementers operating in regulated sectors can adopt it today by passing \`--hybrid\` to the signer (the v1.6.x reference implementations still emit the transitional composite proof; the v1.7 rewrite emits dual proofs).`,
        helpLinks: [{ label: 'Hybrid PQ implementation guide', href: '/help/#hybrid-pq' }],
        meta: 'Shipped v1.6.0 - NIST FIPS 204',
      },
      {
        q: 'Where is the threat model?',
        a: `[docs/THREAT_MODEL.md](https://github.com/vouch-protocol/vouch/blob/main/docs/THREAT_MODEL.md). It covers the trust boundaries (LLM context, sidecar, validator quorum, verifier), the attacker model (network adversary, compromised agent, compromised LLM, compromised key holder), and the mitigation each Vouch primitive provides.`,
      },
      {
        q: 'How does Vouch handle non-repudiation?',
        a: `Every action is a cryptographically signed credential whose signature can be verified by any third party with access to the agent's DID Document. The credential is human-readable JSON, so an auditor can inspect it directly without specialized tooling. Delegation chains preserve the audit trail from the human principal down to the executing agent.

If a dispute arises, the credential and its proof can be presented as evidence; the signature is independently verifiable without needing the issuer to cooperate.`,
      },
      {
        q: 'Is there a defensive disclosure portfolio?',
        a: `Yes. 55 Prior Art Disclosures (PADs) published under CC0 1.0 Universal at [docs/disclosures/](https://github.com/vouch-protocol/vouch/tree/main/docs/disclosures). Each PAD documents an architectural pattern, threat model, or cryptographic primitive used in or adjacent to Vouch. The portfolio exists to establish prior art and prevent broad patents on Vouch's design decisions.`,
      },
    ],
  },

  // =====================================================================
  // FOR STANDARDS REVIEWERS
  // =====================================================================
  {
    id: 'standards',
    audience: 'Technical Foundations',
    title: 'What Vouch is built on',
    items: [
      {
        q: 'What specifications does Vouch build on?',
        a: `Vouch sits on top of well-known open specifications rather than inventing new cryptography:

- **Verifiable Credentials 2.0**, the JSON shape of a Vouch credential
- **Data Integrity proofs**, how the cryptographic signature is attached
- **Decentralized Identifiers (DIDs)**, how agents identify themselves
- **Controlled Identifiers / Multikey**, how public keys are encoded
- **BitstringStatusList**, how individual credentials get revoked
- **RFC 8785 (JCS)**, the rule for serializing JSON the same way every time
- **NIST FIPS 204 (ML-DSA)**, the post-quantum signature algorithm
- **C2PA**, Vouch acts as the identity layer for media provenance

Full mapping is documented in Appendix A of the Vouch Specification.`,
      },
      {
        q: 'How does Vouch fit with Verifiable Credentials 2.0?',
        a: `A Vouch credential **is** a Verifiable Credential. It uses the standard VC 2.0 JSON shape, the standard \`@context\`, the standard \`type\`, \`issuer\`, \`credentialSubject\`, and \`proof\` fields. The only Vouch-specific addition is an \`intent\` object inside \`credentialSubject\` that pins down the agent's action, target, and resource.

Any tool that knows how to read a VC can read a Vouch credential. It just will not know what to do with the \`intent\` field unless it has been taught.`,
      },
      {
        q: 'How does Vouch use Data Integrity proofs?',
        a: `Data Integrity is a way to attach a cryptographic signature to JSON in a readable form (instead of wrapping the whole credential in an opaque JWS blob).

Vouch uses two Data Integrity cryptosuites:

- \`eddsa-jcs-2022\`, the default classical Ed25519 cryptosuite
- \`mldsa44-jcs-2026\`, the post-quantum ML-DSA-44 cryptosuite (provisional identifier, being aligned with [Digital Bazaar's \`mldsa44-rdfc-2024-cryptosuite\`](https://github.com/digitalbazaar/mldsa44-rdfc-2024-cryptosuite) family's forthcoming JCS variant)

A credential can carry **one** proof (classical only) or **two** proofs (one of each cryptosuite, signing the same JCS-canonicalized bytes; this is the dual-proof post-quantum profile). The Data Integrity \`proof\` field is already specified as an array, so dual-signing is a natural use of existing primitives, no Vouch-specific composite cryptosuite required.`,
      },
      {
        q: 'How does Vouch use DIDs?',
        a: `Every agent and every signer in Vouch has a Decentralized Identifier. Two DID methods are supported:

- **did:web**, resolves over HTTPS to a DID Document at your domain. Good for organizations that own a domain.
- **did:key**, the public key is part of the identifier itself, no infrastructure needed. Good for ephemeral or fully decentralized agents.

Adding more DID methods (\`did:peer\`, \`did:dht\`, etc.) is straightforward when there is demand. Vouch is not opinionated about which method you use; it is opinionated that you use one.`,
      },
      {
        q: 'What is Multikey, and why does Vouch use it?',
        a: `Multikey is a format for encoding a public key with a small tag indicating which algorithm it belongs to. Vouch uses it because a single DID Document can then publish multiple keys side-by-side, one Ed25519 and one ML-DSA-44, for example, and verifiers pick whichever they support.

That is the trick behind the hybrid post-quantum profile: you can advertise both a classical key and a post-quantum key, sign credentials with both, and older verifiers (that only know Ed25519) still work fine. No flag day, no breakage.`,
      },
      {
        q: 'How does Vouch use BitstringStatusList for revocation?',
        a: `BitstringStatusList is a mechanism for revoking individual credentials without invalidating everything an issuer ever signed. The idea: publish a compressed bitstring at a stable URL where each bit corresponds to one credential. To revoke a credential, flip its bit and republish. To check status, verifiers fetch the list and look at the right bit.

Vouch ships a reference implementation across Python, TypeScript, and Go, with a published cross-language test vector. Most issuers will pair this with the older "revoke an entire DID" model. BitstringStatusList is for granular per-credential status; the DID-level registry is for "this key was compromised, kill everything from this identity."`,
      },
      {
        q: 'How does Vouch relate to ZCAP-LD?',
        a: `ZCAP-LD is another approach that tackles a similar problem: tracking who delegated which capability to whom. Vouch delegation chains share the same intent, but with different choices:

- Vouch uses **JCS** canonicalization (a deterministic byte-level recipe for serializing JSON); ZCAP-LD uses **JSON-LD** canonicalization.
- Vouch **requires** every link in a chain to name a specific resource; ZCAP-LD is more open-ended about scope.

The two can interoperate; a future revision of the Vouch Specification may spell out the mapping in more detail.`,
      },
      {
        q: 'Why not use IETF JWS / JOSE like JWTs do?',
        a: `JWS Compact Serialization wraps the entire credential in an opaque base64 blob. You cannot read it without decoding it first. Data Integrity keeps the credential as readable JSON and attaches the signature as a sibling object you can look at directly.

For agent actions where humans (auditors, regulators, your CFO) will read the credentials, readability matters. Earlier Vouch drafts experimented with JWS and moved away from it deliberately. JWS is still a valid signature envelope for VCs; Vouch just chose differently.`,
      },
      {
        q: 'How does Vouch fit with C2PA?',
        a: `C2PA is the right approach for "where did this photo, video, or audio come from?", provenance for media. Vouch is the right layer for "which AI agent signed this, and with whose permission?", identity for the signer.

The two complement each other. The Vouch repo ships a small Certificate Authority that issues Vouch-rooted C2PA certificates, so a C2PA manifest can be signed by a Vouch-identified agent and the whole chain checks out. The editor sits on C2PA technical committees and the Content Authenticity Initiative; this composition is intentional.`,
      },
      {
        q: 'How does Vouch fit with the Model Context Protocol (MCP)?',
        a: `Vouch is framework-agnostic, so it works with MCP servers and clients without anything special. An MCP tool-call envelope can carry a Vouch credential alongside the tool arguments. The MCP server (or a Vouch Shield middleware in front of it) verifies the credential before letting the tool run.

There is a reference MCP server integration in the Python SDK to make this concrete.`,
      },
      {
        q: 'What does "informative" vs "normative" mean in the Vouch spec?',
        a: `Standards-speak: **normative** means "if you say you implement this spec, you have to do X." **Informative** means "here is a useful description, but it is not part of the contract."

The Vouch credential layer (signing, verification, delegation, hybrid post-quantum, revocation) is normative. If you call yourself Vouch-compatible, you must implement these the same way as everyone else, byte for byte.

The State Verifiability layer (Heartbeat Protocol, validator quorum, behavioral attestation) was originally documented as informative, "here is the idea, implementations may vary." With the runtime now shipped in the Python SDK and being ported to TypeScript and Go, parts of that layer will become normative in a future revision of the Vouch Specification.`,
      },
      {
        q: 'Are there test vectors for cross-language interop?',
        a: `Yes. [test-vectors/](https://github.com/vouch-protocol/vouch/tree/main/test-vectors) has canonical test vectors for the hybrid post-quantum profile and for BitstringStatusList. Each comes with a deterministic generator script (\`generate.py\`) so anyone can regenerate it and audit the result.

Python, TypeScript, and Go all verify the same vectors. For BitstringStatusList specifically, Python and TypeScript produce byte-identical encoded output; Go produces a slightly different DEFLATE stream that decompresses to the same bitstring (semantically equivalent, which is what the the specification actually requires).`,
      },
      {
        q: 'What is on the Vouch roadmap?',
        a: `Tracked at [ROADMAP.md](https://github.com/vouch-protocol/vouch/blob/main/ROADMAP.md). Headline items:

- Promote the State Verifiability runtime to fully normative once TypeScript and Go ports of the Python implementation land.
- Expand the post-quantum profile from "hybrid Ed25519 + ML-DSA-44" to "pure ML-DSA" as NIST's CNSA 2.0 migration progresses and confidence in ML-DSA matures.
- Federate the credential trust state across multiple validator quorums for multi-tenant deployments.
- Propose the formal standards-track transition once we have enough implementer experience.
- Publish a systems whitepaper on [arXiv](https://arxiv.org) that synthesizes the full architecture, Vouch's cryptographic identity layer, Amnesia's deterministic policy layer, and the bridge between them, with empirical evaluation from six to twelve months of real-world usage data.`,
      },
    ],
  },

  // =====================================================================
  // POST-QUANTUM / HYBRID
  // =====================================================================
  {
    id: 'post-quantum',
    audience: 'Post-Quantum Security',
    title: 'Why the dual-proof profile, and how it works',
    items: [
      {
        q: 'Why does Vouch care about post-quantum?',
        a: `Eventually, a sufficiently powerful quantum computer will be able to break today's elliptic-curve signatures (Ed25519 included). We don't know when, but governments are already publishing migration deadlines (NIST CNSA 2.0, U.S. NSM-10). Even more importantly, an attacker can harvest signed credentials now and decrypt them later. So even before quantum computers exist, the smart move is to start signing things with both an old and a new algorithm so old signatures stay valid forever.`,
      },
      {
        q: 'How does the dual-proof post-quantum profile work?',
        a: `Each credential gets **two** Data Integrity proofs attached: one with the \`eddsa-jcs-2022\` cryptosuite (today's classical Ed25519 algorithm, fast) and one with the \`mldsa44-jcs-2026\` cryptosuite (the NIST-approved ML-DSA-44 post-quantum algorithm). Both proofs cover the same JSON bytes, and they ride together inside the credential's \`proof\` array.

A verifier can choose what to check:

- **Old verifier?** Validate the \`eddsa-jcs-2022\` proof. Ignore the rest. Works today.
- **Forward-looking verifier?** Validate the \`mldsa44-jcs-2026\` proof.
- **Belt-and-suspenders verifier?** Validate every proof in the array; fail if any one is wrong.

You can issue dual-proof credentials right now and they remain valid whether your verifier has been upgraded or not. No flag day, no mass migration, and no Vouch-specific composite cryptosuite to register, the dual-proof pattern uses standard W3C Data Integrity primitives.`,
      },
      {
        q: 'Is post-quantum signing slower?',
        a: `Yes, but barely. On a modern laptop, signing with Ed25519 takes about 50 microseconds; adding the ML-DSA-44 proof on top brings total signing time to around 3 milliseconds. Verification is similar. The bigger trade-off is size: a classical-only credential is ~700 bytes; a dual-proof credential is ~3.2 KB. You will want to send credentials in HTTP bodies rather than headers.`,
      },
      {
        q: 'How do I turn on the post-quantum profile?',
        a: `Just call the hybrid signer. The \`pqcrypto\` library is bundled with \`vouch-protocol\` by default (since v1.6.0), so a plain \`pip install vouch-protocol\` gives you everything needed:

\`\`\`python
from vouch import Signer, generate_identity

keys = generate_identity("agent.example.com")
signer = Signer(private_key=keys.private_key_jwk, did=keys.did)
signed = signer.sign_hybrid(intent={
  "action": "submit_claim", "target": "claim:HC-001",
  "resource": "https://insurance.example/claims/HC-001",
})
\`\`\`

TypeScript and Go work the same way. There is a full how-to in the [Guides](/help/#hybrid-pq) with code in all three languages.

The v1.6.x reference implementations emit the transitional composite proof (\`hybrid-eddsa-mldsa44-jcs-2026\`). The v1.7 rewrite emits two separate Data Integrity proofs on the same credential. The CLI flag stays the same.`,
        helpLinks: [{ label: 'Post-quantum how-to', href: '/help/#hybrid-pq' }],
      },
      {
        q: 'Which post-quantum algorithm does Vouch use?',
        a: `ML-DSA-44, the smallest parameter set of NIST FIPS 204 (the standard published in 2024). It gives roughly the same security level as Ed25519 but against quantum attacks. Larger ML-DSA parameter sets (ML-DSA-65, ML-DSA-87) aren't wired in yet but the format leaves room for them.`,
      },
    ],
  },

  // =====================================================================
  // VOUCH SHIELD
  // =====================================================================
  {
    id: 'shield',
    audience: 'Vouch Shield',
    title: 'Permission checks on every tool call',
    items: [
      {
        q: 'What is Vouch Shield?',
        a: `Vouch Shield is a small TypeScript library that sits between your AI agent and the tools it tries to call. Before any tool runs, Shield checks: is this call signed? Is the signer on my trust list? Does this DID have permission to call this specific tool? If anything is off, the call is blocked and logged. If everything checks out, the call runs.

\`npm install @vouch-protocol/shield\`. Source: [vouch-protocol/vouch-shield](https://github.com/vouch-protocol/vouch-shield).`,
        helpLinks: [{ label: 'Vouch Shield setup', href: '/help/#vouch-shield' }],
      },
      {
        q: 'How is Vouch Shield different from the Vouch Protocol itself?',
        a: `Think of Vouch Protocol as the passport: it defines how an agent proves who it is and what it intends to do. Vouch Shield is the customs officer: it inspects passports at the door and decides who gets through.

You can use Vouch Protocol without Shield (just sign and verify credentials in your own code). Shield is a convenience layer for teams who want the gatekeeping done for them.`,
      },
      {
        q: 'Where does Shield fit in my agent stack?',
        a: `Right before any tool actually executes. If your agent uses LangChain, CrewAI, AutoGen, MCP, or anything similar, Shield slots between "the LLM decided to call tool X" and "tool X actually runs." If the call doesn't pass Shield's checks, the tool never fires.`,
      },
    ],
  },

  // =====================================================================
  // TROUBLESHOOTING
  // =====================================================================
  {
    id: 'troubleshooting',
    audience: 'Troubleshooting',
    title: 'When things go wrong',
    items: [
      {
        q: 'My verifier rejects a credential signed in a different language. What is wrong?',
        a: `Most likely cause: the JCS canonicalization is not byte-identical. Check:

1. Are both ends on the same VC \`@context\` version? Mixing VC 1.1 and VC 2.0 contexts changes the canonical bytes.
2. Are timestamps in the canonical RFC 3339 form? Some implementations append \`+00:00\` instead of \`Z\` for UTC.
3. Are numbers serialized as JCS specifies? Trailing zeros, scientific notation, or non-canonical fractions break JCS.

Run the credential through the JCS reference test vectors at [test-vectors/](https://github.com/vouch-protocol/vouch/tree/main/test-vectors) to isolate the issue.`,
      },
      {
        q: 'My hybrid PQ signature is rejected by a verifier that accepts ed25519. What is wrong?',
        a: `Two possibilities depending on which version produced the credential:

- **v1.7+ dual-proof credentials:** the \`proof\` field is an array. A naive verifier might be reading only the first proof or expecting a single proof object. Make sure the verifier iterates the \`proof\` array and accepts any matching cryptosuite it recognizes (\`eddsa-jcs-2022\` is the classical one).
- **v1.6.x transitional composite credentials:** the \`proof.proofValue\` is a base58 concatenation of the Ed25519 signature (first 64 bytes) and the ML-DSA-44 signature (remaining ~2,420 bytes). A naive verifier that tries to validate the whole concatenated blob as Ed25519 will fail. Either upgrade the verifier to understand the \`hybrid-eddsa-mldsa44-jcs-2026\` composite, or have the issuer emit dual proofs (v1.7+) and treat one of them as the classical proof.`,
        meta: 'Specification §13.2',
      },
      {
        q: 'pip install vouch-protocol fails on pqcrypto. What do I do?',
        a: `\`pqcrypto\` (bundled with \`vouch-protocol\` since v1.6.0) ships prebuilt wheels for Python 3.9-3.13 on Linux x86_64/arm64, macOS x86_64/arm64, and Windows x86_64. On any of those, no compiler is needed.

If you are on a rare platform with no wheel, pip will fall back to building from source and you need a C toolchain:

- macOS: \`xcode-select --install\`
- Ubuntu/Debian: \`apt install build-essential\`
- Windows: install the "C++ build tools" workload from Visual Studio Installer

After that, \`pip install vouch-protocol\` succeeds.

Special case: if you genuinely cannot install \`pqcrypto\` at all (e.g. an extremely locked-down build environment), open a GitHub issue. A pure-Python ML-DSA-44 verifier (without signing) is on the roadmap for read-only environments.`,
      },
      {
        q: 'The Go sidecar refuses to start. What should I check?',
        a: `1. Is port 8877 (or your configured port) free? \`netstat -an | grep 8877\`
2. Is your DID resolvable? \`curl https://agent.example.com/.well-known/did.json\` should return your DID Document.
3. Is your private key correctly placed (env var, KMS config, or file)?

Run with \`--verbose\` for detailed startup logs.`,
      },
      {
        q: 'My credential has the right signature but verification still fails. Why?',
        a: `Common causes:

1. **DID resolution failed** - the verifier could not fetch the DID Document. Check network, TLS, and the \`.well-known/did.json\` URL.
2. **Key not in DID Document** - the signing key's verification-method ID is not in the DID Document's \`verificationMethod\` array.
3. **Credential expired** - \`validUntil\` is in the past.
4. **Nonce already seen** - the nonce store has a record of this credential's nonce.
5. **Revoked at the DID level** - the issuing DID is in the revocation registry.
6. **Revoked at the credential level** - the credential's \`credentialStatus\` bit is set in the fetched BitstringStatusListCredential.

The verifier returns structured reasons with a specific error code for each failure; check the code to see what failed.`,
      },
      {
        q: 'My verifier sees a credential as valid after I revoked it. What is going on?',
        a: `Almost always cache TTL. The \`StatusListFetcher\` caches the status list credential by URL for 5 minutes by default. A revocation made at the issuer becomes visible to verifiers only after the cache expires (or sooner if the verifier sets \`force_refresh=True\`).

Two operational adjustments:

1. **Shorten the TTL** if your latency-to-revocation requirement is tighter than 5 minutes (\`StatusListFetcher(cache_ttl_seconds=60)\`).
2. **Set \`force_refresh=True\` on verification failure** so a credential that suddenly fails for any reason triggers a fresh fetch of its status list. This is the recommended way to handle stale caches.

For coordinated revocations across a verifier fleet, share the cache (Redis) so an invalidation in one verifier becomes visible to all of them immediately.`,
        meta: 'Specification §11.2',
      },
      {
        q: 'How do I report a security issue?',
        a: `Privately via the process documented in [SECURITY.md](https://github.com/vouch-protocol/vouch/blob/main/SECURITY.md). Do not open public GitHub issues for vulnerabilities.`,
      },
      {
        q: 'Where can I ask questions?',
        a: `Three channels:

- [GitHub issues](https://github.com/vouch-protocol/vouch/issues) for specification or implementation questions
- [Discord](https://discord.gg/mMqx5cG9Y) for community discussion and quick questions`,
      },
    ],
  },

  // =====================================================================
  // AI ASSISTANTS (Claude Skill, OpenAI GPT, Gemini Gem, Vouch Assistant)
  // =====================================================================
  {
    id: 'ai-assistants',
    audience: 'For Developers',
    title: 'AI assistants that help you adopt Vouch',
    items: [
      {
        q: 'What are the four AI assistants?',
        a: `Four surfaces, one canonical knowledge base, pick whichever fits the tool you already use:

- **Claude Skill**: a drop-in skill for Claude Code (the CLI). Reads your local repo, edits files, runs commands. Best for hands-on integration work.
- **Vouch Assistant**: the chat helper on this website and the mobile app. Streams answers in your browser. Signs real Vouch credentials live so you can see the protocol in action.
- **OpenAI Custom GPT**: a configuration you paste into ChatGPT's GPT builder. Optional Actions integration lets the GPT call the hosted assistant to sign for you.
- **Gemini Gem**: a configuration for Google Gemini. Pairs naturally with Google Workspace (Docs, Sheets, Gmail, Search).

All four route to the same documentation, so the answers are consistent. Pick the one that fits your daily tool.`,
      },
      {
        q: 'How do I install the Claude Skill?',
        a: `Two ways, both inside Claude Code (the CLI).

**Marketplace (recommended).** Add the Vouch marketplace, then install the plugin:

\`\`\`bash
/plugin marketplace add vouch-protocol/vouch
/plugin install vouch-protocol@vouch
\`\`\`

Run \`/plugin\` to confirm it is enabled. The skill loads automatically when you mention Vouch.

**Manual.** Copy just the skill folder into your skills directory and restart Claude Code:

\`\`\`bash
cp -r ~/vouch-protocol/claude-skill/skills/vouch-protocol ~/.claude/skills/vouch-protocol
\`\`\`

\`\`\`powershell
Copy-Item -Recurse "$env:USERPROFILE\\vouch-protocol\\claude-skill\\skills\\vouch-protocol" "$env:USERPROFILE\\.claude\\skills\\vouch-protocol"
\`\`\`

Run \`/skills\` to confirm \`vouch-protocol\` is listed. Read the Guides section "Installing the Vouch Claude Skill" for screen-by-screen steps and triggers.`,
        helpLinks: [{ label: 'Installing the Claude Skill', href: '/help/#claude-skill-install' }],
      },
      {
        q: 'How do I build the OpenAI Custom GPT?',
        a: `The configuration is published in the repo at \`openai-gpt/\`. Open https://chatgpt.com/gpts/editor, click Create, switch to Configure, and paste each field from the matching file (\`name.txt\`, \`description.txt\`, \`instructions.md\`, \`conversation-starters.md\`). Upload all files from \`openai-gpt/knowledge/\` to the Knowledge section. Optionally add the Actions integration using \`actions.yaml\` and \`actions-auth.md\`.

We do not host a shared GPT because Custom GPTs are tied to one OpenAI account and cannot be forked. Every team builds and owns its own version.`,
        helpLinks: [{ label: 'Building the OpenAI Custom GPT', href: '/help/#openai-gpt-build' }],
      },
      {
        q: 'How do I create the Gemini Gem?',
        a: `Open https://gemini.google.com/gems/create. Click New Gem. Paste \`name.txt\`, \`description.txt\`, and \`instructions.md\` from \`gemini-gem/\` in the repo. Upload all files from \`gemini-gem/knowledge/\`. Add the prompts in \`examples.md\` as Examples. Save.

The Gem can use Google Workspace tools (drafting Docs, summarizing Sheets, composing Gmail). It always asks for confirmation before any Workspace write.`,
        helpLinks: [{ label: 'Creating the Gemini Gem', href: '/help/#gemini-gem-create' }],
      },
      {
        q: 'What is the Vouch Assistant on this website?',
        a: `The chat helper you can open from "Ask the assistant" in the nav or the floating tab in the bottom-right. It answers questions about the protocol grounded in the canonical docs, and signs real Vouch credentials when you ask it to do something with consequences. The signed credential appears in the chat as a card with the issuer DID, intent, cryptosuite, and a Show raw JSON toggle.

The assistant is open source under \`website-agent/\` in the repo. You can self-host it; the README has the local-run steps.`,
        helpLinks: [{ label: 'Running the Vouch Assistant locally', href: '/help/#assistant-local' }],
      },
      {
        q: 'Is the Vouch Assistant vulnerable to prompt injection?',
        a: `The LLM portion is vulnerable, like any LLM. Vouch's defense is defense-in-depth: the signing key lives in a sidecar process that the LLM cannot reach. Even a fully prompt-injected LLM cannot leak a key it never had, and the sidecar refuses to sign anything outside a small allow-list of action types. So the assistant can be tricked into saying weird things in chat, but cannot mint arbitrary credentials.`,
      },
      {
        q: 'Does the Vouch Assistant cost anything to run?',
        a: `On this website, no. We pay the inference cost. For embedded use in your own product, you run the open-source backend yourself and supply your own LLM API key (Anthropic, OpenAI, or Google Gemini). The signing side is free; only the LLM provider charges for inference.

The Claude Skill, OpenAI GPT, and Gemini Gem are the **Bring-Your-Own-LLM** route: they run inside your existing AI subscription, so we never see your queries and you never pay us for inference.`,
      },
      {
        q: 'Which LLM providers does the Vouch Assistant support?',
        a: `Anthropic Claude, OpenAI GPT, and Google Gemini. Configure with \`VOUCH_LLM_PROVIDER=anthropic|openai|gemini\` and the matching API key. The hosted instance on this website uses Gemini today.`,
      },
      {
        q: 'How do I keep the Claude Skill, GPT, and Gem up to date?',
        a: `**Claude Skill**: if you installed from the marketplace, run \`/plugin\` and update the Vouch plugin. If you copied it manually, \`git pull\` inside your clone and re-copy the skill folder. Restart Claude Code; no further action.

**OpenAI Custom GPT**: in the GPT editor, replace the knowledge files (the builder deduplicates by filename). Bump the version note in the Instructions if you forked them.

**Gemini Gem**: same pattern, re-upload the knowledge files in the Gem editor.

All three follow the protocol's release cadence. Subscribe to releases on https://github.com/vouch-protocol/vouch.`,
      },
      {
        q: 'Is there an llms.txt for AI coding assistants?',
        a: `Yes. [vouch-protocol.com/llms.txt](https://vouch-protocol.com/llms.txt) is a plain-text map of the protocol written for AI coding assistants. Point Cursor, Claude, Copilot, or any tool that reads \`llms.txt\` at it and the assistant gets the package names, the core APIs, and the canonical conventions without crawling the whole site. The Claude Skill, OpenAI Custom GPT, and Gemini Gem are the deeper, packaged version of the same knowledge.`,
      },
      {
        q: 'What is the Agent Trust Index?',
        a: `An open benchmark that scans public AI agents and scores one question for each: can this agent prove who it is? Not whether it is good or safe, just whether it has a cryptographic identity (a \`did:web\`) that resolves to a real public key. The first sweep, drawn from the public Model Context Protocol registry on 10 June 2026, scanned 11,680 agents. Only 157, about 1.3 percent, publish a resolvable identity, and 98.7 percent cannot prove who they are at all. See [the Index](/agent-trust-index/) and its [methodology](/agent-trust-index/methodology/).`,
      },
    ],
  },

  // =====================================================================
  // SIDECARS (Go production, Python+TS lightweight)
  // =====================================================================
  {
    id: 'sidecars',
    audience: 'For Operators',
    title: 'Which sidecar to run, and why',
    items: [
      {
        q: 'What is the Vouch sidecar?',
        a: `A separate process that holds the agent's signing key. The LLM-running process calls it over HTTP for signatures. Because the key lives in a different process from the LLM, prompt injection cannot exfiltrate what is not there.`,
      },
      {
        q: 'Vouch ships sidecars in Go, Python, and TypeScript. Which one should I run?',
        a: `They are tiered. Pick by use case, not by language preference:

| Tier | Language | Use case |
|---|---|---|
| Production | **Go** | Real deployments. Small static binary, KMS / HSM keys, FIPS path in Pro tier. |
| Lightweight | **Python** | Self-hosted, non-regulated stacks already in Python. File or env keys. |
| Lightweight | **TypeScript** | Self-hosted Node stacks. File or env keys. |
| Dev | **Python \`dev_sidecar\`** | Local iteration with an ephemeral key. Never for production. |

Rule of thumb: if your auditor will ask about the sidecar, run the Go one. For everything else, pick the language your stack already uses.`,
        helpLinks: [{ label: 'Choosing a sidecar tier', href: '/help/#sidecar-tiers' }],
      },
      {
        q: 'Why are the Python and TypeScript sidecars minimal?',
        a: `The sidecar is security-critical, so smaller code surface is safer. Python and TS sidecars implement the bare minimum to be useful (sign intents with Ed25519, return the credential) and intentionally leave out hybrid post-quantum, KMS integration, sensitive-mode JWE wrapping, Heartbeat validation, and multi-tenancy. When you need those, switch to the Go sidecar. That switch is the design intent, not a workaround.`,
      },
      {
        q: 'How do I pick between Python and TypeScript for the lightweight tier?',
        a: `Pick whichever runtime your existing application uses. There is no protocol-level difference; both pass the same contract test suite and emit semantically equivalent credentials.`,
      },
      {
        q: 'Do all three sidecars produce byte-identical credentials?',
        a: `Credentials are **semantically equivalent** across all three (same VC shape, same \`eddsa-jcs-2022\` cryptosuite, same JCS canonicalization). A cross-language contract test suite enforces this on every release. The bytes are identical when the inputs are identical.`,
      },
      {
        q: 'Can the sidecar run as a serverless function (Lambda, Cloud Run, Fly Machines)?',
        a: `Yes for the Go sidecar, which is a static binary and starts in milliseconds. The Python and TS sidecars work as serverless too but their cold-start latency makes them less suited to high-frequency signing. For typical agent workloads (one credential per minute), any of them is fine.`,
      },
    ],
  },

  // =====================================================================
  // COMMUNITY AND CONTRIBUTING
  // =====================================================================
  {
    id: 'community',
    audience: 'Community & Contributing',
    title: 'Contributing and the Verified Contributor badge',
    items: [
      {
        q: 'How do I become a Vouch Verified Contributor?',
        a: `Land a merged pull request on the [repository](https://github.com/vouch-protocol/vouch). When it merges, an automated workflow mints a signed Vouch Verified Contributor credential for you, publishes a certificate page at \`vouch-protocol.com/c/<your-handle>/<pr>\`, adds you to the [contributors page](https://vouch-protocol.com/contributors), and posts a comment on your pull request with the badge and the full credential.

New to the project? Start with a [good first issue](https://github.com/vouch-protocol/vouch/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22). The badge is offered, never required.`,
        helpLinks: [{ label: 'Become a Vouch Verified Contributor', href: '/help/#verified-contributor' }],
      },
      {
        q: 'Is the contributor badge a real credential or an image?',
        a: `It is a real Verifiable Credential, signed with the same \`eddsa-jcs-2022\` cryptosuite every Vouch SDK uses. It is issued by \`did:web:vouch-protocol.com:contributors\` and chained back to the project root identity \`did:web:vouch-protocol.com\`, so anyone can verify it with the Vouch verifier or an SDK. The subject is the author of the merged commits, so credit stays correct even when a maintainer relays a contribution for someone else.`,
      },
    ],
  },

  // =====================================================================
  // USING THIS SITE
  // =====================================================================
  {
    id: 'using-this-site',
    audience: 'About this site',
    title: 'Using this site',
    items: [
      {
        q: 'How do I switch between light and dark mode?',
        a: `Click the sun (or moon) icon in the top navigation. It flips between Light and Dark on each click. Your choice is remembered across visits and pages.

The site defaults to Light mode. If you want Dark, click the sun once.`,
      },
      {
        q: 'Where did the blog go?',
        a: `It is back. Open the **Blog** link in the top nav. The nine articles were briefly off-site after the website redesign; all are now restored with the same content and updated styling.`,
      },
      {
        q: 'How do I copy code from the snippets on this site?',
        a: `Every code block has a small burgundy clipboard icon in the top-right corner. Click it and the entire snippet is copied to your clipboard. The icon briefly turns into a green checkmark to confirm.

This works on the homepage, in every guide, in blog posts, and inside the Vouch Assistant's responses.`,
      },
      {
        q: 'How do I open the Vouch Assistant?',
        a: `Three ways:

1. Click **Ask the assistant** in the top navigation.
2. Click the small bordered tab labeled "ASK THE ASSISTANT" at the bottom-right of the page.
3. On mobile, tap "Ask the assistant" in the menu.

All three open the same slide-in panel. Inside the panel, use the diagonal-arrows icon in the panel's header to toggle between side-panel and full-screen mode.`,
      },
      {
        q: 'The assistant gave me an answer that is wrong. What do I do?',
        a: `Three things help:

1. **Verify the answer against the canonical docs**: every answer carries a disclaimer with links to the guides, FAQ, and the source on GitHub.
2. **Report the bad answer** at [https://github.com/vouch-protocol/vouch/issues](https://github.com/vouch-protocol/vouch/issues). Paste the question and the response. We update the knowledge base.
3. **For protocol questions**, the source on GitHub is the ground truth. The assistant is grounded in the docs but is still an AI and can be wrong.`,
      },
      {
        q: 'Why does the assistant ask before doing anything?',
        a: `Because real actions go through a signing gate. The assistant signs a Vouch credential for every action it takes on your behalf, and shows you the credential before performing the action. You can see exactly what is being authorized. If anything looks wrong, refuse the confirmation and the action does not happen.`,
      },
      {
        q: 'How do I jump back to the top of a long page?',
        a: `After you scroll a bit, a small upward-arrow button appears in the bottom-left corner. Click it. Smooth scroll back to the top.`,
      },
    ],
  },
];
