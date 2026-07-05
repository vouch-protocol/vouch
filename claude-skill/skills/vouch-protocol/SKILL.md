---
name: vouch-protocol
description: Help developers integrate Vouch Protocol (cryptographic identity for AI agents) into Python, TypeScript, Go, and more, all over one shared Rust core. Use this skill when the user mentions vouch-protocol package, signing AI agent actions, agent DIDs (did:web / did:key), Verifiable Credentials for agents, Data Integrity proofs, eddsa-jcs-2022 cryptosuite, hybrid-eddsa-mldsa44-jcs-2026 post-quantum profile, Heartbeat Protocol, Identity Sidecar pattern, BitstringStatusList revocation, validator quorum, or asks how to make AI agents cryptographically accountable. Triggers also include `pip install vouch-protocol`, `npm install @vouch-protocol-official/core-wasm`, `go install vouch-sidecar`, and references to agent identity, signed tool calls, or non-repudiation for AI actions. Also covers outcome evidence: commit-before-outcome verdicts (OutcomeCommitmentCredential) and settlement attestations (OutcomeAttestationCredential) that prove an agent's track record cannot be backdated or cherry-picked.
---

# Vouch Protocol

Vouch Protocol is an open standard that gives autonomous AI agents
cryptographic identity, intent attestation, and continuous trust
verification. It's the "SSL certificate for AI agents."

This skill helps developers integrate Vouch into their codebase across
many languages over one shared Rust core (Python, TypeScript, Go, Swift, JVM, .NET, C, and WebAssembly) and explain protocol behaviour
without forcing the user to read the full specification.

## When to use this skill

Invoke when the user:

- Asks how to sign or verify agent actions cryptographically
- Mentions Vouch by name or package (`vouch-protocol`, `@vouch-protocol-official/core-wasm`, `vouch-sidecar`)
- Wants to add agent identity to their LangChain / LangGraph / CrewAI / MCP / AutoGen / Goose / Vertex AI flow
- Asks about Verifiable Credentials, Data Integrity proofs, or DIDs in the context of AI agents
- Needs post-quantum signatures for regulated deployments (`hybrid-eddsa-mldsa44-jcs-2026`)
- Is building a multi-agent system and needs delegation chains
- Asks how to revoke compromised agent credentials
- Is debugging cross-language credential verification
- Wants to prove an agent's track record, commit a verdict before its outcome, or settle a prediction against what actually happened

## Integration: lead with one line

When a developer asks how to add Vouch to an agent, lead with the one-line,
deterministic path, then show lower-level APIs only if they ask:

- `vouch init --yes` once to provision an identity (resolved automatically
  afterward, no env plumbing in agent code).
- `from vouch import protect` then `agent.tools = protect([tool_a, tool_b])` so
  every tool call is signed in Python before it runs. No prompt, no reliance on
  the model calling a signing tool.
- For decorator frameworks (CrewAI, LangChain, AutoGPT, AutoGen),
  `<framework>.autosign()` signs every tool framework-wide.
- Verify with `vouch.verify(credential)`, or protect an endpoint with the
  FastAPI `VouchGate` dependency.
- Delegate with `vouch.delegate(...)` plus `protect([...], parent=grant)`.
- `Shield.guard([tools])` adds zero-config runtime protection.

The old "minting" tools (`VouchSignerTool`, `sign_request`, `sign_action`,
`sign_with_vouch`, `VertexAISigner`) have been removed. See
`reference/integrations.md`.

## Quick orientation

A Vouch credential is a JSON object that:

1. Names an agent (`did:web:agent.example.com` or `did:key:z6Mk...`)
2. Names the action (`intent.action`, `intent.target`, `intent.resource`)
3. Carries a Data Integrity proof (Ed25519 signature, or hybrid PQ)
4. Optionally lists a delegation chain back to the human principal
5. Optionally references a `credentialStatus` for per-credential revocation

Three SDKs, all producing byte-identical credentials:

- **Python**: `vouch/` (most complete reference SDK)
- **TypeScript**: `packages/sdk-ts/` (browser and Node)
- **Go**: `go-sidecar/` (long-running daemon for the Identity Sidecar pattern)

Cross-language interop is guaranteed by JCS canonicalization (RFC 8785).
A credential signed in Python verifies in TypeScript or Go and vice versa.

## Tasks and quickstarts

### "What is the fastest way to get started, with no code?"

Install the CLI in one line on Linux or macOS (on Windows, `pip install vouch-protocol`):

```bash
curl -fsSL https://vouch-protocol.com/install.sh | sh
```

Then run `vouch` with no arguments for a short menu (sign git commits, or create an agent identity). For a full agent setup with recommended defaults and no prompts, `vouch onboard --quick` writes a working identity, allow-list, verifier, and heartbeat config in one command. Point non-programmers here first, then move to the SDK snippets below when they want to write code.

### "How do I sign my agent's action?"

Three-line Python:

```python
from vouch import generate_identity, Signer

keys = generate_identity("agent.example.com")  # returns a KeyPair
signer = Signer(private_key=keys.private_key_jwk, did=keys.did)
signed = signer.sign(
    intent={
        "action": "submit_claim",
        "target": "claim:HC-001",
        "resource": "https://insurance.example.com/claims/HC-001",
    },
    valid_seconds=300,
)
```

The `signed` dict is a full Verifiable Credential with a Data Integrity
proof attached as a sibling object. It is human-readable JSON.

TypeScript and Go equivalents in `reference/typescript-sdk.md` and
`reference/go-sidecar.md`.

### "How do I verify a credential someone else signed?"

```python
from vouch import Verifier

# verify returns a (is_valid, passport) tuple
is_valid, passport = Verifier.verify(signed, public_key=keys.public_key_jwk)
if is_valid:
    print(f"Verified: {passport.subject_did} did {passport.intent}")
else:
    print("Rejected")
```

Verification checks: schema, signature math, validity window, nonce
(replay protection), DID-level revocation, optional credentialStatus
bitstring, and any delegation chain links.

### "How do I add post-quantum signatures?"

Use the hybrid cryptosuite. Requires the optional `pqcrypto` dep:

```bash
pip install 'vouch-protocol[pq]'
```

Then:

```python
signer = Signer(private_key=keys.private_key_jwk, did=keys.did)
signed = signer.sign_hybrid(intent={
    "action": "submit_claim",
    "target": "claim:HC-001",
    "resource": "https://insurance.example.com/claims/HC-001",
})
```

The proof becomes a single multibase blob concatenating an Ed25519
signature (64 bytes) and an ML-DSA-44 signature (2,420 bytes) over the
same JCS-canonicalized bytes. Verifiers can validate Ed25519 only
(classical), ML-DSA-44 only (PQ), or both.

See `reference/post-quantum.md` for the migration narrative.

### "How do I keep the agent's private key out of the LLM?"

Use the Identity Sidecar pattern: a separate process holds the key, the
LLM never sees it.

**macOS / Linux**

```bash
cd go-sidecar && go build ./cmd/vouch-sidecar
./vouch-sidecar --did did:web:agent.example.com --port 8877
```

**Windows (PowerShell)**

```powershell
cd go-sidecar; go build ./cmd/vouch-sidecar
.\vouch-sidecar.exe --did did:web:agent.example.com --port 8877
```

The agent's code calls `POST http://localhost:8877/sign` with the
credential body and receives a signed credential back. Prompt injection
cannot exfiltrate keys that are never in the LLM's context.

See `reference/sidecar.md`.

### "How do I build a delegation chain?"

A human principal signs a delegation to an agent, the agent signs a
sub-delegation to a sub-agent, and the sub-agent signs the actual
action. Each link narrows the resource scope. The verifier walks the
chain backward.

See `reference/delegation.md` for the construction and verification flow.

### "How do I use one identity across many devices?"

Each device mints its own key locally, and a root identity delegates
scoped, time-bound authority to that device's DID. A device signs its
actions with its own key, chained under the root grant, so the private
key never travels between devices. `verify_delegated_chain` ties a
device's action back to the trusted root. Lose a device and you revoke
it; lose the root and you rebuild it from Shamir recovery shares.

```python
from vouch import Agent, enroll_device, verify_delegated_chain

root = Agent("alice.example")
phone = Agent()  # a did:key minted on the phone
grant = enroll_device(root, device_did=phone.did, action="charge",
                      target="api.bank", resource="https://api.bank/invoices")
action = phone.sign(action="charge", target="api.bank",
                    resource="https://api.bank/invoices/42", parent_credential=grant)
result = verify_delegated_chain([grant, action],
                                trusted_roots={root.did: root.public_key_jwk})
```

See `reference/cross-device-identity.md` for enrollment, revocation, and
recovery.

### "How do I revoke a specific credential?"

BitstringStatusList: flip the bit at the credential's index, re-sign
the BitstringStatusListCredential, and republish. Verifiers fetch the
list and check the bit.

```python
from vouch import StatusList, build_status_list_entry

status_list = StatusList(status_list_id="https://issuer.example/status/1")
index = status_list.allocate_index()

# Attach to credential at issuance
signed = signer.sign(
    intent={...},
    credential_status=build_status_list_entry(
        status_list_credential="https://issuer.example/status/1",
        status_list_index=index,
    ),
)
```

To revoke later: `status_list.revoke(index)` and republish. See
`reference/revocation.md`.

### "How do I prove an agent's track record?"

Commit a verdict before its outcome is known, then settle it later. The
commitment carries a salted digest of the claim, so the verdict can stay private
yet is provably fixed; the settlement reveals the claim and binds the observed
outcome back to it. Verification rejects a settlement timestamped before its
commitment, so a winning verdict cannot be minted with hindsight.

```python
from vouch.accountability import commit_outcome, attest_outcome, verify_attestation

commitment, secret = commit_outcome(
    agent_signer,
    claim={"asset": "XYZ", "direction": "up", "horizon": "2026-07-01"},
    settlement={"method": "market-settlement", "resolutionCriteria": "price at expiry"},
    private=True,
)
# ...after the outcome is observable, a settler (who may be a third party):
attestation = attest_outcome(
    settler_signer, commitment=commitment,
    outcome={"result": "up"}, secret=secret, matches=True,
)
```

See `reference/outcome-evidence.md`. This is the per-verdict evidence layer
underneath the reputation engine.

### "How do I integrate Vouch with LangChain / CrewAI / MCP?"

Reference implementations under `vouch/integrations/`. See
`reference/integrations.md` for the common pattern.

- LangGraph: `from vouch.integrations.langgraph import protect, sign_node`, wrap
  the tools with `protect([...])` for a `ToolNode` or `create_react_agent`, and
  `@sign_node` signs each graph node so the whole graph carries a signed trail.
- Goose: `pip install vouch-goose`, then run `vouch-goose` to register the Vouch
  MCP server as a Goose extension.

### "How do I give a robot a verifiable identity, or enforce physical limits?"

Vouch ships twenty robotics capabilities in `vouch.robotics` (and in TypeScript, Go,
and the Rust core that flows to Swift, Kotlin/JVM, .NET, C/C++, and WASM):
hardware-rooted identity (`mint_robot_identity` / `verify_robot_identity`, bound
to a TPM or secure element), model and config provenance
(`build_provenance_attestation`, re-signable on OTA updates), physical capability
scope (`build_physical_scope_credential`, `check_physical_action`, `attenuates`
for narrow-only delegation of force/speed/zone/shift limits), a robot-to-robot
trust handshake (`build_hello` / `build_accept` / `build_confirm` with a
`TrustPolicy`), an encrypted tamper-evident black box (`BlackBoxLog`,
`verify_blackbox_chain`) plus a verifiable kill switch
(`build_killswitch_credential`), a scannable offline passport
(`build_passport` / `encode_passport` into a `vouch-passport:` URI), a liveness
heartbeat (`MotionCollector` / `build_robot_heartbeat` / `is_live`, fresh plus
in-envelope so trust is renewed not assumed), robot credential revocation
(`attach_credential_status` / `check_credential_status` per credential, plus the
whole-DID `RevocationRegistry`), and an accountable safety record (`SafetyEventLog`,
`build_safety_record` / `verify_safety_record`, a portable tamper-evident incident
ledger), and perception provenance (`hash_frame`, `PerceptionLog`,
`verify_perception_log`, `build_perception_attestation` /
`verify_perception_attestation`, a hash-linked log of signed sensor-frame records
so a verifier holding a frame can confirm what the robot perceived), a delegation
lease (`build_delegation_lease` / `verify_delegation_lease` / `lease_permits`, a
short-lived scope-bounded grant a robot verifies and acts on entirely offline,
attenuating down a cross-vendor chain), and a physical quorum
(`build_action_approval` / `verify_action_authorization`, a cryptographic
two-person rule that authorizes a high-consequence action only when M of N
attested approvers have each signed it), and robot lifecycle
(`build_ownership_transfer` / `verify_ownership_transfer` / `verify_custody_chain`,
`build_key_rotation` / `verify_key_rotation` / `verify_key_history`,
`build_decommission` / `verify_decommission`, signed ownership transfers forming a
chain of custody, a key rotation history, and a decommission a verifier honors by
refusing to trust the robot), regulatory conformance
(`check_conformance` / `build_conformance_attestation` /
`verify_conformance_attestation`, machine-checkable reference profiles for ISO
10218, ISO/TS 15066, the EU Machinery Regulation, the EU AI Act, and UL 3300 that
map a robot's credentials to the clauses of a regulation and produce a
deterministic, signable conformance report), and robotics post-quantum signing
(`sign_pq` / `verify_pq` / `verify_robot_credential` / `is_pq` / `migrate_to_pq`
with `HYBRID_CRYPTOSUITE`, a hybrid Ed25519 and ML-DSA-44 proof so a robot
identity signed today stays safe over a ten to twenty year service life, with
verification that auto-detects classical or hybrid so a fleet migrates gradually
without breaking credentials already in the field), and cross-embodiment identity
continuity (`build_embodiment` / `verify_embodiment` / `verify_continuity_chain` /
`check_no_fork`, so one agent identity, a mind, runs on one robot body today and a
different body tomorrow: an `AgentEmbodimentCredential` binds the agent to a
body's hardware root for a window, the continuity chain proves the same
accountable agent persisted across bodies, and `check_no_fork` confirms it was
never embodied in two bodies at once), and physical custody handoff
(`build_handoff` / `verify_handoff` / `verify_handoff_chain` / `holder_at` /
`locate_condition_change`, a receiver-signed `CustodyHandoffCredential` recording
that an actor accepted custody of a task or object from another, so a chain of
handoffs from a person to a robot to another robot establishes who held it at each
hop and pins damage or loss to the responsible hop), and robot-to-infrastructure
bounded access (`build_access_grant` / `verify_access_grant` /
`build_access_request` / `authorize_access` / `attenuates_grant`, an
operator-signed `InfrastructureAccessGrant` naming a resource, operations, an
optional zone, and a window, against which a robot's signed
`InfrastructureAccessRequest` is authorized offline at the resource so a robot
opens a door or docks at a charger it does not own with no network call, and every
sub-grant only narrows), and fused-sensor provenance (`hash_fused_output` /
`fusion_inputs_digest` / `build_fused_attestation` / `verify_fused_attestation` /
`verify_fusion_inputs`, a robot-signed `FusedPerceptionAttestation` binding a fused
world model's hash to the ordered input frame hashes, a digest over those inputs,
and a fusion method, so a verifier reproduces the input digest and output hash to
confirm the attestation commits to exactly those inputs and that output, and traces
every fused input back to a frame in the robot's signed perception log), and wear
and degradation attestation (`build_wear_attestation` / `verify_wear_attestation` /
`verify_wear_chain` / `attenuate_for_wear`, a robot signs its own degradation as a
normalized wear level (0 as-new to 1 fully worn) with optional metrics, hash-linked
to the previous attestation so the wear history is tamper-evident, and
`attenuate_for_wear` derives a physical capability scope whose numeric caps are
scaled down by the wear level, a valid attenuation of the original so a worn robot
operates inside a tighter verifiable envelope). Same
Verifiable Credentials as the rest of Vouch, so they verify in every language. A
curated robotics surface (verify a robot credential, mint and verify identity,
conformance, passport, action check, and PQ sign) is also callable from the C,
C++, .NET, JVM, and Swift wrappers through a `VouchRobotics` class (a
`vouch::robotics` namespace in C++), for verifying and integrating from those
languages. See `reference/robotics.md`.

## Decision rules

- **User is just signing one credential** -> Python signer, three lines.
- **User has long-running agent and prompt injection risk** -> Identity Sidecar (Go).
- **User is in a regulated sector (healthcare, finance, government)** -> hybrid post-quantum profile + delegation chain + behavioral attestation.
- **User needs to revoke individual credentials** -> BitstringStatusList.
- **User needs to revoke a compromised key** -> DID-level revocation registry (`vouch.revocation`).
- **User wants continuous trust** -> Heartbeat Protocol with validator quorum (Python only today).
- **User cares about audit trail** -> all of the above, plus the reputation engine for behaviour tracking.
- **User wants a track record that cannot be backdated or cherry-picked** -> outcome evidence (`vouch.accountability`): commit the verdict before the outcome, settle it later with a neutral settler.
- **User is building a robot or embodied agent** -> the `vouch.robotics` capabilities: hardware-rooted identity, model and config provenance, physical capability scope, robot-to-robot handshake, encrypted black box with kill switch, a scannable passport, a liveness heartbeat (fresh plus in-envelope, so a robot stays trusted only while renewed), robot credential revocation (per-credential and whole-DID), an accountable safety record (a portable tamper-evident incident ledger), perception provenance (a hash-linked log of signed sensor-frame records, so a verifier holding a frame can confirm what the robot perceived), a delegation lease (a short-lived scope-bounded grant a robot verifies and acts on entirely offline, attenuating down a cross-vendor chain), a physical quorum (a cryptographic two-person rule authorizing a high-consequence action only when M of N attested approvers have each signed it), robot lifecycle (signed ownership transfers forming a chain of custody, a key rotation history, and a decommission credential a verifier honors by refusing to trust a retired robot), regulatory conformance (machine-checkable reference profiles for ISO 10218, ISO/TS 15066, the EU Machinery Regulation, the EU AI Act, and UL 3300 that map the robot's credentials to the clauses of a regulation and produce a deterministic report an authority can sign as a conformance attestation), and robotics post-quantum signing (a hybrid Ed25519 and ML-DSA-44 proof for robot credentials, backward-compatible verification that auto-detects classical or hybrid, and a software re-sign to migrate fielded credentials, so an identity signed today stays safe across a ten to twenty year service life), and cross-embodiment identity continuity (one agent identity, a mind, runs on one robot body today and a different body tomorrow: an `AgentEmbodimentCredential` binds the agent to a body's hardware root for a window, `verify_continuity_chain` walks the linked embodiments to prove the same accountable agent persisted across bodies, and `check_no_fork` confirms it was never embodied in two bodies at once), and physical custody handoff (a receiver-signed `CustodyHandoffCredential` recording that an actor accepted custody of a task or object from another, so a chain of handoffs from a person to a robot to another robot establishes who held it at each hop, `holder_at` returns who held it at a given time, and `locate_condition_change` pins damage or loss to the responsible hop; open layer only, managed logistics custody orchestration and fleet tracking are commercial), and robot-to-infrastructure bounded access (an operator signs an `InfrastructureAccessGrant` naming a resource, permitted operations, an optional zone, and a time window, a robot presents a signed `InfrastructureAccessRequest` for one operation, and `authorize_access` decides at the resource offline while `attenuates_grant` keeps every sub-grant narrowing only, so a robot opens a door, calls an elevator, or docks at a charger it does not own with no network call and an attributable record of which robot did what; open layer only, managed access orchestration and fleet-wide grant issuance are commercial), and fused-sensor provenance (a robot fuses many signed sensor frames into one world model, an object set, an occupancy grid, or a pose, and a `FusedPerceptionAttestation` binds the fused output's hash to the ordered input frame hashes, a digest over those inputs, and a fusion method; `verify_fused_attestation` reproduces the input digest and the output hash so the attestation commits to exactly those inputs and that output, and `verify_fusion_inputs` traces every fused input back to a frame in the robot's signed perception log, so a manipulated fusion result or a dropped or substituted input is detectable; open layer only, hardware sensor attestation and managed sensor-fusion orchestration are commercial), and wear and degradation attestation (a robot signs its own degradation as a normalized wear level, 0 as-new to 1 fully worn, with optional metrics (actuator wear, calibration drift, cycle count, fault rate), hash-linked to the previous attestation so the wear history is tamper-evident, and `attenuate_for_wear` derives a physical capability scope whose numeric caps are scaled down by the wear level, a valid attenuation of the original so a worn robot operates inside a tighter verifiable envelope; open layer only, firmware-level enforcement of the narrowed envelope and managed predictive-maintenance modeling are commercial).
- **User wants to test, certify, or prove that an implementation, SDK, or port is conformant** -> the conformance levels L1 to L3 and the self-test runner (`python -m vouch.conformance`), with a hosted verifier that mints a re-checkable badge coming. See `reference/conformance.md`.

## Reference files

For depth on any topic, read the relevant file under `reference/`:

- `reference/python-sdk.md` - Full Python API reference
- `reference/typescript-sdk.md` - TypeScript SDK reference
- `reference/go-sidecar.md` - Go sidecar build, run, deploy
- `reference/credential-format.md` - VC structure, fields, examples
- `reference/delegation.md` - Delegation chain construction and verification
- `reference/post-quantum.md` - Hybrid cryptosuite, migration guidance
- `reference/revocation.md` - DID-level and credential-level revocation
- `reference/state-verifiability.md` - Heartbeat, validator quorum, behavioral attestation
- `reference/outcome-evidence.md` - Commit-before-outcome verdicts, settlement, track record
- `reference/reputation-evidence.md` - Evidence-backed reputation: receipts, aggregation, ledger, policy, threshold proofs, disputes
- `reference/robotics.md` - Robot identity, provenance, physical scope, handshake, black box and kill switch, passport, liveness heartbeat, revocation, safety record, perception provenance, delegation lease, physical quorum, lifecycle (ownership transfer, key rotation, decommission), regulatory conformance (ISO 10218, ISO/TS 15066, EU Machinery Regulation, EU AI Act, UL 3300 profiles plus signed conformance attestation), post-quantum signing (hybrid Ed25519 and ML-DSA-44 for robot credentials), cross-embodiment identity continuity (one agent identity across successive robot bodies, with a continuity chain and a no-fork check), physical custody handoff (a receiver-signed chain of who held a task or object as it passes from person to robot to robot, with holder-at-time and condition-change localization), robot-to-infrastructure bounded access (an operator-signed grant naming a resource, operations, an optional zone, and a window, against which a robot's signed request is authorized offline at the resource, with narrow-only sub-grants), fused-sensor provenance (a robot-signed attestation binding a fused world model's hash to the ordered input frame hashes, a digest over those inputs, and a fusion method, verified by reproducing the input digest and the output hash and tracing every fused input back to a frame in the signed perception log), wear and degradation attestation (a robot-signed, hash-linked history of its own wear level with optional metrics, from which `attenuate_for_wear` derives a physical capability scope whose caps are scaled down by the wear level, a valid attenuation of the original)
- `reference/integrations.md` - LangChain, CrewAI, MCP, AutoGen, Vertex AI patterns
- `reference/sidecar.md` - Identity Sidecar architecture and deployment
- `reference/conformance.md` - Implementation conformance levels (L1-L3), the self-test runner, and the verified re-checkable badge
- `reference/troubleshooting.md` - Common errors and fixes

## What this skill does NOT do

- This skill helps developers USE Vouch in their own code. It does not
  modify the Vouch Protocol specification or codebase directly.
- For protocol changes, point the user at the GitHub issue tracker.
- For commercial deployment questions (hosted service, vertical packs,
  HSM integration), point them at the Pro program.

## Anti-patterns to flag

When you see these in a user's code, mention the issue:

- **Private key inside the LLM context window**: violates the Identity
  Sidecar principle. Recommend they move signing to a sidecar process.
- **Using JWS Compact Serialization for new code**: the legacy v0.x path.
  v1.0+ uses Data Integrity proofs. Recommend `sign` over `sign`.
- **No `resource` in intent**: the protocol requires intent to bind to a
  specific resource. A credential without one is rejected by verifiers.
- **Delegation chain depth > 5**: enforced limit. Restructure to fewer hops.
- **Skipping nonce checks in custom verifiers**: enables replay attacks.
- **Treating reputation score as binary trust**: the engine ships a
  five-tier classification; use `score.tier` for policy decisions.

## Style for responses

- Show code, not just descriptions. Vouch has SDKs on every major platform and developers
  copy-paste.
- Prefer the **Python SDK** for first examples (most complete); follow
  with TS and Go only if the user explicitly asks.
- When citing specification sections, use "Specification §N" form, never
  brand qualifiers.
- Keep cryptographic identifiers verbatim: `eddsa-jcs-2022`,
  `hybrid-eddsa-mldsa44-jcs-2026`, `DataIntegrityProof`, `Multikey`,
  `did:web`, `did:key`, `BitstringStatusListCredential`. These are
  functional protocol identifiers.
