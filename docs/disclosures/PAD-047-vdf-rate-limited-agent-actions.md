# PAD-047: Verifiable Delay Functions for Cryptographic Rate-Limiting of Autonomous Agent Actions

**Identifier:** PAD-047  
**Title:** Method for Cryptographically Enforcing Minimum Elapsed Time Between High-Stakes Autonomous Agent Actions Using Verifiable Delay Functions  
**Publication Date:** April 29, 2026  
**Prior Art Effective Date:** April 29, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** AI Safety / Agent Governance / Verifiable Delay Functions / Runaway Loop Prevention / Autonomous Agent Containment  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-016 (Dynamic Credential Renewal), PAD-020 (Ratchet Lock Protocol), PAD-022 (Swarm Limits Protocol), PAD-039 (JCS Multi-Party Trust State), PAD-042 (Metadata Schema)  

---

## 1. Abstract

A method for cryptographically enforcing a **minimum elapsed wall-clock
time** between high-stakes autonomous agent actions, using a
Verifiable Delay Function (VDF) as a cryptographic proof-of-elapsed-
time. An agent issuing a high-stakes Vouch Credential MUST include a
VDF output computed since the agent's last credential issued at the
same risk tier; verifiers reject credentials whose VDF output is
inconsistent with the claimed elapsed time. This prevents runaway
agent loops, denial-of-service amplification, and certain classes of
adversarial agent behavior, in a manner that is **independent of any
clock authority** the agent or verifier might trust.

The novel element is the deliberate use of a VDF (an inherently
sequential computation that cannot be parallelized) as the rate-
limiting primitive. Unlike rate limits enforced by trusted
timestamps, NTP-synchronized clocks, or the agent's local time
source, a VDF-based rate limit is cryptographically self-evidencing:
the proof of elapsed time is the output of a computation that
provably could not have completed faster than its target duration.

## 2. Problem Statement

Current rate-limiting in agent identity systems relies on one of:

- **Verifier-side rate limits**: the API server tracks request
  frequency per agent DID and rejects excessive requests. Requires
  trust in a server, does not generalize across services.
- **Agent-side timestamps**: the agent self-reports `iat`/`nbf` in
  its credentials. The agent can lie. The verifier can compare
  against its own clock, but the agent's local clock may differ.
- **Trusted timestamp authority**: an external service (RFC 3161 TSA,
  blockchain anchoring) attests to the time of credential issuance.
  Requires trust in the authority and adds latency.

Three failure modes that none of the above address:

1. **Runaway agent loops**: a misbehaving agent enters a tight loop
   issuing thousands of credentials per second, each within its own
   declared validity window. Server-side rate limits depend on
   network reachability and on the verifier observing the loop.
2. **Distributed amplification**: an attacker controlling many agent
   identities issues coordinated bursts. Per-DID rate limits do not
   help.
3. **Time-based replay attacks**: an agent observed by a sandboxed
   adversary replays a credential to a different verifier whose
   clock skew tolerance is large enough to permit the replay.

What is needed is a mechanism where the agent **cannot issue credentials
faster than a target rate** even if it lies about its local clock, even
if it controls many parallel identities, and even if it has unbounded
hardware resources. The mechanism must be self-evidencing (the proof
of elapsed time travels with the credential) and must not depend on
any external time authority.

## 3. The Novel Mechanism

### 3.1 Verifiable Delay Functions

A Verifiable Delay Function `VDF(challenge, t)` is a function with
three required properties:

1. **Sequentiality**: computing `VDF(challenge, t)` requires at
   least t sequential steps; even with arbitrary parallelism, the
   wall-clock time cannot be reduced below t.
2. **Verifiability**: given `(challenge, t, output)`, anyone can
   verify the output in time `O(log t)` (much faster than computing
   it).
3. **Uniqueness**: the output is uniquely determined by
   `(challenge, t)`.

Reference VDF constructions: Wesolowski (2018), Pietrzak (2019).
Both produce outputs of constant size (tens to hundreds of bytes)
regardless of t.

### 3.2 The Rate-Limit Construction

Each Vouch agent operating under the rate-limit profile maintains a
*VDF chain*: a sequence of VDF outputs where each output's challenge
is derived from the previous output (or from the agent's DID at
genesis).

When the agent issues a high-stakes Vouch Credential at time T_i, it:

1. Reads the previous VDF output `V_{i-1}` from its local state.
2. Computes the new challenge:
   `challenge_i = SHA-256(V_{i-1} || canonical(credential_metadata))`.
3. Computes `V_i = VDF(challenge_i, t_target)` where `t_target` is
   the configured minimum interval (e.g., 100 ms for ordinary
   actions, 1 second for high-stakes, 10 seconds for very-high-stakes).
4. Embeds `V_i`, `t_target`, and `V_{i-1}` (or its hash) into the
   credential's `proof.delayProof` field.
5. Signs the credential normally.

A verifier accepting the credential:

1. Verifies the Data Integrity proof (signature) as usual.
2. Recomputes `challenge_i = SHA-256(V_{i-1} || canonical(metadata))`.
3. Verifies that `V_i` is the correct VDF output for
   `(challenge_i, t_target)` using the VDF's logarithmic-time
   verification.
4. If verification passes, the verifier knows that at least
   `t_target` wall-clock time elapsed since the agent computed the
   previous credential's VDF output.

### 3.3 Why VDF and Not a Timestamp

The VDF's sequentiality property is key. An agent cannot:

- **Skip the wait** by precomputing future VDF outputs, because each
  VDF challenge depends on the *previous* VDF output (Markov chain).
- **Parallelize the wait** by running many VDFs simultaneously,
  because VDF construction is provably sequential.
- **Steal another agent's VDF outputs**, because the VDF challenge
  includes the agent's own credential metadata (canonical-hashed
  via JCS).
- **Forge a VDF output**, because VDF outputs are unique and
  publicly verifiable.

The agent's only path to issuing the next high-stakes credential is
to actually wait, computing VDF cycles in sequence.

### 3.4 Risk-Tiered Rate Limits

A single agent may operate under multiple rate-limit tiers
simultaneously, each with its own VDF chain. Example policy:

| Action category | t_target | Effective max rate |
|---|---|---|
| Logging / heartbeat | 1 ms | 1,000 / sec |
| Ordinary API read | 10 ms | 100 / sec |
| API write | 100 ms | 10 / sec |
| Financial transaction | 1 sec | 1 / sec |
| High-value financial decision | 10 sec | 6 / minute |
| Catastrophic-impact decision | 60 sec | 1 / minute |

The agent maintains a separate VDF chain per tier. The verifier reads
the action category from the credential's intent and applies the
appropriate tier's `t_target` requirement.

### 3.5 Composability with Heartbeat (PAD-016)

The Heartbeat Protocol (PAD-016) renews trust at adaptive TTLs. The
VDF rate-limit composes naturally:

- The Heartbeat's "Trust Entropy" decay provides the adaptive
  trust score.
- The VDF rate-limit provides the cryptographic floor on action
  frequency.

A high-trust agent (low entropy) can act at the maximum rate the
VDF tier permits. A low-trust agent (high entropy) is further
constrained by the heartbeat protocol's renewal cadence, on top of
the VDF rate limit. The two mechanisms are complementary and
multiplicatively safer.

### 3.6 Federated VDF Chains (Multi-Validator Variant)

In a federated validator quorum (PAD-039 multi-party trust state),
the VDF chain can be split across validators: each validator
contributes a VDF cycle, and the M-of-N quorum enforces M
sequential VDF computations. This is even slower for adversaries to
fake, since they must compromise M validators to forge the chain.

## 4. Embodiments

**Embodiment 1: Containment of runaway trading agents.** A trading
agent operates under `t_target = 1 second` for trade execution. A
software bug that would otherwise cause the agent to issue 10,000
trades per second is structurally constrained to 1 per second, even
before any human intervention. Risk exposure is mathematically
bounded.

**Embodiment 2: API spam protection at the edge.** A Cloudflare
Workers verifier rejects credentials whose VDF chain is too dense
(e.g., 50 credentials in 1 second when t_target requires 100 ms
spacing). The verifier has cryptographic certainty the agent
violated its rate budget, not just statistical suspicion.

**Embodiment 3: Adversarial agent containment.** A red-team agent
attempting to perform reconnaissance against a regulated service
must wait the full t_target between probes. Reconnaissance time
windows that would otherwise complete in seconds extend to hours,
making the attack detectable and recoverable.

**Embodiment 4: Long-running deliberation requirement.** A
healthcare diagnostic agent operating under `t_target = 10 seconds`
for diagnosis credentials cannot issue a diagnosis faster than 10
seconds, even if the underlying model could generate a response in
500 milliseconds. The 10-second interval is reserved for additional
sanity checks (e.g., a second model running in parallel, a human
review queue).

**Embodiment 5: Multi-tier mixed deployment.** An autonomous fleet
operates under a tiered policy: routine status updates at 100/sec
(tier 1), routing decisions at 10/sec (tier 2), high-value
maneuvers at 1/sec (tier 3). The agent maintains three independent
VDF chains. A bug or compromise affecting one tier does not
collapse the rate limit on the other tiers.

## 5. Non-Obviousness

Existing rate-limiting mechanisms in identity protocols rely on
trusted clocks, server-side counters, or trusted timestamp
authorities. None provide a cryptographically self-evidencing
proof of elapsed time that travels with the credential and is
verifiable by any party without consulting an authority.

The non-obvious elements are:

1. **Use of a VDF as the rate-limit primitive.** VDFs are typically
   discussed in the context of randomness beacons, public lottery
   protocols, and blockchain timestamping. Their use as a per-agent
   rate-limiting mechanism for credential issuance is novel.

2. **VDF chain composition.** Each VDF challenge depends on the
   previous output, forming a Markov chain that prevents pre-
   computation. The agent cannot issue credentials faster than the
   sequential VDF rate.

3. **Risk-tiered VDF chains.** Multiple parallel VDF chains per
   agent enable per-action-category rate limits without conflating
   high-frequency low-stakes actions with low-frequency high-stakes
   actions.

4. **Composability with adaptive trust (Heartbeat Protocol).** The
   VDF rate-limit composes multiplicatively with PAD-016's adaptive
   trust decay, providing both a cryptographic floor and an adaptive
   ceiling.

5. **Federated VDF chains for quorum-validated rate limits.** In
   federated trust deployments, the VDF chain can be distributed
   across M validators, requiring adversaries to compromise M
   validators to forge the chain.

The combination is non-obvious relative to:

- Server-side rate limits (depends on trusted server).
- Self-reported timestamps (the agent can lie).
- Trusted timestamp authorities (single point of failure, latency).
- Proof-of-work (parallelizable, defeats the purpose).
- Standard JWT `iat` and `nbf` claims (rely on local clock).

## 6. Disclaimer

This disclosure is published as defensive prior art under the Apache
2.0 License. It is intended to prevent assertion of patents covering
the disclosed mechanism. The author claims no exclusive rights to the
described invention. The mechanism is published openly because the
ability to cryptographically rate-limit autonomous agent actions
without trusting a central authority is a foundational AI safety
primitive that must remain a public good.

---

*Published as prior art to ensure that cryptographic rate-limiting
of autonomous agent actions remains an open standard, available to
every safety-critical agent deployment.*
