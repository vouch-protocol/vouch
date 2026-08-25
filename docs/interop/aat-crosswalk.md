# Vouch Protocol and AAT: crosswalk

**Compared against:** `draft-niyikiza-oauth-attenuating-agent-tokens-01`,
N. A. Niyikiza (Tenuo), 15 June 2026, Standards Track intent, individual
submission to the OAuth WG. Expires 17 December 2026.

**Vouch side:** CG Report v1.6.2 (`docs/specs/w3c-cg-report.md`) plus the
unpublished v1.7 delegation redesign (`docs/specs/w3c-cg-report-v1.7-draft.md`)
and the shipped `vouch/attenuation.py` / `core/vouch-core/src/attenuation.rs`.

## Summary

AAT and Vouch v1.7 §9 build the same primitive: an offline-derivable,
monotonically-narrowing delegation chain, anchored at a root trust key and
verifiable by the enforcement point without an authorization-server round trip.
The overlap on that primitive is substantial. They differ in serialization, in
the granularity of the narrowing lattice, and — most usefully — in what each one
declares out of scope.

## Where AAT is ahead

**Argument-level constraints.** AAT §3.4 defines a typed constraint vocabulary
(`exact`, `range`, `one_of`, `not_one_of`, `contains`, `subset`, `wildcard`,
`all`, `any`) with both a normative `check` predicate and a normative `subsumes`
relation per type, and an IANA registry (§10.3) with designated-expert review for
extensions. Unrecognized constraint types fail closed.

Vouch has no argument dimension. `_DIMENSIONS` in `vouch/attenuation.py` is
`(action, target, resource, time, rate, policy)`. Narrowing is on the resource
URI, the action/target sets, the time window, the rate ceiling, and a policy
object — never on the argument values of a specific invocation.
`vouch/mcp_guard.py` states this in its own docstring: it "does NOT by itself
bind the credential to the specific argument values of this call."

In an MCP setting the attack is `write_file(path="/etc/shadow")` — authorized
tool, hostile argument. AAT addresses it; Vouch currently does not.

**Proof of possession at invocation.** AAT invariant I6 plus §5 define a PoP JWT
binding each invocation to a fresh `jti`, timestamp, target tool, presented
arguments, and optional audience, with mandatory stateful `jti` tracking for
irreversible operations (§8.5). Vouch's guard disclaims replay protection unless
a nonce tracker is separately wired.

## Where Vouch is ahead

**Narrowing lattice breadth.** Six dimensions with cross-language conformance
vectors (`test-vectors/delegation-attenuation/vector.json`) that gate builds in
Python, TypeScript and Go against a Rust core. AAT has richer *argument*
constraints; Vouch has `rate` and `policy` dimensions AAT has no equivalent for.

**Depth.** AAT invariant I2 enforces depth monotonicity under the root's limit.
Vouch v1.7 §9.4 removed the fixed depth cap deliberately: an agent at the cap
that still needs to hand off authority proxies the request or shares its
credentials, both of which *broaden* authority and destroy the audit trail. Cost
control moved to verifier-side budgets (`verifier_budget_exceeded`). This is a
substantive critique of any fixed-depth model, reviewed by Alan Karp and Manu
Sporny on PR #42.

**Revocation.** AAT §8.9 places revocation of individual and derived tokens
explicitly out of scope, relying on short lifetimes, and notes that "a companion
document may define lineage-scoped cascading revocation." Vouch v1.7 §9.6 is
that mechanism, already implemented: revoking any link invalidates everything
downstream in the same lineage (`delegation_revoked`), over BitstringStatusList
plus a DID-level registry, with key rotation deliberately excluded as a cascade
trigger.

**Crypto-agility.** Multikey verification methods and the dual-proof
Ed25519 + ML-DSA-44 profile over identical JCS-canonicalized bytes, with
cross-language vectors.

## What AAT declares out of scope, verbatim (§8.1.2)

These four are the interop surface, named by the AAT author, not by us:

1. *Malicious or compromised root issuer.* "AATs provide no mechanism to detect
   or constrain a malicious root issuer." → Vouch §18 federated root of trust:
   a root recognizes issuers, recognition is re-checked on every verification,
   and revoking a Recognized Issuer Credential withdraws every identity that
   issuer attested.
2. *Actions within authorized argument constraints.* "An agent that makes
   excessive or unintended use of its authorized tools within the bounds of its
   token is not detectable at the enforcement point. Rate limiting, audit
   logging, and behavioral monitoring are complementary controls." → the `rate`
   dimension, the Heartbeat Protocol, and behavioral attestation.
3. *Compromised holder key.* AAT's only mitigation is short lifetimes. → the
   Identity Sidecar keeps the key out of the LLM context entirely, reducing the
   probability of the compromise rather than only bounding its window.
4. *Model exfiltration and side channels.* "AATs operate at the authorization
   layer and have no visibility into the model layer." → model-weight binding
   (PAD-043) and retrieval anchoring (PAD-045) are model-layer.

## Position

AAT is the stronger artifact at the token and argument layer, in the
serialization the OAuth community uses, with a normative subsumption relation
Vouch does not have an equivalent for. Competing with it on attenuation is not a
winnable framing.

The composition is: an AAT constrains what a sub-agent may invoke, down to
argument values; Vouch supplies the per-invocation signed evidence, the
continuity check that the agent still holds the authority it started with, the
lineage-scoped cascading revocation the draft asks a companion document to
define, and the post-quantum durability for retention. §8.1.2 names three of
those four as complementary controls.

## Open work implied by this comparison

- Add an argument-constraint dimension to `_DIMENSIONS`, or state plainly that
  Vouch defers argument-level narrowing to a carried AAT.
- Wire replay protection into `guard_mcp` by default rather than as an opt-in
  nonce tracker.
- Draft the lineage-scoped cascading revocation companion that AAT §8.9 invites.
