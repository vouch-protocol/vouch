# Delegation Chains Reference

A delegation chain proves "principal authorized agent, agent authorized
sub-agent, sub-agent took the action." Each link narrows scope.

## When to use a delegation chain

- A human principal wants to authorize an AI agent to act on their behalf
- An AI agent spawns a sub-agent (multi-agent flow) and the sub-agent acts
- Cross-organization workflows where one org's agent invokes another org's agent
- Any time the audit answer to "who said this was OK?" matters more than
  the action itself

## Structure

The action credential carries an optional `delegationChain` array:

```json
{
    "type": ["VerifiableCredential", "VouchCredential"],
    "issuer": "did:web:sub.example.com",
    "credentialSubject": {
        "id": "did:web:sub.example.com",
        "intent": { "action": "submit_claim", "target": "claim:HC-001", "resource": "..." },
        "delegationChain": [
            {
                "issuer": "did:web:cfo.example.com",
                "subject": "did:web:agent.example.com",
                "intent": { "action": "*", "target": "*", "resource": "orders/*" },
                "validFrom": "...",
                "validUntil": "...",
                "parentProofValue": null
            },
            {
                "issuer": "did:web:agent.example.com",
                "subject": "did:web:sub.example.com",
                "intent": { "action": "submit_claim", "target": "*", "resource": "orders/HC-001" },
                "validFrom": "...",
                "validUntil": "...",
                "parentProofValue": "z..."
            }
        ]
    },
    "proof": {...}
}
```

Each link records: issuer, subject (the next entity in the chain), the
intent scope being delegated, validity window, and the proof value of
the parent link (binding the chain cryptographically).

## Construction (Python)

```python
from vouch import generate_identity, Signer, build_vouch_credential

# Each entity has its own identity. In production you load these from your
# own key store; here we generate them for illustration.
cfo_keys = generate_identity("cfo.example.com")
agent_keys = generate_identity("agent.example.com")
sub_keys = generate_identity("sub.example.com")

# Principal signs delegation #1
principal_signer = Signer(private_key=cfo_keys.private_key_jwk, did=cfo_keys.did)
delegation_to_agent = principal_signer.sign_credential(build_vouch_credential(
    issuer_did="did:web:cfo.example.com",
    subject_did="did:web:agent.example.com",
    intent={"action": "*", "target": "*", "resource": "orders/*"},
    valid_seconds=86400,  # 24h
))

# Agent signs delegation #2 (narrowing to one order)
agent_signer = Signer(private_key=agent_keys.private_key_jwk, did=agent_keys.did)
delegation_to_sub = agent_signer.sign_credential_with_parent(
    parent=delegation_to_agent,
    subject_did="did:web:sub.example.com",
    intent={"action": "submit_claim", "target": "*", "resource": "orders/HC-001"},
    valid_seconds=3600,
)

# Sub-agent signs the action
sub_signer = Signer(private_key=sub_keys.private_key_jwk, did=sub_keys.did)
action = sub_signer.sign_credential_with_chain(
    chain=[delegation_to_agent, delegation_to_sub],
    intent={"action": "submit_claim", "target": "claim:HC-001", "resource": "orders/HC-001"},
    valid_seconds=300,
)
```

The SDK helpers `sign_credential_with_parent` and
`sign_credential_with_chain` handle parent-proof binding and the
capability-attenuation rule (each link can only narrow the parent).

## Verification

```python
from vouch import Verifier

# verify_credential returns a (is_valid, passport) tuple
is_valid, passport = Verifier.verify_credential(action)
# Verifier automatically walks delegationChain backward and validates each link
```

The verifier checks at each link:

1. Signature math: the link's `proof` validates against the issuer's DID Doc
2. Capability attenuation: this link narrows the parent on at least one of action, target, resource, time, rate, or policy, and is broader on none (resource narrowing, below, is the resource case of this rule)
3. Validity window: now is within each link's `validFrom..validUntil`
4. Issuer-of-this-link == subject-of-previous-link (chain integrity)

If any check fails, the whole action credential is rejected with a
specific reason (`delegation_chain_invalid`, `capability_not_attenuated`,
`resource_not_narrowed`, etc.).

There is no fixed limit on chain length. Because authority only ever
narrows as it passes down a chain, a chain ends naturally when nothing is
left to narrow. A verifier MAY still set its own cost budget (by depth, by
total verification time, or by cumulative validity across the chain). If a
chain exceeds that budget, the verifier rejects it with
`verifier_budget_exceeded` and names the limit it hit, so the delegating
agent knows to narrow earlier instead of routing around the block.

## Resource narrowing rule

Each link's resource scope MUST be a subset of the parent's:

- Parent `orders/*` -> child `orders/HC-001` is valid (subset)
- Parent `orders/HC-001` -> child `orders/HC-002` is invalid (sibling, not subset)
- Parent `orders/*` -> child `users/*` is invalid (different prefix)

The subset check is path-prefix-based with wildcard support. Custom
matchers can be plugged in via the verifier config for complex schemas.

## Trusted principal anchoring

The verifier needs to know which DIDs are trusted principals. Configure
the trust root explicitly:

```python
verifier = Verifier(trusted_principals=[
    "did:web:cfo.example.com",
    "did:web:hr.example.com",
])
```

If a chain doesn't terminate at a trusted principal, it fails with
`untrusted_principal`. This prevents an attacker from signing their own
"principal" delegation.

## Why no fixed depth limit?

Earlier versions capped a chain at five hops. That cap turned out to do
more harm than good: an agent that hit the limit but still needed to hand
a narrower slice of its authority to another agent could not delegate, so
it would proxy the other agent's requests or share its credentials instead.
Both of those hand over more authority than intended and erase the audit
trail.

The control now is attenuation itself. Every link must be strictly smaller
than its parent, so a chain cannot grow in authority no matter how long it
gets, and it stops on its own once there is nothing left to narrow. If a
verifier wants to bound how much work it spends walking a chain, it sets a
local cost budget (depth, verification time, or cumulative validity) and
reports `verifier_budget_exceeded` when a chain crosses it.

For flows that need a different shape than a linear chain, you can still
use Validator Quorum issuance, where a validator becomes the intermediate
authority.

## Common errors

- **`delegation_chain_invalid: parent proof mismatch`**: a link's
  `parentProofValue` doesn't match the previous link's `proofValue`.
  Usually means the chain was reassembled out of order.
- **`resource_not_narrowed: ...`**: a child link tried to grant access
  beyond its parent's scope.
- **`capability_not_attenuated`**: a child link did not narrow the parent
  on any dimension, or was broader on one. Narrow action, target, resource,
  time, rate, or policy.
- **`verifier_budget_exceeded`**: the chain crossed a verifier's local cost
  budget (depth, verification time, or cumulative validity). Narrow earlier
  or split the work; this is the verifier's choice, not a protocol limit.
- **`untrusted_principal`**: the chain root isn't in the verifier's trust
  set.
- **`link_signature_invalid`**: a delegation link's signature failed
  verification. Usually a key rotation or DID Doc cache miss.

## Common patterns

### Single principal, single agent
Most common. One delegation link, the agent's action credential. Two
total credentials.

### Single principal, agent + sub-agent
Three credentials in the chain: principal -> agent -> sub-agent, plus
the sub-agent's action credential.

### Cross-organization delegation
Org A's principal delegates to its agent, the agent calls into Org B's
agent endpoint. The receiving Org B verifies the chain against its
trusted principals (which must include Org A's principal DID).

### Time-bounded delegation
Set `validUntil` on the delegation link to the desired expiry. Even if
the agent's keys are compromised later, the delegation cannot be used
after expiry.

### Single-use delegation
Set `validUntil` to a short window and put a nonce in the link's intent.
Combined with the verifier's nonce store, this gives true single-use.
