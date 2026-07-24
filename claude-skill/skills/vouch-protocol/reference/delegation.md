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

## Construction (one line)

The one-line path uses `vouch.delegate` on the principal side and a `parent=`
argument on the agent side. The agent's tools are then chained under the grant
automatically, and the protocol enforces that each link can only narrow the
authority, never widen it.

```python
import vouch

# Principal grants narrow authority in one call.
grant = vouch.delegate(
    action="submit_claim", target="*", resource="orders",
    to="did:web:agent.example.com", signer=principal_signer,
)

# Every action the agent signs is chained under the grant.
agent.tools = vouch.protect([submit_claim], parent=grant)
```

`parent=` also works on `@signed` and `sign_intent`.

## Construction (lower level)

To build a chain explicitly, sign each credential under its parent. The
`parent_credential` argument appends a delegation link and enforces resource
narrowing at build time. The full non-expansion rule (no link may broaden its parent on any of action, target, resource, time, rate, or policy) is checked at verification, and there is no fixed chain-depth limit; verifiers bound cost with their own budgets.

```python
from vouch import Signer

# Principal grants to the agent.
principal_signer = Signer(private_key=principal_priv_jwk, did="did:web:cfo.example.com")
delegation_to_agent = principal_signer.sign(
    intent={"action": "*", "target": "*", "resource": "orders"},
    valid_seconds=86400,  # 24h
)

# Agent narrows and re-delegates to a sub-agent.
agent_signer = Signer(private_key=agent_priv_jwk, did="did:web:agent.example.com")
delegation_to_sub = agent_signer.sign(
    intent={"action": "submit_claim", "target": "*", "resource": "orders/HC-001"},
    parent_credential=delegation_to_agent,
    valid_seconds=3600,
)

# Sub-agent signs the action under the chain.
sub_signer = Signer(private_key=sub_priv_jwk, did="did:web:sub.example.com")
action = sub_signer.sign(
    intent={"action": "submit_claim", "target": "claim:HC-001", "resource": "orders/HC-001"},
    parent_credential=delegation_to_sub,
    valid_seconds=300,
)
```

## Verification

```python
import vouch

# One line. Auto-resolves the issuer key and walks the delegationChain,
# validating each link.
ok, passport = vouch.verify(action)
```

The verifier checks at each link:

1. Signature math: the link's `proof` validates against the issuer's DID Doc
2. Resource narrowing: this link's `resource` is a subset of the parent's
3. Validity window: now is within each link's `validFrom..validUntil`
4. Issuer-of-this-link == subject-of-previous-link (chain integrity)
5. Total chain depth <= 5 (Specification §9.4)

If any check fails, the whole action credential is rejected with a
specific reason (`delegation_chain_invalid`, `resource_not_narrowed`,
`chain_depth_exceeded`, etc.).

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

## Why depth = 5?

Empirical limit from PAD-006 (trust-graph URL chaining). Five hops is
enough for nearly all realistic multi-agent flows. The cap prevents
unbounded chain growth that would explode the verifier's walk cost.

For flows that need deeper nesting, restructure to use Validator
Quorum issuance instead of pure delegation (the validator becomes the
intermediate authority).

## Common errors

- **`delegation_chain_invalid: parent proof mismatch`**: a link's
  `parentProofValue` doesn't match the previous link's `proofValue`.
  Usually means the chain was reassembled out of order.
- **`resource_not_narrowed: ...`**: a child link tried to grant access
  beyond its parent's scope.
- **`chain_depth_exceeded`**: more than 5 links. Restructure.
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
