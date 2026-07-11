# Root of Trust for Machine Identity

Vouch Protocol can act as the trust anchor for AI agent and robot
identity. This is an optional authority layer on top of the base
protocol. A verifier pins one Vouch Protocol root, the root recognizes
issuers, and a recognized issuer vouches for an agent's identity. A
verifier then confirms any agent by walking a short chain back to the
single root it already trusts.

The base protocol is unchanged. An agent's own `vouch init` still mints
a self-certifying identity with no authority above it. This layer is
additive: reach for it when a verifier wants identities backed by a named
authority rather than self-asserted alone.

## The problem it solves

A self-issued Vouch Protocol credential anchors to whatever the agent
claims about itself. With `did:web` that is a domain you control; with
`did:key` it is a public key baked into the identifier. Both prove the
same key signed the credential. Neither says who stands behind the agent,
what model it runs, or who owns it. A verifier that receives a credential
from an unfamiliar agent has no authority to point at.

The Root of Trust layer closes that gap. An issuer the root recognizes
binds the agent's DID to real attributes, and the recognition traces back
to a root the verifier pinned in advance. The verifier decides once, up
front, which root it trusts. Everything else is checked from the
credentials presented, with no external certificate authority and no
central per-agent lookup.

## The three credential types

All three are ordinary Verifiable Credential 2.0 documents with an
`eddsa-jcs-2022` Data Integrity proof, the same proof used everywhere
else in Vouch Protocol. Each carries exactly one of the trust-layer types
below, so a credential minted for one slot in the chain cannot be
replayed into another.

### 1. Root of Trust credential (`VouchRootOfTrust`)

Self-issued by the root: issuer and subject are both the root's own DID.
It makes the root self-describing. A verifier pins the root DID; keeping
this credential is optional and lets a verifier display what the root
anchors.

Required shape:

```json
{
  "type": ["VerifiableCredential", "VouchRootOfTrust"],
  "issuer": "did:key:z6MkRoot...",
  "validFrom": "2026-07-12T00:00:00Z",
  "validUntil": "2036-07-09T00:00:00Z",
  "credentialSubject": {
    "id": "did:key:z6MkRoot...",
    "vouchVersion": "1.0",
    "rootOfTrust": {
      "name": "Example Machine Identity Root",
      "scope": ["ai-agent", "robot"]
    }
  },
  "proof": { "cryptosuite": "eddsa-jcs-2022", "...": "..." }
}
```

- `issuer` equals `credentialSubject.id` (self-issued).
- `rootOfTrust.name`: human-readable name of the root.
- `rootOfTrust.scope`: what the root anchors. Defaults to
  `["ai-agent", "robot"]`.

### 2. Recognized-issuer credential (`RecognizedIssuerCredential`)

Issued by the root. It names an issuer DID and the identity actions that
issuer may perform. `recognizedIn` points back to the root DID so a
verifier can trace the recognition to the anchor it pinned. The holder
staples this credential to what it presents, so the verifier needs no
directory lookup.

Required shape:

```json
{
  "type": ["VerifiableCredential", "RecognizedIssuerCredential"],
  "issuer": "did:key:z6MkRoot...",
  "validFrom": "2026-07-12T00:00:00Z",
  "validUntil": "2027-07-12T00:00:00Z",
  "credentialSubject": {
    "id": "did:key:z6MkIssuer...",
    "recognizedActions": ["issueAgentIdentity"],
    "recognizedIn": "did:key:z6MkRoot..."
  },
  "credentialStatus": { "...": "optional revocation entry" },
  "proof": { "cryptosuite": "eddsa-jcs-2022", "...": "..." }
}
```

- `issuer`: the root DID.
- `credentialSubject.id`: the issuer being recognized.
- `recognizedActions`: one or more of `issueAgentIdentity` and
  `issueRobotIdentity`. Defaults to `["issueAgentIdentity"]`.
- `recognizedIn`: the root DID, chaining recognition back to the anchor.
- `credentialStatus`: optional, for revoking the recognition later.

### 3. Agent identity credential (`AgentIdentityCredential`)

Issued by a recognized issuer. Here the issuer differs from the subject:
the issuer binds the agent's DID to attributes it stands behind. This is
the piece that turns a self-asserted agent DID into an identity a third
party vouches for.

Required shape:

```json
{
  "type": ["VerifiableCredential", "AgentIdentityCredential"],
  "issuer": "did:key:z6MkIssuer...",
  "validFrom": "2026-07-12T00:00:00Z",
  "validUntil": "2027-07-12T00:00:00Z",
  "credentialSubject": {
    "id": "did:key:z6MkAgent...",
    "identity": {
      "owner": "Example Robotics Inc.",
      "model": "claims-assistant-2",
      "capabilityClass": "financial-read",
      "createdAt": "2026-07-12T00:00:00Z"
    }
  },
  "credentialStatus": { "...": "optional revocation entry" },
  "proof": { "cryptosuite": "eddsa-jcs-2022", "...": "..." }
}
```

- `issuer`: the recognized issuer's DID (not the agent's).
- `credentialSubject.id`: the agent's DID.
- `identity`: a non-empty map of attributes. `owner`, `model`,
  `capabilityClass`, and `createdAt` are the common ones; you may add
  more and they pass through verification.
- `credentialStatus`: optional, for revoking the identity later.

## The anchor-once verification algorithm

A verifier trusts one thing up front: a root DID. Everything else is
derived. `verify_identity_chain` takes the agent identity credential and
the recognized-issuer credential, plus the pinned `trusted_root`, and
walks:

```
action credential          (optional, signed by the agent)
  -> agent identity credential   (signed by the recognized issuer)
    -> recognized-issuer credential  (signed by the pinned root)
      -> pinned Vouch Protocol root
```

Step by step:

1. Verify the recognized-issuer credential's proof, confirm its issuer is
   exactly the `trusted_root`, and confirm `recognizedActions` includes
   the required action (`issueAgentIdentity` by default). Reject if the
   recognition is revoked.
2. Verify the agent identity credential's proof and confirm its issuer is
   the DID that the root just recognized. Reject if the identity is
   revoked.
3. Optionally, if the Root of Trust credential is supplied, confirm it is
   genuinely self-issued by the `trusted_root`.
4. Optionally, if an action credential is supplied, verify it and confirm
   it was signed by the agent the identity describes.

The result reports `ok`, and on success the `agent_did`, the
`issuer_did` that vouched for it, the `root_did` it anchored to, and the
bound `attributes`. On failure it returns a structured reason (for
example `issuer_not_recognized_for_action` or
`identity_not_from_recognized_issuer`) so a caller can see exactly which
link broke.

## Offline operation

When the root, the issuer, and the agent all use `did:key`, the whole
chain verifies with no network. Each `did:key` carries its public key in
the identifier itself, so every signature resolves locally. This suits
air-gapped verifiers, robots on a factory floor, and edge deployments
that cannot reach a directory.

For `did:web` issuers, pass `allow_did_resolution=True` to resolve keys
over the network, or pin keys ahead of time by passing a
DID-to-public-key map so verification stays offline.

## Revocation

Recognition and identity are both revocable through the standard
`credentialStatus` field (BitstringStatusList). Revoke a recognized
issuer to withdraw its authority to vouch for new agents; revoke an
individual agent identity to retire one agent without touching the
issuer. The verifier consults the status entry during the walk and
rejects a revoked link. This reuses the same revocation machinery as the
rest of Vouch Protocol, so nothing new is needed operationally.

## The CLI

Four subcommands under `vouch root` drive the full lifecycle:

- `vouch root init`: self-issue a Root of Trust credential and mint the
  root's key. Run once to stand up a root.
- `vouch root recognize`: issue a recognized-issuer credential from the
  root, naming an issuer DID and the actions it may perform.
- `vouch root issue-identity`: as a recognized issuer, issue an agent
  identity credential that binds an agent DID to its attributes.
- `vouch root verify-chain`: walk an agent identity back to a pinned
  root and report whether it anchors.

The agent's own `vouch init` is unchanged. `vouch root` is the separate,
additive authority surface.

## Anyone can self-host a root

There is no privileged central root. Anyone can run `vouch root init` to
stand up their own root, recognize their own issuers, and publish the
root DID for verifiers to pin. An enterprise runs a root for its own
fleet; a marketplace runs one for the agents it lists; a robotics vendor
runs one for the machines it ships. Verifiers choose which roots to
trust, so the model stays self-sovereign and there is no gatekeeper to
ask permission from.

## Four-language byte-identical interop

The Root of Trust layer ships in Python, TypeScript, Rust, and Go, all
producing the same wire format. A recognized-issuer credential signed in
one language verifies in the other three, and a chain can span languages:
a root in Go, an issuer in Python, an agent in Rust, a verifier in
TypeScript all interoperate because they share JCS canonicalization
(RFC 8785) and the same `eddsa-jcs-2022` proof. This is the same
cross-language guarantee the base credentials carry, extended to the
authority layer.

## When to reach for it

- A verifier wants agent identities backed by a named authority, with a
  single trust decision made up front.
- Identities should carry attributes an issuer stands behind (owner,
  model, capability class) rather than self-asserted claims alone.
- The deployment needs offline verification with no directory lookup.
- You want to run your own root and recognize your own issuers, with no
  external certificate authority.

The base `vouch init` identity remains the right starting point for a
single self-certifying agent. Add the Root of Trust layer when a verifier
needs to anchor many agents to an authority it trusts.
