# Threshold Signing Reference

FROST(Ed25519) threshold signing: split a signing key among several
custodians so that any threshold of them can produce a signature together,
without the full private key ever existing whole at any point, not even
during signing. The resulting signature is a standard Ed25519 signature, so
it verifies exactly like any other Vouch credential; no new proof type.

This is available in every SDK: Python, TypeScript, Go, JVM, .NET, C, and
Swift. All seven bind the same audited Rust core (the `frost-ed25519` crate
from the Zcash Foundation, RFC 9591), so every language produces
byte-identical results from one implementation, not a separately reviewed
reimplementation per language.

## When to use it

- A decision needs more than one custodian's agreement before it can be
  signed (a board, an on-call rotation, a set of co-founders), and you want
  that enforced by the key itself, not by policy someone could bypass.
- You want to remove any single point of compromise: no one custodian,
  including a coordinator, ever holds a complete key.
- You are signing repeatedly (a live service, a validator), which is what
  distinguishes this from root-identity recovery (see the Cross-Device
  Identity reference): recovery reconstructs a key once, for a deliberate
  restore; threshold signing never reconstructs it at all.

## The model

- Generate: a dealer mints `max_signers` key shares and a group public key,
  such that any `min_signers` of the shares can sign together. This mints a
  fresh threshold-native identity; it does not convert an existing
  single-key Ed25519 identity into one (a standard Ed25519 seed is not
  directly usable as a FROST share, so treat a threshold identity as its own
  identity from the start).
- Commit (round 1): each participating signer generates single-use nonces
  (kept secret, never sent) and a public commitment (safe to share).
- Sign share (round 2): each signer, given the message and every
  participant's commitment, produces a signature share from its own key
  share and nonces.
- Aggregate: a coordinator combines the signature shares into one final,
  standard Ed25519 signature, over the same group public key.

## Generate a threshold identity

```python
from vouch import threshold

generated = threshold.generate_key(min_signers=2, max_signers=3)
# generated.shares: 3 KeyShare objects, distribute one to each custodian
# generated.group_public_key: the identity's public key
```

## Sign with a threshold of custodians

`ThresholdSigner` runs the full commit / sign-share / aggregate ceremony in
one call for a coordinator that holds enough shares to sign (a service with
several custodian shares mounted, or a test harness). A true multi-device
ceremony instead calls `commit` / `sign_share` / `aggregate` directly on
each device, passing commitments and shares over the network.

```python
from vouch import Signer, ThresholdSigner

threshold_signer = ThresholdSigner(
    generated.shares[:2], generated.group_public_key
)

signer = Signer.from_backend(
    did="did:web:agent.example",
    public_key=generated.group_public_key.public_key_jwk,
    sign=threshold_signer.sign,
)
credential = signer.sign(action="read", target="t", resource="https://x/y")
```

`Signer.from_backend`'s callback signs a digest and returns a signature; a
`ThresholdSigner` slots in directly, so the rest of the Signer, and every
verifier, is unaware a threshold ceremony produced the signature.

## Verify

Nothing changes on the verifying side. The aggregated signature is a
standard Ed25519 signature over `group_public_key`, so any Vouch verifier
checks it exactly like a single-key credential:

```python
from vouch import Verifier

valid, _ = Verifier.verify(credential, public_key=generated.group_public_key.public_key_jwk)
assert valid
```

## Security notes

- `generate_key` mints a fresh identity; it cannot convert an existing
  single-key Ed25519 identity, because that identity's private scalar is
  not generally a canonical element of the group order FROST's scalar field
  uses. Enroll a threshold identity as a device or root the same way any
  other Vouch identity is enrolled.
- Nonces from `commit` are single-use. Reusing them for more than one
  `sign_share` call leaks the signer's key share.
- Aggregation self-verifies: the core checks the combined signature against
  the group public key before returning it, and refuses to return an
  invalid signature.
- There is deliberately no "reconstruct" function anywhere in this surface.
  Nothing here takes key shares and returns a seed or a private scalar.

## API summary

- `generate_key(min_signers, max_signers)` -> shares and a group public key
- `commit(key_share)` -> single-use nonces and a public commitment
- `sign_share(message, key_share, nonces, commitments_by_participant)` -> a
  signature share
- `aggregate(message, commitments_by_participant, shares_by_participant,
  group_public_key)` -> the final Ed25519 signature
- `ThresholdSigner(shares, group_public_key)` with `.sign(digest)`, for
  plugging into `Signer.from_backend`

Every SDK exposes the same four-step ceremony and the same convenience
signer, spelled in that language's own casing (for example
`ThresholdGenerateKey` in Go, `thresholdGenerateKey` in TypeScript and
Swift).
