# Threshold signing (FROST)

Split a signing key among several custodians so any threshold of them can
sign together, without the full private key ever existing whole, not even
during signing.

Every SDK (Python, TypeScript, Go, JVM, .NET, C, Swift) binds the same
audited Rust core (the `frost-ed25519` crate from the Zcash Foundation, RFC
9591), so every language produces byte-identical results from one
implementation. The resulting signature is a standard Ed25519 signature, so
it verifies like any other Vouch credential.

## 1. Generate a threshold identity

A dealer mints `max_signers` key shares and a group public key, such that
any `min_signers` of them can sign together. This mints a fresh
threshold-native identity; it does not convert an existing single-key
Ed25519 identity into one.

```python
from vouch import threshold

generated = threshold.generate_key(min_signers=2, max_signers=3)
# generated.shares: distribute one KeyShare to each custodian
# generated.group_public_key: the identity's public key
```

## 2. Sign with a threshold of custodians

`ThresholdSigner` runs the full commit, sign-share, and aggregate ceremony
in one call, for a coordinator that holds enough shares to sign (a service
with several custodian shares mounted, or a test harness).

```python
from vouch import Signer, ThresholdSigner

threshold_signer = ThresholdSigner(generated.shares[:2], generated.group_public_key)

signer = Signer.from_backend(
    did="did:web:agent.example",
    public_key=generated.group_public_key.public_key_jwk,
    sign=threshold_signer.sign,
)
credential = signer.sign(action="read", target="t", resource="https://x/y")
```

`Signer.from_backend`'s callback signs a digest and returns a signature; a
`ThresholdSigner` slots in directly, so the rest of the Signer, and every
verifier, stays unaware a threshold ceremony produced the signature.

## 3. Verify

Nothing changes on the verifying side. The aggregated signature is a
standard Ed25519 signature over the group public key, so any Vouch verifier
checks it exactly like a single-key credential.

```python
from vouch import Verifier

valid, _ = Verifier.verify(credential, public_key=generated.group_public_key.public_key_jwk)
assert valid
```

## 4. A true multi-device ceremony

A coordinator holding every share in one process is a convenience, not a
requirement. For custodians who never share a process, call the four steps
directly on each device and pass commitments and shares over the network:

```python
from vouch import threshold

round1 = threshold.commit(my_share)
# send round1.commitments to the other participants, keep round1.nonces secret

my_sig_share = threshold.sign_share(
    message, my_share, round1.nonces, commitments_by_participant
)
# send my_sig_share to whoever aggregates

signature = threshold.aggregate(
    message, commitments_by_participant, shares_by_participant, generated.group_public_key
)
```

## What's never assembled, and what is

- No function anywhere in this surface takes key shares and returns a seed
  or a private scalar. Aggregation self-verifies before it returns, and
  refuses to return an invalid signature.
- Nonces from `commit` are single-use; reusing one for more than one
  `sign_share` call leaks the signer's key share.
- This is distinct from [cross-device identity](cross-device-identity.md)'s
  root recovery, which does reconstruct a key, once, for a deliberate
  restore. Threshold signing never reconstructs the key at all, and is
  meant for live, repeated signing rather than a one-time recovery.
