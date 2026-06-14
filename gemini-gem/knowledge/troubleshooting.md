# Troubleshooting Reference

Common errors during integration, with diagnoses and fixes.

## Installation

### `pip install vouch-protocol[pq]` fails

Cause: the `pqcrypto` dependency needs C headers and a compiler.

- macOS: `brew install liboqs` then retry
- Ubuntu/Debian: `apt install build-essential libssl-dev` then retry
- Windows: install Visual C++ Build Tools or use WSL

### `npm install @vouch-protocol-official/sdk` fails on Node 16

The SDK requires Node 18+. Upgrade Node.

### Go build error: `package github.com/cloudflare/circl/sign/mldsa/mldsa44`

Make sure `go mod tidy` has run. The hybrid signer uses Cloudflare's
CIRCL library; it's a transitive dependency that's fetched on first
build.

## Signing

### "intent.action is REQUIRED"

The credential's `intent` is missing one of `action`, `target`, or
`resource`. All three are required. Empty strings count as missing.

```python
# Wrong:
build_vouch_credential(issuer_did="...", intent={"action": "submit"})

# Right:
build_vouch_credential(issuer_did="...", intent={
    "action": "submit_claim",
    "target": "claim:HC-001",
    "resource": "https://insurance.example.com/claims/HC-001",
})
```

### Signature byte length is wrong

Ed25519 signatures are always exactly 64 bytes (raw). After multibase
base58btc encoding with the `z` prefix, expect ~88 characters. If you
see a different length, you may be looking at JWS Compact Serialization
from the legacy v0.x path; use `sign_credential` instead of `sign`.

Hybrid signatures are 64 + 2,420 = 2,484 bytes raw, about 3,400
characters base58btc.

### "DID Document not found" when signing

Signing doesn't need the DID Document; verification does. If you see
this error during signing, your SDK is incorrectly trying to verify
the just-signed credential. Check that you're using `sign_credential`,
not a misconfigured roundtrip helper.

## Verification

### "DID resolution failed"

Verifier couldn't fetch the issuer's DID Document. Common causes:

- did:web URL doesn't resolve: check `https://{domain}/.well-known/did.json`
  returns a valid JSON document
- TLS certificate problems: did:web requires valid HTTPS
- DNS not yet propagated: test with `curl` directly first
- Local-only did:web: use `did:web:localhost%3A8080` form for local
  testing (URL-encoded port)

```bash
# Sanity check
curl https://agent.example.com/.well-known/did.json
```

### "verificationMethod not found"

The credential's `proof.verificationMethod` ID doesn't exist in the
DID Document's `verificationMethod` array. Two common causes:

- Key was rotated; the credential was signed with the old key.
  Verifier should reject (defense in depth).
- DID Document caching: verifier has a stale cached version. Clear
  cache or wait for TTL.

```python
verifier = Verifier(cache_ttl_seconds=60)  # tighter than default
```

### "signature_invalid"

The signature math failed. Common causes:

- Credential was tampered with after signing
- JCS canonicalization mismatch: SDK versions differ in canonicalization
  rules. Run test vectors at `test-vectors/jcs/` to identify the
  divergence
- Wrong public key: the DID Doc has a key, but it's not the one that
  signed this credential (key rotation gap)
- Hybrid mode mismatch: classical-only verifier on a hybrid credential
  (or vice versa). Check `proof.cryptosuite`

### "credential_expired"

`validUntil` is in the past. If this is unexpected:

- Clock skew between issuer and verifier (check system NTP)
- Credential reused beyond its validity window (refresh)
- For long-running agents, use SessionVoucher with shorter intent
  credentials

### "nonce_replay"

The credential's `id` was already seen by this verifier. Either:

- Genuine replay attack (someone is replaying old credentials)
- Legitimate retry with same credential (caller should generate fresh)
- Nonce store cleared and credentials being re-presented (set TTL >=
  longest credential validity)

### "issuer_revoked"

The signing DID is in the revocation registry. Either:

- Genuine: the issuer was revoked. Credential rejected correctly.
- Cache miss: the issuer was un-revoked but cache is stale. Wait or
  invalidate cache.

### "credential_revoked"

The credential's `credentialStatus` bit is set in the BitstringStatusList.
The verifier MUST set `force_refresh=True` on the fetcher and retry to
confirm; if still set, credential is genuinely revoked.

### "delegation_chain_invalid"

A link in the chain failed verification. Sub-reasons:

- `parent_proof_mismatch`: a link's `parentProofValue` doesn't match
  the previous link's `proofValue`. Chain was reassembled incorrectly.
- `resource_not_narrowed`: a child link granted access beyond its
  parent's scope.
- `chain_depth_exceeded`: more than 5 links. Restructure.
- `untrusted_principal`: the chain root isn't in the verifier's trust set.
- `link_signature_invalid`: one of the delegation link signatures
  failed.

## Cross-language

### "Same input, different proofValue across languages"

JCS canonicalization disagreement. Run the test vectors at
`test-vectors/jcs/vectors.json` against all three SDKs; identify the
divergence. Common causes:

- Floats / integers: JCS has specific rules for numeric formatting
- Unicode escape sequences: JCS uses specific escaping
- Key ordering: must be lexicographic at every nesting level
- Whitespace: JCS strips all insignificant whitespace

### Python signs, TypeScript can't verify

Check `proof.cryptosuite`. If it's `hybrid-eddsa-mldsa44-jcs-2026`,
ensure the TypeScript SDK has `@noble/post-quantum` installed.

### Go signs, but the multibase prefix differs

Go's `compress/flate` produces a different DEFLATE stream from Python's
zlib for BitstringStatusList. Both decode to the same bitstring, but
the encoded form differs. The spec requires equivalence of the
decompressed bitstring, not the gzip envelope. Verification works
across both.

## Sidecar

### Sidecar refuses to start

- Port already in use: `netstat -an | grep 8877`
- DID not resolvable: see "DID resolution failed" above
- Key file unreadable: check permissions and ownership
- Run with `--verbose` for startup details

### Calls to sidecar hang

- Sidecar process crashed: check logs
- Network policy blocking: verify connectivity with `curl http://localhost:8877/health`
- TLS handshake at the network boundary: if sidecar is over network,
  ensure TLS certificate is valid

### Sidecar signs but verifier rejects

Sidecar's DID and the verifier's expected issuer don't match. Verify:

```bash
curl http://localhost:8877/did
# Should match the `issuer` field in produced credentials
```

## Performance

### Slow verification (> 100 ms per credential)

- DID resolution cache not warming up: configure `cache_ttl_seconds`
- Nonce store is on remote Redis with high RTT: move to local cache + async sync
- Status list fetcher fetching on every verification: ensure TTL is set

### Slow signing

- Hybrid mode (3 ms per credential) vs classical (50 µs): expected
- Cold start cost on first sign: subsequent are faster
- KMS-backed signing has network RTT: about 30-50 ms per sign for AWS
  KMS in same region

### Memory growth in long-running verifier

- Nonce store unbounded: ensure TTL cleanup is enabled
- DID Document cache unbounded: set `cache_max_entries`
- Status list cache unbounded: set `cache_max_entries` on `StatusListFetcher`

## Debugging tools

### Print a credential's canonical bytes (for signature debugging)

```python
from vouch.jcs import canonicalize
import json

# Without proofValue
to_canonicalize = {k: v for k, v in signed.items() if k != "proof"}
to_canonicalize["proof"] = {k: v for k, v in signed["proof"].items() if k != "proofValue"}

canonical = canonicalize(to_canonicalize)
print(canonical.hex())
```

### Diff two implementations' output

```bash
python -m vouch.jcs canonicalize < credential.json > python.bin
node -e "console.log(require('@vouch-protocol-official/sdk').canonicalize(...))" < credential.json > ts.bin
diff python.bin ts.bin
```

### Verify a specific test vector

```bash
cd test-vectors/hybrid-eddsa-mldsa44
PYTHONPATH=../.. python generate.py  # regenerate
python ../../tests/test_hybrid_interop.py
```

## When to file an issue

- Cross-language verification fails on a credential you can share
- A claimed-supported integration (LangChain, CrewAI, etc.) errors
- A test vector fails reproducibly on a clean checkout
- Documentation contradicts behavior

Repo: https://github.com/vouch-protocol/vouch/issues

## When to ask in Discord

- "How would you model X with Vouch?"
- "Is the Heartbeat Protocol overkill for my use case?"
- "Which KMS backend would you pick for Y?"

Discord: https://discord.gg/mMqx5cG9Y
