# Python SDK Reference

The Python SDK (`vouch-protocol` on PyPI) is the reference implementation.
Most complete surface; other languages mirror its API.

## Install

```bash
pip install vouch-protocol            # core
pip install 'vouch-protocol[pq]'      # + hybrid post-quantum (ML-DSA-44)
pip install 'vouch-protocol[server]'  # + FastAPI bridge server
pip install 'vouch-protocol[all]'     # everything
```

## Identity

```python
from vouch import generate_identity, Signer

# Generate a new agent identity
keys = generate_identity("agent.example.com")  # returns KeyPair
# keys.did                = "did:web:agent.example.com"
# keys.private_key_jwk    = JWK JSON string (store securely)
# keys.public_key_jwk     = JWK JSON string (publish in DID Doc)

# Create a signer (constructor takes the private key JWK and the DID)
signer = Signer(private_key=keys.private_key_jwk, did=keys.did)

# Reload an existing identity from your own key store the same way:
# read the stored private_key_jwk and did, then construct a Signer.
signer = Signer(private_key=stored_private_key_jwk, did="did:web:agent.example.com")
```

## Credential issuance

```python
from vouch import build_vouch_credential

credential = build_vouch_credential(
    issuer_did="did:web:agent.example.com",
    intent={
        "action": "submit_claim",     # required
        "target": "claim:HC-001",      # required
        "resource": "https://insurance.example.com/claims/HC-001",  # required
    },
    valid_seconds=300,                 # default 300 (5 minutes)
    reputation_score=85,               # optional, [0, 100]
    delegation_chain=[...],            # optional, list of prior links
    credential_status={                # optional, BitstringStatusList entry
        "id": "...#42",
        "type": "BitstringStatusListEntry",
        "statusPurpose": "revocation",
        "statusListIndex": "42",
        "statusListCredential": "https://issuer.example/status/1",
    },
)

# Sign it
signed = signer.sign_credential(credential)
# signed is a dict ready to JSON-serialize and send
```

## Hybrid post-quantum issuance

```python
signer_pq = Signer(private_key=keys.private_key_jwk, did=keys.did)
signed_pq = signer_pq.sign_credential_hybrid(intent={
    "action": "submit_claim",
    "target": "claim:HC-001",
    "resource": "https://insurance.example.com/claims/HC-001",
})
# signed_pq["proof"]["cryptosuite"] == "hybrid-eddsa-mldsa44-jcs-2026"
```

## Verification

```python
from vouch import Verifier

# verify_credential returns a (is_valid, passport) tuple
is_valid, passport = Verifier.verify_credential(signed, public_key=keys.public_key_jwk)

if is_valid:
    p = passport
    print(f"Agent {p.subject_did} did {p.intent['action']} on {p.intent['resource']}")
else:
    print("Rejected")
```

Async verifier with concurrent DID resolution and caching. It returns the
same `(is_valid, passport)` tuple:

```python
from vouch import AsyncVerifier

async def main():
    verifier = AsyncVerifier()
    is_valid, passport = await verifier.verify_credential(signed)
```

## Session Vouchers (Heartbeat Protocol)

```python
from vouch import build_session_voucher

voucher = build_session_voucher(
    subject_did="did:web:agent.example.com",
    validator_dids=["did:web:validator.example.com"],
    decay_lambda=0.01,          # trust decay rate per second
    initial_trust=1.0,          # starting trust
    max_ttl_seconds=3600,       # hard expiry
    scope=["read", "write"],
    valid_seconds=120,
)
```

Then orchestrate with `HeartbeatSession` and validate with `HeartbeatValidator`.
See `reference/state-verifiability.md`.

## Trust Entropy decay

Verifiers consume the SessionVoucher's `decayLambda` to compute current trust:

```python
from vouch import compute_trust_at, check_trust_threshold
from datetime import datetime, timezone

trust = compute_trust_at(session_voucher, at_time=datetime.now(timezone.utc))
# trust = initialTrust * exp(-decayLambda * elapsed_seconds)

if check_trust_threshold(session_voucher, threshold=0.9):
    allow_high_stakes_operation()
```

## Reputation engine

```python
from vouch import ReputationEngine, RedisReputationStore, ReputationEvent

engine = ReputationEngine(store=RedisReputationStore(url="redis://localhost:6379"))

# Record events
await engine.record_event(ReputationEvent(
    did="did:web:agent.example.com",
    action_type="success",
    delta=1,
    reason="claim_submitted_successfully",
))

# Read score and tier
score = await engine.get_score("did:web:agent.example.com")
print(score.score, score.tier)  # e.g., 85, "trusted"
```

Backends: `MemoryReputationStore`, `RedisReputationStore`, `KafkaReputationStore`.

## DID-level revocation

```python
from vouch import RevocationRegistry, RedisRevocationStore, RevocationRecord

registry = RevocationRegistry(store=RedisRevocationStore(url="redis://localhost:6379"))

await registry.revoke(RevocationRecord(
    did="did:web:compromised-agent.example.com",
    revoked_at=int(time.time()),
    reason="key_compromised",
))

# Verifier consults this on every verification
```

## BitstringStatusList (credential-level revocation)

```python
from vouch import (
    StatusList,
    build_status_list_credential,
    build_status_list_entry,
    verify_status,
    StatusListFetcher,
    FilesystemStatusListStore,
)

# Issuer side
store = FilesystemStatusListStore("/var/lib/vouch/status-1.json")
try:
    status_list = store.load()
except FileNotFoundError:
    status_list = StatusList(status_list_id="https://issuer.example/status/1")

# Issue new credential with status entry
index = status_list.allocate_index()
store.save(status_list)  # persist cursor

entry = build_status_list_entry(
    status_list_credential="https://issuer.example/status/1",
    status_list_index=index,
)
# attach `entry` as credential_status when signing

# Revoke later
status_list.revoke(index)
store.save(status_list)
status_credential = build_status_list_credential(
    issuer_did="did:web:issuer.example",
    status_list=status_list,
)
signed_status_credential = signer.sign_credential(status_credential)
# publish at the stable URL

# Verifier side
fetcher = StatusListFetcher(cache_ttl_seconds=300)
status_credential = fetcher.get(signed["credentialStatus"]["statusListCredential"])
is_revoked = verify_status(
    credential_status=signed["credentialStatus"],
    status_list_credential=status_credential,
)
```

## CLI

`pip install vouch-protocol` installs the `vouch` command:

```
vouch init [--domain DOMAIN] [--env]    Generate keypair + DID
vouch credential sign [--hybrid]        Sign a Verifiable Credential
vouch credential verify                 Verify a Verifiable Credential
vouch git init                          One-command Git workflow setup
vouch reputation get [--did DID]        Fetch reputation score
vouch revocation check [--did DID]      Check revocation status
```

## Modules quick-map

| Module | Purpose |
|---|---|
| `vouch.signer` | Credential signing (legacy JWS + modern VC) |
| `vouch.verifier` | Verification with structured reasons |
| `vouch.async_verifier` | High-throughput async verification |
| `vouch.vc` | VC envelope builders |
| `vouch.data_integrity` | eddsa-jcs-2022 proof construction |
| `vouch.data_integrity_hybrid` | hybrid-eddsa-mldsa44-jcs-2026 |
| `vouch.multikey` | Multikey encode / decode |
| `vouch.did_web` | did:web resolver and DID Document builder |
| `vouch.kms` | KMS abstraction (AWS, GCP, Azure, local) |
| `vouch.keys` | Local keypair generation |
| `vouch.jcs` | RFC 8785 canonicalization |
| `vouch.status_list` | BitstringStatusList primitives |
| `vouch.status_list_fetcher` | HTTPS fetcher with cache |
| `vouch.revocation` | DID-level revocation registry |
| `vouch.reputation` | Reputation engine and storage |
| `vouch.cache` | DID Doc cache (Memory, Redis, Tiered) |
| `vouch.nonce` | Nonce store for replay defense |
| `vouch.ratelimit` | Token-bucket rate limiting |
| `vouch.metrics` | Prometheus metrics |
| `vouch.canary` | Heartbeat canary commit/reveal chain |
| `vouch.behavioral_attestation` | Behavioral digest builder |
| `vouch.merkle` | Merkle tree primitives |
| `vouch.heartbeat` | Heartbeat Protocol orchestration |
| `vouch.quorum` | Validator quorum coordination |
| `vouch.trust_entropy` | Trust decay computation |
| `vouch.cli` | Command-line interface |
| `vouch.integrations.*` | Framework wrappers |
