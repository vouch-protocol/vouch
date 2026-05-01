# Vouch ↔ Amnesia Integration

This document describes the optional, one-directional integration between
[Vouch Protocol](https://github.com/vouch-protocol/vouch) and
[Amnesia](https://github.com/vouch-protocol/amnesia). Both projects work fully
on their own. When deployed together, Vouch can produce W3C Verifiable
Credentials with Data Integrity proofs as cryptographic attestations of
Amnesia's egress decisions, giving you a tamper-evident audit trail that
travels with your code.

## When to use this integration

Use it when you need any of:

- **Audit trail for regulated environments.** Every push (or every push
  attempt) leaves behind a signed W3C VC 2.0 credential describing what was
  pushed, what policy was active, and what the egress decision was.
- **Cross-machine verifiability.** A signed attestation produced on
  developer A's machine can be verified by anyone with the issuer's DID
  resolution path. No shared infrastructure, no central audit server.
- **Post-quantum-ready audit logs.** With the
  `hybrid-eddsa-mldsa44-jcs-2026` cryptosuite, attestations remain
  verifiable even against future post-quantum adversaries.
- **Insurance / liability evidence.** A signed attestation chain is
  admissible evidence that a developer's machine performed deterministic
  policy evaluation at the moment of egress.

If none of these apply, Amnesia's plain-text logging is sufficient and you
do not need the bridge.

## What the bridge does NOT do

- It does not change Amnesia's enforcement behavior. Block / attest / allow
  are still decided by Amnesia's deterministic evaluator. The bridge only
  signs the result.
- It does not require Amnesia to know about Vouch. The bridge consumes
  Amnesia's output (`.vouch/blocks.log` or programmatic decision objects).
- It does not add latency to the pre-push hook. Attestation can be produced
  asynchronously after the hook decides.

## Architecture

```
   Developer typing in Claude Code / Cursor
                |
                v
      <r> ... </r>  rule capture
                |
                v
       .vouch/ledger/<rule>.json
                |
                v
       Amnesia.Synapse (Compactor)
                |
                v
              .vouchpolicy
                |
   git push -> .git/hooks/pre-push -> Amnesia.Cortex
                                          |
                  produces EgressDecision (deterministic)
                                          |
                +-------------------------+--------------------------+
                |                                                    |
                v                                                    v
     Standard Amnesia                                      Vouch ↔ Amnesia bridge
       blocks.log                                          (this integration)
       desktop notify                                              |
       silent block                                                v
                                                       Signed W3C VC 2.0
                                                   (eddsa-jcs-2022 or hybrid)
                                                              |
                                                              v
                                                  POST to audit endpoint /
                                                  store on disk / publish
```

## Python usage

```python
from vouch.integrations.amnesia import attest_decision, attest_decision_from_log
from vouch.signer import Signer

# Approach 1: programmatic (Amnesia invoked from Python)
signer = Signer.from_did_web('did:web:agent.example.com')
decision = {
    "workspace": "/home/user/project",
    "decided_at": "2026-04-30T08:34:12Z",
    "diff_hash": "sha256-...",
    "policy_hash": "sha256-...",
    "rule_decisions": [...],
    "overall": "block",
    "block_reason": "rule rule_xyz matched"
}
attestation = attest_decision(decision, signer)
# attestation.credential is the signed W3C VC ready to POST or store.

# Approach 2: read all decisions from Amnesia's blocks log
attestations = attest_decision_from_log(
    '/home/user/project/.vouch/blocks.log',
    signer,
)
for a in attestations:
    print(a.decision_overall, a.rule_count)
```

For the post-quantum hybrid embodiment:

```python
attestation = attest_decision(
    decision,
    signer,
    cryptosuite='hybrid-eddsa-mldsa44-jcs-2026',
)
```

## TypeScript usage

```typescript
import { attestDecision, attestDecisionsFromLog } from '@vouch-protocol/sdk/integrations/amnesia';
import { Signer } from '@vouch-protocol/sdk';

const signer = await Signer.fromDidWeb('did:web:agent.example.com');

const attestation = await attestDecision(decision, signer);
// attestation.credential is the signed W3C VC.

const all = await attestDecisionsFromLog(
    '/home/user/project/.vouch/blocks.log',
    signer,
);
```

## Wiring it into Amnesia.Cortex (optional)

If you want every push attempt to produce an attestation automatically,
configure Amnesia to call the bridge after each evaluation. In your
`.vouch/config.json`:

```json
{
    "version": 1,
    "attestationMode": "w3c-vc",
    "attestation": {
        "cryptosuite": "eddsa-jcs-2022",
        "issuerDid": "did:web:agent.example.com",
        "signerKeyPath": "~/.vouch/keys/agent.json",
        "outputPath": ".vouch/attestations/"
    }
}
```

When `attestationMode` is `"w3c-vc"`, Amnesia.Cortex calls into the Vouch
SDK after each decision, signs the attestation, and writes it to
`outputPath`. When `attestationMode` is `"plain"` (the default), Amnesia
produces only the JSON `blocks.log` entry.

The attestation file format is one signed VC per push attempt, named:

```
.vouch/attestations/<ISO-timestamp>_<diff-hash-prefix>.json
```

## Verification

A receiving auditor verifies an attestation using the standard Vouch
verification path. The credential contains:

- `issuer`: the DID of the developer's local Vouch identity
- `credentialSubject.policyVersion`: SHA-256 of the policy that was
  evaluated
- `credentialSubject.diffHash`: SHA-256 of the diff that was evaluated
- `credentialSubject.ruleDecisions`: per-rule match results
- `credentialSubject.decision`: overall verdict
- `proof`: Data Integrity proof using the configured cryptosuite

A verifier can:

1. Resolve the issuer DID and obtain the public key.
2. Verify the proof using the public key and the JCS-canonicalized
   credential bytes.
3. Confirm the proof is valid and the issuer is trusted.

If the proof verifies, the auditor has cryptographic evidence that:

- A specific developer's local Amnesia evaluator processed a specific diff
- Against a specific policy version
- And produced a specific decision
- At a specific moment

This is sufficient for compliance, insurance, or regulatory audit purposes.

## Reference disclosures

- [PAD-040](../disclosures/PAD-040-hybrid-composite-signature-same-canonical-bytes.md)
  Hybrid Composite Signature Bound to Same Canonical Bytes.
- [PAD-041](../disclosures/PAD-041-multikey-algorithm-agnostic-verification.md)
  Algorithm-Agnostic Verification Method Resolution via Multikey Multicodec.
- [PAD-048](../disclosures/PAD-048-write-only-async-context-ledger.md)
  Write-Only Asynchronous Context Ledger for LLM Coding Assistants.
- [PAD-050](../disclosures/PAD-050-zero-context-deterministic-egress-interception.md)
  Zero-Context Deterministic Egress Interception (defines the attestation
  mode that this bridge implements).

## License

Apache 2.0, same as both Vouch Protocol and Amnesia.
