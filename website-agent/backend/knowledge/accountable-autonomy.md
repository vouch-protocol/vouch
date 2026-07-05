# Accountable Autonomy Reference

Identity and delegation prove who acted and under what authority. They do not,
on their own, bound what an already-authorized agent may do, slow down an
irreversible action, prove why the agent acted, or make the record public. The
accountable-autonomy runtime adds five Python SDK modules that do, each an
ordinary `eddsa-jcs-2022` Verifiable Credential so it verifies across the
language SDKs.

## Reasoned Action Proofs (`vouch.reasoning`)

The agent states *why* before it acts, ties each reason to a real artifact by its
hash, and escrows the justification before executing. An auditor can then prove
the reasoning was neither fabricated (each anchor must resolve and hash-match) nor
rewritten after the fact (the justification must recompute to the committed
digest), and that it was committed before execution.

```python
from vouch import Signer, generate_identity
from vouch.reasoning import (
    build_justification, evidence_anchor, sign_reasoned_action,
    verify_reasoned_action, verify_justification, LocalEscrow, justification_digest,
)

k = generate_identity("agent.example.com"); agent = Signer(private_key=k.private_key_jwk, did=k.did)
intent = {"action": "delete", "target": "/tmp/cache", "resource": "/tmp/cache/*"}
just = build_justification(intent, [evidence_anchor("user asked", ref="msg:1", evidence={"text": "clean /tmp"})])
cred = sign_reasoned_action(agent, intent=intent, justification=just)
ok, subject = verify_reasoned_action(cred, k.public_key_jwk)
good, reason = verify_justification(just, subject, resolver={"msg:1": {"text": "clean /tmp"}}.get)
```

Structured reasons: `justification_digest_mismatch`, `evidence_unresolved`,
`evidence_hash_mismatch`, `escrow_after_execution`.

## Proof of Deliberation (`vouch.deliberation`)

A reversible action runs instantly. An irreversible one (wire funds, delete
without backup, publish, actuate) must commit and broadcast a signed intent with
a challenge window and a set of authorized objectors, wait out the window, and
survive any veto before a verifier accepts the execute credential. The agent
cannot shorten the window (the verifier checks the elapse) and cannot clear its
own veto (the veto authority is a separate DID).

```python
from vouch.deliberation import (
    commit_intent, execute, veto_intent, check_execution, CLASS_IRREVERSIBLE_FINANCIAL,
)

intent = commit_intent(agent, intent={"action": "transfer_funds", "target": "acct:v1", "resource": "usd:5000"},
                       reversibility_class=CLASS_IRREVERSIBLE_FINANCIAL, min_seconds=900,
                       veto_authorities=["did:web:controller"])
ex = execute(agent, intent_credential=intent)  # only accepted once the window has elapsed
reason = check_execution(ex, intent, k.public_key_jwk)   # None, or challenge_window_not_elapsed / vetoed
```

Structured reasons: `challenge_window_not_elapsed`, `vetoed`, `intent_mismatch`,
`unauthorized_executor`.

## Executable Caveats (`vouch.caveats`)

Delegation narrows static fields (action, target, resource, time, rate). Caveats
add live conditions ("only for shipped orders", "under the lifetime spend",
"business hours") attached to a delegation link. Caveats accumulate down the
chain, no descendant can drop an ancestor's caveat (the verifier requires the
chain to root at the grantor), and every verifier must evaluate every accumulated
caveat. A standard caveat library evaluates identically across languages; a
custom module-hash caveat is the escape hatch.

```python
from vouch.caveats import build_capability, verify_capability, flag_true, value_ceiling

link1 = build_capability(ceo, to=mgr.get_did(), attenuation={"action": "refund"},
                         caveats=[flag_true("shipped-only", field="shipped")])
link2 = build_capability(mgr, to=agent.get_did(), attenuation={"action": "refund", "resource": "usd:<=200"},
                         caveats=[value_ceiling("under-200", field="amount", limit=200)], parent=link1)
reason = verify_capability([link1, link2], keys.get, {"shipped": True, "amount": 120}, root_issuer=ceo.get_did())
```

Structured reasons: `caveat_denied:<id>`, `unrooted_capability`, `broken_chain`,
`verifier_budget_exceeded`.

## Inference Provenance (`vouch.provenance`)

Binds an output to a fingerprint of the model weights and a Merkle root over the
context it was grounded in, plus the sampler settings. An auditor can re-fetch
the sources to reproduce the context root (catching a fabricated or substituted
context) and re-run the model on the same seed to byte-compare the output.

```python
from vouch.provenance import sign_inference_provenance, verify_context, check_replay, weights_hash

cred = sign_inference_provenance(agent, output={"action": "approve_refund"},
                                 model_weights_hash=weights_hash(b"...weights..."),
                                 context_chunks=[{"source": "policy://refunds", "text": "..."}],
                                 sampler={"seed": 42, "temperature": 0.0})
ok, subject = verify_inference_provenance(cred, k.public_key_jwk)
good, reason = verify_context([{"source": "policy://refunds", "text": "..."}], subject)  # context_root_mismatch on tamper
```

Structured reasons: `context_root_mismatch`, `output_mismatch`, `weights_mismatch`.

## Action Transparency (`vouch.transparency`)

Consequential actions are submitted to an append-only RFC 6962 Merkle log that
signs its size and root as a Signed Tree Head. A verifier can demand an inclusion
proof that an action is in the log; a monitor can demand a consistency proof that
an older tree head is a strict prefix of a newer one, so the log cannot silently
omit an action or rewrite history, and comparing tree heads across observers
catches a split view.

```python
from vouch.transparency import TransparencyLog, sign_tree_head, check_inclusion, check_consistency

log = TransparencyLog()
i = log.append({"agent": "did:web:a", "action": "transfer_funds", "amount": "usd:5000"})
sth = sign_tree_head(log_operator, log)
reason = check_inclusion({"agent": "did:web:a", "action": "transfer_funds", "amount": "usd:5000"},
                         i, sth, log.inclusion_proof(i), log_public_key=log_keys.public_key_jwk)
```

Structured reasons: `inclusion_failed`, `consistency_failed`, `tree_shrank`,
`invalid_signed_tree_head`.

## How they compose

None of these verify an agent's mind. Together they make harm irrational and
unhidable even for a misaligned agent: it must state a reason on the record
(reasoning), wait out a window a human can veto (deliberation), stay inside an
authority that cannot be broadened (caveats), against a decision that is
reproducible (provenance), in front of a public append-only log (transparency).
