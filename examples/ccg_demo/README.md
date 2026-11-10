# Vouch Protocol: delegation, decay, and heartbeat demos

Three short scripts that show how Vouch Protocol decides whether an AI agent may
act. Each runs offline in under a second, needs no API keys, and uses a fake
clock instead of waiting. Every case prints one ALLOWED / DENIED (or ACCEPTED /
REJECTED) line, and a script exits 0 only when every case matches its expected
outcome.

## Install

```bash
pip install "vouch-protocol==3.0.0"
```

Then, from a checkout of this repository:

```bash
bash examples/ccg_demo/run_all.sh
```

Or run one at a time, for example `python3 examples/ccg_demo/01_delegation.py`.
The scripts import the installed `vouch` package.

## 01_delegation.py: authority only narrows

Alice grants her assistant read and update on her calendar with a $50 spend cap.
The assistant re-delegates read only, capped at $20, to a sub-agent.

| Case | Outcome |
|---|---|
| a) sub-agent reads the calendar | ALLOWED |
| b) sub-agent spends $15 | ALLOWED |
| c) sub-agent updates the calendar | DENIED, outside its grant |
| d) sub-agent spends $30 | DENIED, over its $20 cap |
| e1) sub-agent grants a grandchild update | DENIED, broader than its own grant |
| e2) sub-agent grants a grandchild a $100 cap | DENIED, broader than its own grant |
| f) Alice's grant is edited after signing | DENIED, signature check |
| g) a grant claims to be from Alice but is not signed by her | DENIED, signature check |

The claim: every signed grant travels inside the delegation chain, so a verifier
decides from the credential alone that each step stays within the one before it
on action, target, resource, time, rate, and policy (including spend caps), that
each grant names the next delegate, and that the chain roots at the principal it
trusts. No policy server is involved. Where a case is denied, the script also
shows that a credential built by hand to get around the signer is still refused
by the verifier.

## 02_trust_decay.py: trust decays until it is renewed

A validator with the default settings (initial trust 1.0, decay 0.01 per second,
a 120 second voucher) issues a signed SessionVoucher. The script prints the
trust at 0, 10, 30, 70, and 120 seconds and which action tiers it still allows:
critical needs 0.9, sensitive 0.75, routine 0.5.

The claim: trust is a number a verifier recomputes at the moment of the action,
trust(t) = initialTrust x exp(-decayLambda x t), so an agent that stops renewing
loses the right to high-stakes actions first (after about 10.5 seconds), then
sensitive ones (about 28.8 seconds), then routine ones (about 69.3 seconds).

## 03_heartbeat.py: renewal needs a live, signed, in-order agent

| Case | Outcome |
|---|---|
| a1, a2) signed beats on time | ACCEPTED |
| b) a beat replayed | REJECTED |
| c) beats delivered out of order | REJECTED |
| d1) a beat after three missed intervals (limit two) | REJECTED, session lapses |
| d2) a routine action on the last voucher | DENIED, trust has decayed and the voucher expired |
| d3) an on-time beat after the lapse | REJECTED until the session is reset |
| e1) an unsigned beat | REJECTED |
| e2) a beat edited after signing | REJECTED |
| f1) a sensitive transfer under authority epoch 5 | ALLOWED |
| f2) the same transfer after the authority moves to epoch 6 (suspended) | DENIED, though decayed trust still passes |

The claim: a SessionVoucher is renewed only for a heartbeat the agent signed,
made within the validator's time window, next in sequence, consistent with the
canary commit/reveal chain, and matching the Merkle root of the actions it
reports. Missing more than the allowed number of intervals lapses the session.
For sensitive actions, a newer authority epoch refuses an older voucher at once,
without waiting for its trust to decay.
