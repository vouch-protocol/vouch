# Conformance Reference

Vouch conformance proves that an implementation, an SDK, a fork, or a
port, produces byte-correct protocol output and supports the required
feature sets. It is implementation-level, and distinct from robotics
regulatory conformance (`check_conformance`, the ISO and EU profiles),
which grades a robot against a regulation.

Levels are cumulative: a level is achieved only when every check at that
level and all lower levels passes.

## The three levels

**L1 Credential.** RFC 8785 JCS canonicalization, `eddsa-jcs-2022` sign
and verify, the validity window (an expired credential is rejected), and
nonce replay resistance.

**L2 Structural-Security.** Everything in L1, plus BitstringStatusList
revocation, delegation narrowing with the five-link depth bound, the
Identity Sidecar allow and deny behaviour, and a hash-linked audit trail.

**L3 State Verifiable + Post-Quantum.** Everything in L2, plus the
post-quantum proof set (an `eddsa-jcs-2022` proof and an `mldsa44-jcs-2024`
proof over the same document), the Heartbeat renewal chain, and an M-of-N
validator quorum.

Robotics is a separate profile, Robotics Conformant, not part of L1 to L3.

## Test your implementation (self-test)

The reference runner checks an implementation against the levels and
reports the highest it fully satisfies:

```
python -m vouch.conformance
```

It runs the checks in-process against the SDK (canonicalization against
the shared JCS vectors, a sign and verify round-trip with tamper
rejection, revocation, delegation narrowing, the sidecar allow and deny
behaviour, the audit trail, the post-quantum proof set, the heartbeat chain,
and the validator quorum) and prints a per-check pass or fail with the
highest passing level.

## The verified badge (coming)

The self-test proves conformance to yourself. A hosted verifier turns it
into a Vouch-verified, re-checkable result: it issues fresh random
challenges, re-checks every response server-side with the canonical
core, derives the level, and mints a signed `VouchConformanceCredential`
unique to your implementation. Because the verifier recomputes every
expected answer, a pass cannot be faked by replaying the public test
vectors. The badge links to the credential, so anyone can re-verify
Vouch's signature and re-run the challenges.

Until that is live, the `/conformance` page carries a self-declaration
and shows what a verified pass will earn.

Spec: section 17 (Conformance Levels).
