# The Vouch robotics evidence pack: a note for assessors

*For compliance, risk, and conformity-assessment readers. This describes what the
evidence pack is, what it proves, how you verify it yourself, and — just as
importantly — what it does not prove.*

---

## What it is

A robot accumulates claims about itself during normal operation: which machine it
is, what software it runs, what physical limits it is held to, what safety events
it recorded. Ordinarily those claims reach an assessor as a vendor's PDF: the
vendor asserts, and you decide how much to trust the assertion.

The evidence pack is the same information as **six digitally signed credentials**,
each independently checkable with public cryptography. You do not have to trust
the vendor's report, and you do not have to trust Vouch. You re-run the check
yourself, offline, and get the same answer or you do not.

The pack is then mapped, clause by clause, onto five regulatory regimes: the
**EU AI Act** high-risk requirements, **ISO 10218-1/-2**, **ISO/TS 15066**, the
**EU Machinery Regulation 2023/1230**, and **UL 3300**. The output states, per
clause, whether the presented evidence satisfies it — or names the exact gap.

## The six credentials, and what each one attests

| Credential | What it attests | What it cannot tell you |
|---|---|---|
| **Robot identity** | This is machine *make / model / serial*, and its software identity key is bound to a specific hardware root (a TPM or secure element) that signed the binding. | That the hardware root itself is genuine — that rests on the silicon vendor's trust chain. |
| **Model provenance** | The exact vision-language-action model, weights hash, safety policy, and configuration the robot was running. Re-signed on every over-the-air update, forming a chain of what ran when. | Whether the model is *safe* — only which model it was. |
| **Physical capability scope** | The force, speed, near-human speed, zones, and shift windows the robot is permitted. Signed, so the limit is attributable to whoever set it. | That the robot's actuators physically obey it (see "what it does not prove"). |
| **Safety record** | A tamper-evident, hash-linked ledger of safety events (incidents, near-misses, overrides, envelope breaches), summarised and signed. | That every real-world event was *recorded* — only that recorded entries were not altered or removed. |
| **Heartbeat with motion digest** | Over the last interval the robot's actual peak force, speed, near-human speed and zone breaches stayed inside the declared envelope. | Anything about intervals for which no heartbeat was produced. |
| **Perception provenance** | The sensor frames the robot acted on, bound by hash to the robot's key and hash-linked in sequence. | That the sensors were not physically spoofed upstream of capture. |

## How you verify it yourself

No account, no vendor portal, no network call to us. Everything below runs on
your own machine against the artifact you were given.

1. **Get the artifact.** The pack is JSON — six credentials plus one signed
   conformance attestation per regime.
2. **Install the open-source reference implementation.** `pip install
   vouch-protocol` (or use the TypeScript, Go, Rust, C, Swift, JVM, .NET or C++
   implementations — all reproduce identical results byte for byte).
3. **Check each signature** against the issuer's published public key. The
   format is the W3C Verifiable Credentials Data Integrity standard with the
   `eddsa-jcs-2022` cryptosuite — not a Vouch-proprietary format.
4. **Re-run the conformance check** yourself: `check_conformance(credentials,
   "eu-ai-act-high-risk")`. You get a deterministic report — same inputs, same
   output, on any implementation.
5. **Verify the assessor's attestation**, which binds the full report by
   cryptographic digest. Alter one character of the embedded report and
   verification fails.

The critical property: **step 4 does not depend on us.** If our implementation
and yours disagree, that is a bug you can demonstrate.

## The worked artifact

This is the actual, unedited output of the reference example
(`python examples/robotics_ai_act_evidence_pack.py`). Note that the first block
deliberately shows an *incomplete* pack, so you can see the tool reporting gaps
rather than only successes:

```
base credential set (identity, provenance, scope, safety record):
  eu-ai-act-high-risk      CONFORMS (4/4)  EU AI Act high-risk systems
  iso-10218                CONFORMS (4/4)  ISO 10218-1/-2 industrial robots
  iso-ts-15066             GAPS     (2/3)  ISO/TS 15066 collaborative robots
    gap: ISO/TS 15066:2016, 5.2: Continuous monitoring of the collaborative operation
  eu-machinery-2023-1230   CONFORMS (4/4)  EU Machinery Regulation 2023/1230
  ul-3300                  GAPS     (3/4)  UL 3300 service, communication, and mobile robots
    gap: UL 3300, sensing integrity: Integrity of perception used for safe operation

full evidence pack (6 credentials):
  eu-ai-act-high-risk      CONFORMS (4/4)  EU AI Act high-risk systems
  iso-10218                CONFORMS (4/4)  ISO 10218-1/-2 industrial robots
  iso-ts-15066             CONFORMS (3/3)  ISO/TS 15066 collaborative robots
  eu-machinery-2023-1230   CONFORMS (4/4)  EU Machinery Regulation 2023/1230
  ul-3300                  CONFORMS (4/4)  UL 3300 service, communication, and mobile robots

signed attestations (5 profiles):
  eu-ai-act-high-risk      verifies=True  reportDigest=uMuWAsxwdw8uZVkW...
  iso-10218                verifies=True  reportDigest=uVAP1stf9MCglXYl...
  iso-ts-15066             verifies=True  reportDigest=uoSx4OGx6X-CuC8O...
  eu-machinery-2023-1230   verifies=True  reportDigest=u-Niyinnn4ZQ_9AA...
  ul-3300                  verifies=True  reportDigest=u7tslKJ4LRSBotZZ...
```

Two things worth noticing. The tool **names the specific open clause** rather
than failing silently — a missing motion digest is reported as the ISO/TS 15066
continuous-monitoring clause, and missing perception provenance as the UL 3300
sensing-integrity clause. And `reportDigest` binds each attestation to one exact
report; a later edit to the report invalidates it.

## What this does not prove

Stated plainly, because an overstated claim here would be worse than no claim.

- **It is not a certification, and not a substitute for one.** Nothing here
  makes a robot compliant or authorises CE marking. It produces evidence that
  a conformity-assessment process can consume.
- **The clause mapping is a reference crosswalk, not legal advice.** It is our
  reading of how a credential relates to a clause. A notified body's reading
  governs. The mapping is published openly so it can be argued with; see
  `docs/robotics-conformance-crosswalk.md` for the per-clause assessment,
  including where we consider the evidence only partial.
- **Cryptography proves attribution and integrity, not physics.** A signed
  scope credential proves *who declared* a 0.5 m/s near-human limit and that the
  declaration was not altered. It does not prove the actuators obeyed it. The
  heartbeat's motion digest is the robot's own self-report; it is tamper-evident,
  not independently witnessed.
- **A signature says nothing about the truthfulness of the signer.** If a robot
  is compromised, or an operator signs false data, the credential faithfully
  records that false claim — attributably. The value is that the claim is
  non-repudiable and traceable to a key, not that it is true.
- **Absence of evidence is not covered.** The ledger proves recorded entries
  were not tampered with. It cannot prove nothing was omitted before recording.
- **Standards coverage is uneven.** The EU AI Act and Machinery Regulation texts
  are public and the mapping is against them directly. ISO 10218, ISO/TS 15066
  and UL 3300 are paywalled; those mappings are built from clause structure and
  publicly available summaries, and are flagged accordingly in the crosswalk.

## Maturity, honestly

This is an **open-source reference implementation**, not a certified product.
The formats are open and vendor-neutral, built on W3C Verifiable Credentials
rather than anything proprietary. Nine independent implementations (Python,
TypeScript, Go, Rust, C, C++, Swift, JVM, .NET) produce byte-identical output,
and a shared interop vector pins that equivalence in CI.

What does not exist yet: certified or maintained regulatory profiles, hosted
continuous monitoring, an auditor evidence portal, or any third-party attestation
that the crosswalk is correct. Those are deliberately out of scope for the open
layer.

**The proposition is reproducible evidence, not certification.** If that is
useful to your assessment process, the most productive next step is to take the
worked artifact above, verify it independently, and tell us where the crosswalk
is wrong.

---

*Reference implementation: <https://github.com/vouch-protocol/vouch> ·
Evidence pack: `examples/robotics_ai_act_evidence_pack.py` ·
Clause-by-clause assessment: `docs/robotics-conformance-crosswalk.md`*
