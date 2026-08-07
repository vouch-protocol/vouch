# Robotics conformance crosswalk

A clause-by-clause assessment of the five built-in profiles in
`vouch/robotics/conformance.py`: for each requirement, what the profile claims,
whether the cited credential genuinely evidences it, and what the regime
requires that Vouch does not cover at all.

The module describes its profiles as "a reference crosswalk to make conformance
verifiable in the open, not legal advice." This document is the audit of that
crosswalk. It is deliberately unflattering where the mapping is thin.

---

## Sourcing, and the limits of this review

**This review could not consult the primary text of any of the five regimes.**
That is a hard constraint of the environment it was produced in, and it bounds
every conclusion below.

| Source | Status | Consequence |
|---|---|---|
| EU AI Act, Reg (EU) 2024/1689 | **Consulted, via a third-party reproduction.** EUR-Lex and every mirror tried are blocked by this environment's egress proxy (verified: `CONNECT ... 403`). The operative text of Arts. 12-15 was instead read from a public reproduction of the Official Journal text, [`bojkovski-cpu/ai-act-annotated`](https://github.com/bojkovski-cpu/ai-act-annotated) (`src/data/articles_en.json`, all 113 articles). | Article-level assessments below are quoted from that reproduction and marked `[text]`. It is **not** the Official Journal: a reproduction can contain transcription errors, so a notified body should re-check against EUR-Lex. It is nonetheless a large improvement on recollection. |
| EU Machinery Reg 2023/1230 | **Not consulted.** Same reason. | As above. Annex III 1.1.9 and 1.2.1 assessments are corroborated by secondary sources cited inline. |
| ISO 10218-1/-2 | **Not consulted — paywalled.** ISO texts are not free. | Clause *content* is not asserted anywhere below. Only clause *numbering and edition status* are discussed, from secondary sources. |
| ISO/TS 15066 | **Not consulted — paywalled.** | As above. One likely-incorrect clause number is flagged, not corrected. |
| UL 3300 | **Not consulted — paywalled.** | As above. |

Consequently **no requirement below is marked "verified against primary text",**
because none is. Every row carries a provenance marker:

- `[secondary]` — corroborated by at least one independent secondary source, cited.
- `[unverified]` — consistent with general knowledge of the regime, but not
  corroborated from any source consulted here. Treat as a hypothesis.
- `[structural]` — a conclusion that needs no regulation text, because it follows
  from the profile's own data (e.g. a citation that is not a clause reference,
  or two requirements citing the same clause).
- `[text]` — quoted from the operative text of the article (EU AI Act only, via
  the third-party reproduction named above).
- `[demonstrated]` — executed against this branch's `check_conformance` and
  observed. These are the only claims here backed by evidence rather than
  reading, and they are all claims about the *checker*, never about a regulation.

Three checker weaknesses were confirmed by execution and are the most actionable
findings in this document:

```python
# All three return satisfied=True.
check_conformance([{... "RobotSafetyRecordCredential", {"totalEvents": 0}}],   "iso-10218")
check_conformance([{... "RobotHeartbeatCredential", {"motionDigest": {..., "withinEnvelope": False}}}],
                  "iso-ts-15066")
check_conformance([{... "RobotIdentityCredential", {"hardwareRoot": {"kind": "TPM"}}}], "ul-3300")
```

A robot that recorded **zero** safety events evidences a records requirement; a
heartbeat that reports an envelope **breach** evidences the continuous-monitoring
requirement; and an identity credential with **no hardware attestation** evidences
a hardware-binding requirement.

Anything an assessor intends to rely on must be re-checked against the purchased
standard or the official journal text. **Where this document and the actual
regulation disagree, the regulation governs.**

## Evidence-strength legend

| Strength | Meaning |
|---|---|
| **full** | The credential, as checked, is substantive evidence for the clause as a whole. |
| **partial** | The credential evidences part of the clause, or evidences a declaration about the clause rather than the underlying behaviour. |
| **none** | The check does not meaningfully evidence the clause; it confirms a field is present. |

One caveat applies to every row and is not repeated: `check_conformance`
verifies **structure and coverage, not proofs**. It confirms a credential of the
right type carries a non-empty field at a path. It does not verify signatures
(the caller must do that first), and it cannot check that a declared value is
*true*. A `maxForceN` of 80 N evidences that someone signed a declaration of
80 N — not that the robot cannot exceed it.

---

## 1. `eu-ai-act-high-risk` — EU AI Act high-risk systems

Assessed against the operative text of Arts. 12-15 `[text]`.

| Clause | Credential → field | Strength | Notes |
|---|---|---|---|
| Art. 12 — Record-keeping | `RobotSafetyRecordCredential` → `logHead` | **partial** | `[text]` Art. 12(1): systems "shall technically allow for the **automatic recording of events (logs) over the lifetime of the system**". Art. 12(2) requires logging to enable recording of events relevant for (a) identifying risk situations or substantial modification, (b) facilitating post-market monitoring under Art. 72, (c) monitoring operation under Art. 26(5). `logHead` is strong evidence that recorded entries are **complete and unaltered**, which is more than a plain log offers. It is not evidence that logging is enabled, that it spans the lifetime, or that the recorded events cover the three categories in 12(2). |
| Art. 13 — Transparency and provision of information to deployers | `ModelProvenanceAttestation` → `vla.modelName`, `vla.configHash` | **partial** | `[text]` The title itself is decisive: Art. 13(2)-(3) require the system to be **accompanied by instructions for use** containing an enumerated list — provider identity, characteristics/capabilities/limitations, accuracy metrics, foreseeable misuse, the human-oversight measures of Art. 14, expected lifetime and maintenance. A model name and config hash are provenance facts, not instructions for use. Notably **Art. 13(3)(f)** asks for "a description of the mechanisms ... that allows deployers to properly collect, store and interpret the **logs** in accordance with Article 12" — the closest fit to what Vouch produces, and the profile does not target it. |
| Art. 14 — Human oversight | `PhysicalCapabilityScope` → `physicalScope.maxSpeedNearHumansMps` | **partial** | `[text]` **Art. 14(4)(e)** requires oversight to enable a person "to **intervene** in the operation of the high-risk AI system or **interrupt the system through a 'stop' button** or a similar procedure that allows the system to come to a halt in a safe state", and 14(4)(d) to "disregard, override or reverse the output". A near-human speed cap is a relevant enforced limit but addresses none of that. This text **confirms proposal P1**: Vouch's `KillSwitchCredential` maps directly onto 14(4)(e), and the profile ignores it. |
| Art. 15 — Accuracy, robustness and cybersecurity | `ModelProvenanceAttestation` → `vla.weightsHash` | **partial** | `[text]` Art. 15(1) requires an appropriate level of accuracy, robustness and cybersecurity, performing consistently "throughout their lifecycle"; **15(3)** puts the accuracy metrics in the instructions for use; **15(5)** requires resilience against unauthorised third parties altering use, outputs or performance, naming data poisoning, model poisoning, adversarial examples and model flaws. A weights hash pins *which build ran*, so a claimed accuracy figure can be bound to an artifact and model-poisoning after the fact becomes detectable — genuinely relevant to 15(5). It is no evidence of accuracy, robustness, or the other attack classes. |

**What the EU AI Act requires that Vouch does not cover at all** `[unverified]`:
risk management system (Art. 9); data and data governance (Art. 10); technical
documentation (Art. 11); quality management system (Art. 17); conformity
assessment (Art. 43); registration (Art. 49); post-market monitoring (Art. 72);
serious-incident reporting (Art. 73). **The profile covers four articles of a
regime whose obligations run across roughly a dozen.** A `CONFORMS` result on
this profile should never be read as "AI Act compliant".

## 2. `iso-10218` — ISO 10218-1/-2 industrial robots

> **Edition problem, and it is serious.** The profile declares `version: "2011"`.
> **ISO 10218-1:2025 and ISO 10218-2:2025 were published in February 2025 and
> came into force on 1 April 2025**, the first major revision since 2011
> `[secondary]`. The profile therefore maps to a **superseded edition**. The
> revision is not cosmetic: it adds functional-safety and cybersecurity
> requirements, introduces new robot/application classifications, and
> normatively integrates ISO/TS 15066 `[secondary]`.
> Sources: [A3 — Updated ISO 10218 FAQ](https://www.automate.org/robotics/blogs/updated-iso-10218-faq),
> [IBF Solutions — new EN ISO 10218-1 and -2](https://www.ibf-solutions.com/en/seminars-and-news/news/new-standards-for-industrial-robots-en-iso-10218-1-and-2),
> [ISO 10218-1:2025 catalogue entry](https://www.iso.org/obp/ui/en/#!iso:std:73933:en).

| Clause | Credential → field | Strength | Notes |
|---|---|---|---|
| ISO 10218-1:2011, 5.2 — Identification bound to hardware | `RobotIdentityCredential` → `hardwareRoot.kind` | **partial** | `[unverified]` Clause content not consulted (paywalled). Note the check tests only `hardwareRoot.kind` — the string `"TPM"` — and **not** `hardwareRoot.attestation`. A credential naming a root kind with no attestation satisfies this check `[demonstrated]`. The full `verify_robot_identity` does check the attestation, but the conformance check does not. See proposal P2. |
| ISO 10218-1:2011, 5.3 — Software/config integrity | `ModelProvenanceAttestation` → `vla.weightsHash` | **partial** | `[unverified]` Clause content not consulted. |
| ISO 10218-1:2011, 5.6 — Limiting speed, force, workspace | `PhysicalCapabilityScope` → `maxForceN`, `maxSpeedMps` | **partial** | `[unverified]` The title says "speed, force, **and workspace**", but the check does not require `allowedZones`. The workspace limb of the requirement is unevidenced. See proposal P3. |
| ISO 10218-2:2011, 5.2 — Records of safety-relevant events | `RobotSafetyRecordCredential` → `totalEvents` | **none** | `[demonstrated]` `totalEvents` is satisfied by the value `0`… only because `check_conformance` treats `0` as present (it rejects `None`, `[]`, `{}` — not `0`). A robot that recorded nothing passes. The credential also carries `logHead`, which would at least tie the count to a tamper-evident chain, and is not required here. See proposal P4. |

**What ISO 10218 requires that Vouch does not cover** `[unverified]`: the whole
of mechanical design, actuating-power control, protective stop and emergency-stop
circuitry, safety-rated function performance levels (PL/SIL per ISO 13849 /
IEC 62061), singularity protection, axis-limiting devices, validation and
verification methods, and integrator-side cell design in Part 2. Vouch evidences
*declarations and records about* a robot; it does not evidence the functional
safety engineering that these standards are principally about.

---

## 3. `iso-ts-15066` — ISO/TS 15066 collaborative robots

> **Two problems, both material.**
>
> **(a) The clause numbers appear to be wrong.** Multiple secondary sources
> place ISO/TS 15066's collaborative techniques as: 5.5.2 safety-rated monitored
> stop, 5.5.3 hand guiding, **5.5.4 speed and separation monitoring**, with power
> and force limiting following as 5.5.5 `[secondary]`. The profile cites **5.5.4
> for "power and force limiting"** and **5.5.2 for "defined collaborative
> workspace"**. If the secondary sources are right, both citations are
> misattributed — 5.5.4 would be SSM, and 5.5.2 would be the safety-rated
> monitored stop, not the workspace definition.
> Sources: [NIST/PMC — Implementing speed and separation monitoring](https://pmc.ncbi.nlm.nih.gov/articles/PMC5117641/),
> [Engineering.com — What is ISO/TS 15066?](https://www.engineering.com/standardizing-collaborative-robots-what-is-iso-ts-15066/),
> [ISO news release](https://www.iso.org/news/2016/03/Ref2057.html).
> **This has NOT been corrected in code.** Correcting a clause citation on the
> strength of secondary summaries of a paywalled standard would substitute one
> unverified claim for another. It must be checked against the purchased text
> and then fixed. Flagged, deliberately not "fixed".
>
> **(b) The document may be superseded.** Most ISO/TS 15066:2016 requirements
> have been incorporated into ISO 10218-2:2025 `[secondary]`, and the revised
> ISO 10218 drops "collaborative operation" in favour of "collaborative
> application" — terminology this profile still uses. Whether a standalone
> 15066 profile should continue to exist is a design decision, not a bug.

| Clause (as cited) | Credential → field | Strength | Notes |
|---|---|---|---|
| 5.5.4 — Power and force limiting | `PhysicalCapabilityScope` → `maxSpeedNearHumansMps`, `maxForceN` | **partial** | Clause number likely misattributed (above). As evidence: PFL in 15066 is defined by biomechanical limits per body region — pressure and force thresholds against a body model. A single scalar `maxForceN` is a coarse proxy for a per-body-region table. |
| 5.5.2 — Defined collaborative workspace | `PhysicalCapabilityScope` → `allowedZones` | **partial** | Clause number likely misattributed (above). A zone-name list is a plausible expression of a collaborative workspace, but carries no geometry. |
| 5.2 — Continuous monitoring | `RobotHeartbeatCredential` → `motionDigest` | **partial** | `[unverified]` This is the strongest mapping in the profile: the motion digest reports observed peak force, speed, near-human speed and zone breaches for the interval, and asserts `withinEnvelope`. Two limits: it is the robot's **self-report**, not independent witness; and the check requires only that `motionDigest` be present, not that `withinEnvelope` be `true`. **A heartbeat reporting a breach satisfies this requirement** `[demonstrated]`. See proposal P5. |

**What ISO/TS 15066 requires that Vouch does not cover** `[unverified]`: the
biomechanical limit tables themselves, the transient/quasi-static contact
distinction, pressure and pressure-distribution measurement, the protective
separation distance calculation for SSM (which depends on measured stopping
distance and system latency), and the validation methodology for contact events.

---

## 4. `eu-machinery-2023-1230` — EU Machinery Regulation 2023/1230

| Clause | Credential → field | Strength | Notes |
|---|---|---|---|
| Annex III 1.7.4 — Identification and traceability | `RobotIdentityCredential` → `make`, `model`, `serial` | **full** | `[unverified]` This is the best mapping in any of the five profiles. 1.7.4 concerns information and markings; make/model/serial bound to a hardware root is squarely responsive, and arguably exceeds what a printed plate provides. |
| Annex III 1.1.9 — Protection against corruption | `ModelProvenanceAttestation` → `vla.weightsHash`, `vla.safetyPolicy` | **partial** | `[secondary]` 1.1.9 requires the machine to *identify the software installed necessary to operate safely and provide that information at all times in an easily accessible form*, to protect safety-critical software and data against accidental or intentional corruption, **and to collect evidence of legitimate or illegitimate intervention (tamper evidence)**. The provenance attestation addresses software identification well. It does **not** address the tamper-evidence limb — for which Vouch has an exactly-fitting primitive (the black box / safety ledger) that this requirement does not reference. See proposal P6. Source: [Nemko — Machinery Regulation cybersecurity obligations](https://www.nemko.com/blog/eu-machinery-regulation-2023/1230), [IBF — prEN 50742](https://www.ibf-solutions.com/en/seminars-and-news/news/new-standard-pren-50742-protection-against-corruption). |
| Annex III 1.2.1 — Safety and reliability of control systems | `PhysicalCapabilityScope` → `maxForceN` | **partial** | `[secondary]` 1.2.1 requires safety-related control systems to be immune to accidental failure and to withstand reasonably foreseeable malicious third-party attempts. A declared force cap is weak evidence for a clause substantially about control-system integrity and resilience. |
| Annex III 1.2.1 — Recording of safety-relevant data | `RobotSafetyRecordCredential` → `totalEvents` | **partial** | `[structural]` **This is the second requirement citing 1.2.1** — the profile maps two distinct obligations to one clause. At least one citation is likely misplaced; the tamper-evidence/recording obligation reads more naturally against 1.1.9 (above). Same `totalEvents: 0` weakness as ISO 10218. |

**What the Machinery Regulation requires that Vouch does not cover**
`[unverified]`: the entire EHSR set beyond these clauses — materials, stability,
mechanical hazards, guards, emergency stop, ergonomics, noise, vibration,
emissions — plus technical file assembly (Annex IV), conformity assessment
procedures (Annex XI), the Declaration of Conformity, CE marking, and the
instructions for use. Note also the timing: the Regulation applies from
**20 January 2027**, so any mapping should be revisited before then.

---

## 5. `ul-3300` — UL 3300 service, communication and mobile robots

> **The citations in this profile are not clause references.** `[structural]`
> All four are descriptive labels — `"UL 3300, identification"`,
> `"UL 3300, operating limits"`, `"UL 3300, sensing integrity"`,
> `"UL 3300, incident records"` — where every other profile cites a numbered
> clause (`"Reg (EU) 2024/1689, Art. 12"`, `"ISO 10218-1:2011, 5.2"`).
> An assessor cannot look these up. This conclusion needs no access to UL 3300:
> it follows from comparing the profile's own strings.
>
> **Not corrected in code**, because supplying real clause numbers requires the
> paywalled text, and inventing plausible-looking ones would be considerably
> worse than leaving them visibly generic. See proposal P7.

| Citation (as written) | Credential → field | Strength | Notes |
|---|---|---|---|
| "UL 3300, identification" | `RobotIdentityCredential` → `hardwareRoot.kind` | **partial** | Same `hardwareRoot.kind`-only weakness as ISO 10218 (P2). |
| "UL 3300, operating limits" | `PhysicalCapabilityScope` → `maxSpeedMps`, `allowedZones` | **partial** | Coherent as a declaration of limits. |
| "UL 3300, sensing integrity" | `PerceptionProvenanceCredential` → `frameHash` | **partial** | Binds a captured frame to the robot's key, so a substituted or edited frame is detectable *after* capture. It says nothing about sensor integrity *before* capture — a spoofed sensor produces a faithfully signed frame. |
| "UL 3300, incident records" | `RobotSafetyRecordCredential` → `totalEvents` | **none** | Same `totalEvents: 0` weakness (P4). |

**What UL 3300 requires that Vouch does not cover**: not assessable here — the
standard was not consulted. UL 3300 is a safety-certification standard covering
electrical, mechanical, battery, and functional safety construction and testing
requirements; on that basis alone, the great majority of it is outside what
credentials can evidence. Stated as an expectation, not a finding.

---

## Proposed changes

Proposals only — **no change has been made to `conformance.py` in this PR.**
See "Why nothing was changed in code" below.

| # | Proposal | Rationale |
|---|---|---|
| **P1** | Add a requirement to `eu-ai-act-high-risk` mapping Art. 14 to `KillSwitchCredential` (field `command`), alongside the existing scope-based one. | Art. 14 oversight centres on the ability to intervene and interrupt. Vouch already has the primitive; the profile ignores it. |
| **P2** | Add `hardwareRoot.attestation` to the fields of `iso10218-identification` and `ul3300-identity`. | Requiring only `hardwareRoot.kind` lets a credential asserting `"TPM"` with no attestation pass a *hardware-binding* requirement. |
| **P3** | Add `physicalScope.allowedZones` to `iso10218-limits`. | The requirement title says "speed, force, and workspace"; the workspace limb is currently unchecked. |
| **P4** | Add `logHead` to the fields of every `totalEvents` requirement (`iso10218-records`, `eu-mr-records`, `ul3300-records`), matching what `eu-aia-record-keeping` already does. | Ties the count to a tamper-evident chain, and stops a robot with zero recorded events from evidencing a records requirement on the strength of `totalEvents: 0`. |
| **P5** | Extend the checker so a requirement can assert a *value*, not just presence — then require `motionDigest.withinEnvelope == true` for `iso15066-monitoring`. | Today a heartbeat that reports an envelope breach satisfies the continuous-monitoring requirement. This needs a checker change (`_credential_satisfies` currently tests presence only), so it is the largest of these proposals. |
| **P6** | Re-point the Machinery "recording of safety-relevant data" requirement from Annex III 1.2.1 to 1.1.9, and add the black-box/safety-ledger head as evidence. | 1.1.9 explicitly requires collecting evidence of legitimate or illegitimate intervention `[secondary]`; two requirements currently share 1.2.1. |
| **P7** | Replace the four UL 3300 pseudo-citations with real clause numbers from the purchased standard. | Ungrounded citations cannot be checked by an assessor. |
| **P8** | Decide the edition question for `iso-10218` (map to :2025, or state explicitly that the profile targets the withdrawn :2011 edition) and whether `iso-ts-15066` should persist as a standalone profile now that its content sits in ISO 10218-2:2025. | Currently the profile silently targets a superseded edition. |

## Status of the proposals

**P2, P3, P4 and P5 have since been implemented** (commit `30cc6344`).
Requirements gained an
`expect` map so a requirement can assert a *value* and not merely presence; the
continuous-monitoring requirement now requires `motionDigest.withinEnvelope` to
be true; the three records requirements require `logHead`; the two
hardware-binding requirements require `hardwareRoot.attestation`; and the
ISO 10218 limits requirement requires `allowedZones`. All three
`[demonstrated]` weaknesses above are closed, in Python, TypeScript, Go and the
Rust core alike, with the pinned interop digest unchanged.

**The tables above describe the profiles as they stood when audited**, not as
they stand now.

P1 is now supported by the operative text (Art. 14(4)(e), quoted above) and
remains open. P6, P7 and P8 remain open: each still needs a text that could not
be reached from here.

## Why the regulatory citations are still unchanged

The brief permitted changing `conformance.py` "where a mapping is clearly wrong
or clearly missing". Three candidates initially looked to qualify — the ISO/TS
15066 clause numbers, the ISO 10218 edition, and the UL 3300 pseudo-citations.
Each was left alone on the same reasoning:

- The **15066 clause numbers** are probably wrong, but "probably, per secondary
  summaries of a standard I could not read" is not a sound basis for editing a
  compliance artifact. Replacing one unverified citation with another unverified
  citation is not an improvement — it just moves the error and launders its
  provenance.
- The **ISO 10218 edition** is genuinely superseded `[secondary]`, but changing
  `version` to `"2025"` would assert that the four requirements map to the 2025
  text, which was not checked. That would convert a stale-but-honest profile into
  a current-looking but unfounded one.
- The **UL 3300 citations** need real clause numbers, which require the standard.

Where a change would have to rest on text that could not be read, flagging beats
editing. Each is written up above so it can be fixed in one pass by someone with
the documents in hand.

## Recommended next steps

1. Buy ISO 10218-1/-2:2025, ISO/TS 15066:2016 and UL 3300, and settle P7, P8 and
   the 15066 clause numbering against the real text.
2. Apply P2, P3 and P4 — these need no paywalled text; they are internal
   consistency fixes, each currently lets an empty or degenerate credential
   satisfy a requirement, and each is a small, testable change.
3. Consider P5, which needs a checker capability (value assertions, not just
   presence) and is the difference between "a heartbeat exists" and "the robot
   stayed in its envelope".
4. Have a notified body or a competent regulatory counsel review the AI Act and
   Machinery mappings against the official journal text. Nothing in this document
   substitutes for that.

---

*Reviewed against `vouch/robotics/conformance.py` as of this branch: 5 profiles,
19 requirements. No primary regulatory text was accessible during this review;
see "Sourcing, and the limits of this review" above.*
