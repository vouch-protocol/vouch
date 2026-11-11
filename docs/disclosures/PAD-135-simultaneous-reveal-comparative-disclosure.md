# PAD-135: Simultaneous-Reveal Comparative Disclosure

**Identifier:** PAD-135  
**Title:** Method by Which Mutually Distrustful Parties Compare Sensitive Measurements by Committing Them to a Common Append-Only Log and Revealing Only After the Round Closes by Log Index, So No Party Can Condition Its Disclosure on Another's and Non-Participation Is a Dated Attributable Event  
**Publication Date:** September 10, 2026  
**Prior Art Effective Date:** September 10, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** AI Governance / Fair Exchange / Commitment Schemes / Multilateral Measurement  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-131 (Immutable Red Line Commitment), PAD-130 (Capability-Proportional Sequential Delay), PAD-134 (Sealed Dissent Registration), PAD-125 (Census-Complete Compute Ceiling Attestation), PAD-030 (Zero-Knowledge Reputation Portability)  

---

## 1. Abstract

Two parties each need to know something about the other and neither will go first, because
whoever discloses first discloses into an information asymmetry the other can exploit. This
method removes the ordering advantage. A round is opened by a descriptor fixing the
participants, the measurement schema, the closing index in a common append-only log, and
the comparison predicate. Each participant appends a blinded commitment to its measurement
before the closing index. The round closes when the log passes that index. Only then does
the reveal phase begin, and a reveal is checked against a commitment that was fixed before
any participant could observe another's value.

Because the closing boundary is a log index rather than a wall-clock deadline, the ordering
is established by a structure none of the participants controls, and a participant that
fails to commit before the boundary is recorded as a dated, attributable non-commitment
rather than as an absence. Non-participation therefore carries information instead of
concealing it.

Where the comparison is ordinal, participants may commit to differences against a common
committed reference rather than to absolute values, so the round can establish which party
stands where without any party publishing a magnitude at all.

Key innovations:

- **Closure by log index**, so the commitment boundary rests on a shared append-only
  structure instead of on any participant's clock or on a coordinator's discretion.
- **Non-commitment as a positive dated record**, so declining to participate is visible and
  attributable rather than silent.
- **Ordinal rounds over committed differences**, so relative standing is establishable
  without disclosure of absolute values.

---

## 2. Problem Statement

### 2.1 First disclosure is a penalty

In any comparison between rivals, the party that discloses first grants the others the
option to disclose or withhold with knowledge of the first value. Rational parties
therefore all wait, and no comparison occurs.

### 2.2 A trusted coordinator is not available

Schemes that solve the ordering problem by routing values through a neutral party require
the participants to agree on one, to trust it not to leak, and to trust it not to
participate itself. Among rivals of comparable weight there is often no such party.

### 2.3 Deadlines set by clocks are contestable

A wall-clock deadline depends on whose clock, and a participant near the boundary can
dispute or exploit the ambiguity. The boundary must be a fact all participants observe
identically.

### 2.4 Absence is ambiguous

Where a participant simply does not respond, its silence is indistinguishable from a
failure of the channel, and no consequence can attach to it.

---

## 3. Solution (The Invention)

**Round descriptor.** A signed descriptor opens the round and fixes: the participant
identifiers, the measurement schema and units, the closing log index, the comparison
predicate to be evaluated, and the reveal deadline expressed as a further index. The
descriptor is itself appended to the log, so the round's terms are fixed and dated before
any commitment.

**Commitment phase.** Each participant computes the digest of its canonical measurement
concatenated with a fresh blinding value, signs the commitment together with the round
identifier, and appends it. A commitment appearing at an index at or beyond the closing
index is outside the round.

**Closure.** The round closes when the log's size passes the closing index. Closure is
therefore observed identically by every participant, and the set of in-round commitments is
fixed and provable by inclusion proofs against a signed tree head at closure.

**Non-commitment record.** At closure, participants named in the descriptor with no
in-round commitment are enumerated in a signed closure record. Their non-participation is
dated, attributable, and provable against the log, and it may itself be an input to
downstream predicates.

**Reveal phase.** After closure, each committed participant appends its canonical
measurement and blinding value. A reveal is valid only if it recomputes to the participant's
in-round commitment. A participant that reveals nothing before the reveal deadline is
recorded as committed-and-unrevealed, which is distinguishable from both a valid reveal and
a non-commitment.

**Predicate evaluation.** The declared predicate, such as maximum, ordering, threshold
crossing, or equality, is evaluated over the valid reveals. Because the predicate is fixed
in the descriptor before commitment, no participant can select the comparison after seeing
the values.

**Ordinal variant.** Where absolute values are too sensitive to reveal even after closure,
participants commit to signed differences against a reference value committed in the
descriptor. Revealing differences establishes ordering and gaps without establishing
levels. The same closure and non-commitment machinery applies unchanged.

**Predicate-only variant.** Where a proving system is available, participants may satisfy
the predicate by publishing a proof over their commitments rather than revealing, so the
round yields the predicate's truth value alone.

**Composition.** A round's output supplies the measurement records used by other
mechanisms, including the capability increment that parameterizes a required sequential
delay and the corroboration count that may release a sealed registration.

---

## 4. Prior Art Differentiation

Commitment schemes, sealed-bid auctions, fair exchange protocols, secure multiparty
computation, and append-only logs are prior art. This disclosure does not claim them. What
is differentiated is:

- **Defining the commitment boundary as an index in a shared append-only log**, so closure
  is a fact observed identically by all participants and requires no coordinator and no
  agreement on clocks.
- **Producing a signed closure record enumerating named non-committers**, so declining to
  participate is a dated attributable event that downstream predicates may consume.
- **Distinguishing committed-and-unrevealed from non-committed**, so two different failures
  carry two different meanings.
- **The ordinal variant over committed differences against a descriptor-committed
  reference**, establishing relative standing without disclosure of levels.
- **Fixing the comparison predicate in the round descriptor before commitment**, so the
  question cannot be chosen after the answers are known.

Sealed-bid auctions rely on an auctioneer to hold bids and to declare the close. Fair
exchange protocols address two-party simultaneity for goods and payment. Neither yields a
multi-party round whose closure, participation, and non-participation are all provable
against a public structure that none of the participants operates.

---

## 5. Technical Implementation

A reference implementation defines the signed round descriptor with its closing and reveal
indices, blinded commitment construction and appending, closure evaluation against log size
with inclusion proofs, the signed closure record enumerating non-committers, reveal
validation against commitments, the committed comparison predicates, the ordinal variant
over committed differences, and the states distinguishing valid reveal, unrevealed, and
non-committed, all over `eddsa-jcs-2022` Data Integrity proofs and JCS canonicalization.

---

## 6. Claims Summary

1. A method in which parties compare sensitive measurements by appending blinded
   commitments to a common append-only log, where the commitment phase closes at a log index
   fixed in advance by a signed round descriptor.
2. The method of claim 1 wherein closure is determined by the log's size passing the
   declared index, so the boundary is observed identically by every participant without a
   coordinator and without reliance on any participant's clock.
3. The method of claim 1 wherein the round descriptor fixes the participants, measurement
   schema, comparison predicate, and reveal deadline before any commitment is made, so the
   comparison cannot be chosen after the values are known.
4. The method of claim 1 wherein a signed closure record enumerates named participants
   holding no in-round commitment, so non-participation is a dated attributable event
   consumable by downstream predicates.
5. The method of claim 1 wherein a participant that committed and did not reveal by the
   reveal deadline is recorded in a state distinct from both valid reveal and
   non-commitment.
6. The method of claim 1 wherein a reveal is accepted only if it recomputes to the
   participant's in-round commitment.
7. The method of claim 1 wherein participants commit to signed differences against a
   reference value fixed in the descriptor, so the round establishes relative standing
   without disclosing absolute values.
8. The method of claim 1 wherein participants satisfy the declared predicate by publishing a
   proof over their commitments rather than revealing, so only the predicate's truth value
   results.
9. The method of claim 1 wherein the round's output supplies measurement records consumed by
   a further mechanism, comprising a capability increment parameterizing a required
   sequential delay or a corroboration count releasing a sealed registration.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of the date
above. The methods are released under Apache 2.0 and may be freely implemented, to prevent
patenting by any party and to keep them available to the open Vouch Protocol ecosystem and
to the wider AI governance and verification communities.
