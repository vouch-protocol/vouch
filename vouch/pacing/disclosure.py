"""
Simultaneous-Reveal Comparative Disclosure (PAD-135).

Two parties each need to know something about the other and neither will go
first, because whoever discloses first discloses into an asymmetry the other can
exploit. This module removes the ordering advantage.

A signed round descriptor fixes the participants, the measurement schema, the
comparison predicate, the closing log index, and the reveal deadline. Each
participant appends a blinded commitment before the closing index. The round
closes when the log passes that index, which is a fact every participant
observes identically, so no coordinator is needed and no party's clock enters
the trust base. Only then does the reveal phase begin.

Non-participation carries information instead of concealing it: a named
participant with no in-round commitment is enumerated in a signed closure
record, and a participant that committed and never revealed is recorded in a
state distinct from both.

Where absolute values are too sensitive to reveal at all, the ordinal variant
has participants commit to differences against a reference fixed in the
descriptor, so the round establishes relative standing without establishing
levels.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ._common import (
    PacingError,
    base_credential,
    blinded_commitment,
    constant_time_eq,
    digest_of,
    mb64,
    subject_of,
    unmb64,
    verify_credential,
)

DESCRIPTOR_TYPE = "VouchDisclosureRoundDescriptor"
COMMITMENT_TYPE = "VouchDisclosureCommitment"
REVEAL_TYPE = "VouchDisclosureReveal"
CLOSURE_TYPE = "VouchDisclosureClosureRecord"

PREDICATE_MAXIMUM = "maximum"
PREDICATE_ORDERING = "ordering"
PREDICATE_THRESHOLD = "threshold-crossing"
PREDICATE_EQUALITY = "equality"
KNOWN_PREDICATES = frozenset(
    {PREDICATE_MAXIMUM, PREDICATE_ORDERING, PREDICATE_THRESHOLD, PREDICATE_EQUALITY}
)

MODE_ABSOLUTE = "absolute"
MODE_ORDINAL = "ordinal-difference"

STATE_REVEALED = "revealed"
STATE_UNREVEALED = "committed-unrevealed"
STATE_NOT_COMMITTED = "not-committed"

REASON_INVALID_PROOF = "invalid_proof"
REASON_NOT_A_PARTICIPANT = "not_a_participant"
REASON_ROUND_MISMATCH = "round_mismatch"
REASON_LATE_COMMITMENT = "commitment_after_closing_index"
REASON_REVEAL_MISMATCH = "reveal_does_not_open_commitment"
REASON_LATE_REVEAL = "reveal_after_deadline"
REASON_DUPLICATE_COMMITMENT = "duplicate_commitment"
REASON_UNKNOWN_PREDICATE = "unknown_predicate"


def open_round(
    signer: Any,
    *,
    round_id: str,
    participants: Sequence[str],
    schema: Dict[str, Any],
    closing_index: int,
    reveal_index: int,
    predicate: str,
    mode: str = MODE_ABSOLUTE,
    reference_value: Optional[float] = None,
) -> Dict[str, Any]:
    """
    Publish the round descriptor, fixing every term before any commitment.

    Args:
        signer: Whoever opens the round, which may be any participant.
        round_id: A stable identifier for the round.
        participants: The named participants.
        schema: The measurement schema and units.
        closing_index: The log index at which the commitment phase closes.
        reveal_index: The log index by which reveals must be present.
        predicate: The comparison to be evaluated, fixed before the values exist.
        mode: Absolute values, or ordinal differences against a reference.
        reference_value: The reference the ordinal mode measures differences from.
    """
    if len(set(participants)) < 2:
        raise PacingError("a round needs at least two distinct participants")
    if predicate not in KNOWN_PREDICATES:
        raise PacingError(f"unknown predicate: {predicate!r}")
    if mode not in (MODE_ABSOLUTE, MODE_ORDINAL):
        raise PacingError(f"unknown mode: {mode!r}")
    if reveal_index <= closing_index:
        raise PacingError("reveal_index must be after closing_index")
    if mode == MODE_ORDINAL and reference_value is None:
        raise PacingError("ordinal mode requires a reference_value in the descriptor")
    subject: Dict[str, Any] = {
        "id": round_id,
        "convenor": signer.get_did(),
        "participants": sorted(participants),
        "schema": dict(schema),
        "closingIndex": int(closing_index),
        "revealIndex": int(reveal_index),
        "predicate": predicate,
        "mode": mode,
    }
    if reference_value is not None:
        subject["referenceValue"] = float(reference_value)
    return base_credential(signer, DESCRIPTOR_TYPE, subject)


def descriptor_digest(descriptor: Dict[str, Any]) -> str:
    """Canonical digest of a round descriptor, which commitments bind to."""
    return digest_of(descriptor)


def commit_measurement(
    signer: Any,
    *,
    descriptor: Dict[str, Any],
    value: float,
    blinding: bytes,
    log_index: int,
) -> Dict[str, Any]:
    """
    Append a blinded commitment to a measurement before the round closes.

    In ordinal mode the committed value is the difference from the descriptor's
    reference, so a reveal later establishes standing without establishing level.
    """
    if not isinstance(blinding, (bytes, bytearray)) or len(blinding) < 16:
        raise PacingError("blinding must be at least 16 bytes")
    subject_descriptor = subject_of(descriptor)
    payload = {"round": subject_descriptor.get("id"), "value": float(value)}
    return base_credential(
        signer,
        COMMITMENT_TYPE,
        {
            "id": f"{subject_descriptor.get('id')}#{signer.get_did()}",
            "round": subject_descriptor.get("id"),
            "descriptor": descriptor_digest(descriptor),
            "participant": signer.get_did(),
            "commitment": blinded_commitment(payload, blinding),
            "logIndex": int(log_index),
        },
    )


def reveal_measurement(
    signer: Any,
    *,
    descriptor: Dict[str, Any],
    value: float,
    blinding: bytes,
    log_index: int,
) -> Dict[str, Any]:
    """Publish the value and blinding after the round has closed."""
    subject_descriptor = subject_of(descriptor)
    return base_credential(
        signer,
        REVEAL_TYPE,
        {
            "id": f"{subject_descriptor.get('id')}#{signer.get_did()}",
            "round": subject_descriptor.get("id"),
            "descriptor": descriptor_digest(descriptor),
            "participant": signer.get_did(),
            "value": float(value),
            "blinding": mb64(bytes(blinding)),
            "logIndex": int(log_index),
        },
    )


def is_closed(descriptor: Dict[str, Any], log_size: int) -> bool:
    """True once the log has passed the descriptor's closing index."""
    return int(log_size) > int(subject_of(descriptor).get("closingIndex", 0))


@dataclass
class RoundState:
    """Every participant's state in one round, after closure."""

    round_id: str
    committed: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    revealed: Dict[str, float] = field(default_factory=dict)
    states: Dict[str, str] = field(default_factory=dict)
    reasons: List[str] = field(default_factory=list)

    @property
    def non_committers(self) -> List[str]:
        """Named participants that never committed in the round."""
        return sorted(name for name, state in self.states.items() if state == STATE_NOT_COMMITTED)

    @property
    def unrevealed(self) -> List[str]:
        """Participants that committed and never revealed."""
        return sorted(name for name, state in self.states.items() if state == STATE_UNREVEALED)


def collect_round(
    descriptor: Dict[str, Any],
    *,
    commitments: Sequence[Dict[str, Any]],
    reveals: Sequence[Dict[str, Any]],
    participant_public_keys: Dict[str, Any],
    convenor_public_key: Any,
    log_size: int,
) -> RoundState:
    """
    Build the round's state from the published commitments and reveals.

    A commitment at or beyond the closing index is outside the round. A reveal
    that does not recompute to its participant's in-round commitment is rejected,
    and a reveal after the deadline is rejected, each with its own reason.
    """
    if not verify_credential(descriptor, convenor_public_key, DESCRIPTOR_TYPE):
        state = RoundState(round_id="")
        state.reasons.append(REASON_INVALID_PROOF)
        return state

    subject = subject_of(descriptor)
    round_id = str(subject.get("id"))
    digest = descriptor_digest(descriptor)
    closing = int(subject.get("closingIndex", 0))
    reveal_deadline = int(subject.get("revealIndex", 0))
    participants = list(subject.get("participants") or [])
    state = RoundState(round_id=round_id)

    for commitment in commitments:
        body = commitment.get("credentialSubject") or {}
        participant = body.get("participant")
        if participant not in participants:
            state.reasons.append(REASON_NOT_A_PARTICIPANT)
            continue
        if not verify_credential(
            commitment, participant_public_keys.get(participant), COMMITMENT_TYPE
        ):
            state.reasons.append(REASON_INVALID_PROOF)
            continue
        if commitment.get("issuer") != participant or body.get("descriptor") != digest:
            state.reasons.append(REASON_ROUND_MISMATCH)
            continue
        index = body.get("logIndex")
        if not isinstance(index, int) or index >= closing:
            state.reasons.append(REASON_LATE_COMMITMENT)
            continue
        if participant in state.committed:
            state.reasons.append(REASON_DUPLICATE_COMMITMENT)
            continue
        state.committed[participant] = commitment

    for reveal in reveals:
        body = reveal.get("credentialSubject") or {}
        participant = body.get("participant")
        if participant not in state.committed:
            state.reasons.append(REASON_NOT_A_PARTICIPANT)
            continue
        if not verify_credential(reveal, participant_public_keys.get(participant), REVEAL_TYPE):
            state.reasons.append(REASON_INVALID_PROOF)
            continue
        if reveal.get("issuer") != participant or body.get("descriptor") != digest:
            state.reasons.append(REASON_ROUND_MISMATCH)
            continue
        index = body.get("logIndex")
        if not isinstance(index, int) or index <= closing or index > reveal_deadline:
            state.reasons.append(REASON_LATE_REVEAL)
            continue
        try:
            blinding = unmb64(str(body.get("blinding")))
        except PacingError:
            state.reasons.append(REASON_REVEAL_MISMATCH)
            continue
        payload = {"round": round_id, "value": float(body.get("value", 0.0))}
        expected = (state.committed[participant].get("credentialSubject") or {}).get("commitment")
        if not constant_time_eq(blinded_commitment(payload, blinding), str(expected)):
            state.reasons.append(REASON_REVEAL_MISMATCH)
            continue
        state.revealed[participant] = float(body.get("value"))

    for participant in participants:
        if participant in state.revealed:
            state.states[participant] = STATE_REVEALED
        elif participant in state.committed:
            state.states[participant] = STATE_UNREVEALED
        else:
            state.states[participant] = STATE_NOT_COMMITTED

    return state


def closure_record(
    signer: Any, *, descriptor: Dict[str, Any], state: RoundState, log_size: int
) -> Dict[str, Any]:
    """
    Sign the round's closure, enumerating who did not commit.

    Declining to participate becomes a dated attributable event that downstream
    predicates can consume, rather than an absence indistinguishable from a
    channel failure.
    """
    if not is_closed(descriptor, log_size):
        raise PacingError("the round has not closed yet")
    return base_credential(
        signer,
        CLOSURE_TYPE,
        {
            "id": state.round_id,
            "descriptor": descriptor_digest(descriptor),
            "logSize": int(log_size),
            "committed": sorted(state.committed),
            "nonCommitters": state.non_committers,
            "unrevealed": state.unrevealed,
        },
    )


def evaluate_predicate(
    descriptor: Dict[str, Any], state: RoundState, *, threshold: Optional[float] = None
) -> Dict[str, Any]:
    """
    Evaluate the predicate the descriptor fixed before any value existed.

    In ordinal mode the revealed values are differences from the descriptor's
    reference, so ordering and gaps are established without levels.
    """
    subject = subject_of(descriptor)
    predicate = str(subject.get("predicate"))
    values = dict(state.revealed)
    if not values:
        return {"predicate": predicate, "result": None, "participants": []}

    if predicate == PREDICATE_MAXIMUM:
        leader = max(values, key=lambda name: values[name])
        return {"predicate": predicate, "result": leader, "value": values[leader]}
    if predicate == PREDICATE_ORDERING:
        order = sorted(values, key=lambda name: values[name], reverse=True)
        return {"predicate": predicate, "result": order, "gaps": _gaps(values, order)}
    if predicate == PREDICATE_THRESHOLD:
        if threshold is None:
            raise PacingError("threshold-crossing requires a threshold")
        crossed = sorted(name for name, value in values.items() if value >= float(threshold))
        return {"predicate": predicate, "result": crossed, "threshold": float(threshold)}
    if predicate == PREDICATE_EQUALITY:
        distinct = set(round(value, 12) for value in values.values())
        return {"predicate": predicate, "result": len(distinct) == 1}
    raise PacingError(f"unknown predicate: {predicate!r}")


def _gaps(values: Dict[str, float], order: Sequence[str]) -> List[float]:
    """Successive gaps down the ordering."""
    return [
        float(values[order[index]] - values[order[index + 1]]) for index in range(len(order) - 1)
    ]


def absolute_from_ordinal(descriptor: Dict[str, Any], difference: float) -> float:
    """Recover an absolute value from an ordinal difference, given the reference."""
    reference = subject_of(descriptor).get("referenceValue")
    if reference is None:
        raise PacingError("descriptor carries no reference value")
    return float(reference) + float(difference)
