"""
Unit tests for Validator Quorum (Specification §11.6).
"""

import pytest

from vouch.heartbeat import HeartbeatSession, HeartbeatValidator
from vouch.quorum import (
  ROLE_BEHAVIORAL,
  ROLE_BUDGET,
  ROLE_POLICY,
  HeartbeatQuorum,
  QuorumError,
  QuorumPolicy,
  QuorumValidator,
)


AGENT_DID = "did:web:agent.example.com"


def _validator(did: str, **overrides) -> HeartbeatValidator:
  defaults = dict(
    validator_did=did,
    initial_trust=1.0,
    decay_lambda=0.01,
    max_ttl_seconds=3600,
    voucher_valid_seconds=120,
    scope=["agent_actions"],
  )
  defaults.update(overrides)
  return HeartbeatValidator(**defaults)


class TestQuorumConstruction:
  def test_requires_at_least_one_validator(self):
    with pytest.raises(QuorumError):
      HeartbeatQuorum(validators=[], threshold=1)

  def test_threshold_must_be_positive(self):
    with pytest.raises(QuorumError):
      HeartbeatQuorum(
        validators=[QuorumValidator(validator=_validator("did:web:v1.example.com"))],
        threshold=0,
      )

  def test_threshold_above_total_weight_rejected(self):
    with pytest.raises(QuorumError):
      HeartbeatQuorum(
        validators=[
          QuorumValidator(validator=_validator("did:web:v1.example.com")),
          QuorumValidator(validator=_validator("did:web:v2.example.com")),
        ],
        threshold=3,
      )

  def test_duplicate_validator_dids_rejected(self):
    with pytest.raises(QuorumError):
      HeartbeatQuorum(
        validators=[
          QuorumValidator(validator=_validator("did:web:v1.example.com")),
          QuorumValidator(validator=_validator("did:web:v1.example.com")),
        ],
        threshold=1,
      )

  def test_negative_weight_rejected(self):
    with pytest.raises(QuorumError):
      QuorumValidator(
        validator=_validator("did:web:v1.example.com"), weight=-1.0
      )


class TestQuorumValidation:
  def _build_2_of_3(self):
    v1 = QuorumValidator(
      validator=_validator("did:web:v1.example.com"), role=ROLE_POLICY
    )
    v2 = QuorumValidator(
      validator=_validator("did:web:v2.example.com"), role=ROLE_BEHAVIORAL
    )
    v3 = QuorumValidator(
      validator=_validator("did:web:v3.example.com"), role=ROLE_BUDGET
    )
    return HeartbeatQuorum(validators=[v1, v2, v3], threshold=2)

  def test_three_of_three_approve(self):
    quorum = self._build_2_of_3()
    session = HeartbeatSession(subject_did=AGENT_DID)
    req = session.build_request().to_dict()
    result = quorum.validate(req)
    assert result.ok is True
    assert result.votes_for == 3
    assert len(result.approving_dids) == 3
    assert result.rejections == {}

  def test_two_of_three_approve_when_one_validator_has_canary_break(self):
    # Make the first validator process a prior chain that will then
    # disagree with the agent's actual chain.
    quorum = self._build_2_of_3()
    session = HeartbeatSession(subject_did=AGENT_DID)

    # Seed v1 with a different agent's chain to corrupt its view.
    other_session = HeartbeatSession(subject_did=AGENT_DID)
    other_session.build_request() # advance other_session's chain
    # Now feed v1 a heartbeat from other_session under the SAME (subject, session_id)
    # by manually setting session_id (simulating a competing emitter).
    spoof_req = other_session.build_request().to_dict()
    spoof_req["session_id"] = session.session_id
    quorum.validators[0].validator.validate(spoof_req)

    # Now the legitimate agent submits its first real heartbeat.
    real_req = session.build_request().to_dict()
    result = quorum.validate(real_req)
    # v1 sees a stale interval (already saw index 1); v2 and v3 are fresh.
    # With threshold=2 and 2 fresh validators approving, the quorum still issues.
    assert result.ok is True
    assert result.votes_for >= 2

  def test_below_threshold_rejects(self):
    # 3-of-3 quorum
    v1 = QuorumValidator(validator=_validator("did:web:v1.example.com"))
    v2 = QuorumValidator(validator=_validator("did:web:v2.example.com"))
    v3 = QuorumValidator(validator=_validator("did:web:v3.example.com"))
    quorum = HeartbeatQuorum(validators=[v1, v2, v3], threshold=3)

    session = HeartbeatSession(subject_did=AGENT_DID)

    # Pre-poison v1 so it rejects the next request as stale.
    first_req = session.build_request().to_dict()
    v1.validator.validate(first_req)
    # Replay it (stale interval) - v1 will reject, others have not seen it.
    result = quorum.validate(first_req)
    assert result.ok is False
    assert result.votes_for < 3
    assert "did:web:v1.example.com" in result.rejections


class TestWeightedQuorum:
  def test_weighted_validator_counts_more(self):
    v1 = QuorumValidator(
      validator=_validator("did:web:senior.example.com"), weight=2.0
    )
    v2 = QuorumValidator(
      validator=_validator("did:web:junior.example.com"), weight=1.0
    )
    # Threshold 2 means the senior alone meets the quorum.
    quorum = HeartbeatQuorum(validators=[v1, v2], threshold=2)
    session = HeartbeatSession(subject_did=AGENT_DID)

    # Poison v2 so it rejects (stale interval after first observation).
    first = session.build_request().to_dict()
    v2.validator.validate(first)
    result = quorum.validate(first)
    # v2 rejects (stale), v1 sees this for the first time and approves
    # with weight 2.0, which meets threshold=2.
    assert result.ok is True
    assert result.votes_for == 2.0


class TestTrustAggregation:
  def test_conservative_aggregation_defaults(self):
    v1 = QuorumValidator(
      validator=_validator(
        "did:web:v1.example.com",
        initial_trust=1.0,
        decay_lambda=0.005,
        voucher_valid_seconds=300,
        scope=["read", "write"],
      )
    )
    v2 = QuorumValidator(
      validator=_validator(
        "did:web:v2.example.com",
        initial_trust=0.8,
        decay_lambda=0.01,
        voucher_valid_seconds=120,
        scope=["read"],
      )
    )
    quorum = HeartbeatQuorum(validators=[v1, v2], threshold=2)
    session = HeartbeatSession(subject_did=AGENT_DID)
    result = quorum.validate(session.build_request().to_dict())

    assert result.ok is True
    cs = result.session_voucher["credentialSubject"]
    assert cs["initialTrust"] == 0.8 # min
    assert cs["decayLambda"] == 0.01 # max
    assert cs["scope"] == ["read"] # intersection
    # Validity window is the minimum of the two configured windows.
    from datetime import datetime, timezone

    valid_from = datetime.strptime(
      result.session_voucher["validFrom"], "%Y-%m-%dT%H:%M:%SZ"
    ).replace(tzinfo=timezone.utc)
    valid_until = datetime.strptime(
      result.session_voucher["validUntil"], "%Y-%m-%dT%H:%M:%SZ"
    ).replace(tzinfo=timezone.utc)
    assert (valid_until - valid_from).total_seconds() == 120

  def test_custom_aggregation_policy(self):
    # Caller wants average initial_trust instead of min.
    v1 = QuorumValidator(
      validator=_validator(
        "did:web:v1.example.com", initial_trust=1.0, decay_lambda=0.01,
      )
    )
    v2 = QuorumValidator(
      validator=_validator(
        "did:web:v2.example.com", initial_trust=0.6, decay_lambda=0.02,
      )
    )

    def avg(values):
      return sum(values) / len(values)

    policy = QuorumPolicy(
      initial_trust_aggregator=avg,
      decay_lambda_aggregator=avg,
    )
    quorum = HeartbeatQuorum(validators=[v1, v2], threshold=2, policy=policy)
    session = HeartbeatSession(subject_did=AGENT_DID)
    result = quorum.validate(session.build_request().to_dict())

    cs = result.session_voucher["credentialSubject"]
    assert cs["initialTrust"] == pytest.approx(0.8)
    assert cs["decayLambda"] == pytest.approx(0.015)


class TestQuorumIssuerField:
  def test_issuer_lists_only_approving_validators(self):
    v1 = QuorumValidator(validator=_validator("did:web:v1.example.com"))
    v2 = QuorumValidator(validator=_validator("did:web:v2.example.com"))
    v3 = QuorumValidator(validator=_validator("did:web:v3.example.com"))
    quorum = HeartbeatQuorum(validators=[v1, v2, v3], threshold=2)

    session = HeartbeatSession(subject_did=AGENT_DID)

    # Make v3 disagree by feeding it a stale (replayed) interval first.
    first = session.build_request().to_dict()
    v3.validator.validate(first)
    result = quorum.validate(first)
    assert result.ok is True
    # The aggregate voucher should issuer-list only v1 and v2.
    assert result.session_voucher["issuer"] == [
      "did:web:v1.example.com",
      "did:web:v2.example.com",
    ]
    assert "did:web:v3.example.com" in result.rejections


class TestEndToEndQuorum:
  def test_multiple_intervals_succeed(self):
    v1 = QuorumValidator(
      validator=_validator("did:web:v1.example.com"), role=ROLE_POLICY
    )
    v2 = QuorumValidator(
      validator=_validator("did:web:v2.example.com"), role=ROLE_BEHAVIORAL
    )
    v3 = QuorumValidator(
      validator=_validator("did:web:v3.example.com"), role=ROLE_BUDGET
    )
    quorum = HeartbeatQuorum(validators=[v1, v2, v3], threshold=2)

    session = HeartbeatSession(subject_did=AGENT_DID)
    for i in range(5):
      session.record_action(f"action_{i}".encode())
      req = session.build_request().to_dict()
      result = quorum.validate(req)
      assert result.ok, f"interval {i} failed: {result.rejections}"
      assert len(result.approving_dids) == 3 # all three approve when chain intact
