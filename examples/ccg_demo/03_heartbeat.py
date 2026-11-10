#!/usr/bin/env python3
"""
Heartbeats: trust is renewed only by a live, signed, in-order agent.

An agent renews its SessionVoucher by sending a signed heartbeat every 60
seconds. The validator checks the agent's signature, the time the beat was
made, its place in the sequence, the canary commit/reveal chain, and the
Merkle root of the actions it reports. Miss more than two intervals and the
session lapses. Separately, an authority state change (a mandate suspension)
refuses a sensitive action even while decayed trust still passes. Time comes
from a fake clock, so the run is instant and repeatable.

Run: python3 examples/ccg_demo/03_heartbeat.py
"""

from __future__ import annotations

import base64
import json
import sys
from datetime import datetime, timedelta, timezone

from vouch import Signer, generate_identity, multikey
from vouch.authority_state import STATUS_SUSPENDED, sign_authority_state, verify_authority_state
from vouch.heartbeat import HeartbeatSession, HeartbeatValidator
from vouch.status_list import CONSEQUENCE_ROUTINE, CONSEQUENCE_SENSITIVE
from vouch.trust_check import verify_agent_call
from vouch.vc import sign_session_voucher

T0 = datetime(2026, 11, 10, 17, 0, 0, tzinfo=timezone.utc)  # fake clock
results = []


class Clock:
    def __init__(self) -> None:
        self.now = T0

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


def did_key_signer() -> Signer:
    kp = generate_identity()
    raw = base64.urlsafe_b64decode(json.loads(kp.public_key_jwk)["x"] + "==")
    return Signer(
        private_key=kp.private_key_jwk, did="did:key:" + multikey.encode_ed25519_public(raw)
    )


def report(case: str, expected: str, actual: str, detail: str) -> None:
    mark = "ok" if expected == actual else "UNEXPECTED"
    results.append(expected == actual)
    print(f"  {case:<48} {actual:<8} {detail}  [{mark}]")


def beat_verdict(validator, request):
    r = validator.validate(request)
    return ("ACCEPTED" if r.ok else "REJECTED"), (", ".join(r.reasons) or "voucher renewed"), r


validator_key = did_key_signer()


def fresh(**session_kw):
    clock = Clock()
    agent = did_key_signer()
    validator = HeartbeatValidator(
        validator_did=validator_key.did, clock=clock, interval_seconds=60, max_missed_intervals=2
    )
    session = HeartbeatSession(subject_did=agent.did, signer=agent, **session_kw)
    return clock, agent, validator, session


print("Renewal")
clock, agent, validator, session = fresh()
session.record_action(b"read:calendar")
first = session.build_request(now=clock()).to_dict()
actual, why, _ = beat_verdict(validator, first)
report("a1) first signed beat", "ACCEPTED", actual, why)
clock.advance(60)
session.record_action(b"read:calendar/events")
second = session.build_request(now=clock()).to_dict()
actual, why, _ = beat_verdict(validator, second)
report("a2) next beat, on time", "ACCEPTED", actual, why)

clock.advance(30)
actual, why, _ = beat_verdict(validator, second)
report("b) the same beat replayed", "REJECTED", actual, why)

clock.advance(30)
beat3 = session.build_request(now=clock())
beat4 = session.build_request(now=clock() + timedelta(seconds=1))
clock.advance(1)
actual, why, _ = beat_verdict(validator, beat4.to_dict())
report("c) beat 4 arrives before beat 3", "REJECTED", actual, why)

print("\nMissed beats")
clock, agent, validator, session = fresh()
_, _, accepted = beat_verdict(validator, session.build_request(now=clock()).to_dict())
last_voucher = sign_session_voucher(accepted.session_voucher, validator_key)
credential = agent.sign(
    action="read", target="calendar", resource="https://calendar.example.com/alice", valid_from=T0
)
clock.advance(60 * 4)  # three intervals missed; the limit is two
actual, why, _ = beat_verdict(validator, session.build_request(now=clock()).to_dict())
report("d1) beat after three missed intervals", "REJECTED", actual, why)
v = verify_agent_call(
    credential,
    public_key=agent.get_public_key_multikey(),
    session_voucher=last_voucher,
    voucher_public_key=validator_key.get_public_key_multikey(),
    consequence=CONSEQUENCE_ROUTINE,
    at_time=clock(),
)
report(
    "d2) routine action on the last voucher",
    "DENIED",
    "ALLOWED" if v.ok else "DENIED",
    f"trust {v.trust:.4f}; " + ", ".join(v.reasons),
)
clock.advance(60)
actual, why, _ = beat_verdict(validator, session.build_request(now=clock()).to_dict())
report("d3) an on-time beat after the lapse", "REJECTED", actual, why)

print("\nForged beats")
clock, agent, validator, session = fresh()
unsigned = HeartbeatSession(subject_did=agent.did).build_request(now=clock()).to_dict()
actual, why, _ = beat_verdict(validator, unsigned)
report("e1) unsigned beat", "REJECTED", actual, why)
tampered = session.build_request(now=clock()).to_dict()
tampered["behavioralDigest"]["apiCalls"] = 9999  # edited after the agent signed it
actual, why, _ = beat_verdict(validator, tampered)
report("e2) beat edited after signing", "REJECTED", actual, why)

print("\nAuthority state")
clock, agent, validator, session = fresh(authority_epoch=5)
_, _, accepted = beat_verdict(validator, session.build_request(now=clock()).to_dict())
voucher = sign_session_voucher(accepted.session_voucher, validator_key)
credential = agent.sign(
    action="transfer",
    target="vendor-1",
    resource="https://bank.example.com/transfers",
    valid_from=T0,
)
treasury = did_key_signer()


def sensitive(last_seen_epoch):
    return verify_agent_call(
        credential,
        public_key=agent.get_public_key_multikey(),
        session_voucher=voucher,
        voucher_public_key=validator_key.get_public_key_multikey(),
        consequence=CONSEQUENCE_SENSITIVE,
        last_seen_authority_epoch=last_seen_epoch,
        at_time=clock(),
    )


clock.advance(5)
v = sensitive(5)
report(
    "f1) transfer, voucher minted under epoch 5",
    "ALLOWED",
    "ALLOWED" if v.ok else "DENIED",
    f"trust {v.trust:.4f}; {v.authority_reason}",
)
suspended = sign_authority_state(treasury, 6, status=STATUS_SUSPENDED, valid_from=clock())
ok, passport = verify_authority_state(
    suspended, treasury.get_public_key_multikey(), at_time=clock()
)
clock.advance(1)
v = sensitive(passport.authority_epoch if ok else None)
report(
    "f2) same transfer after epoch 6 (suspended)",
    "DENIED",
    "ALLOWED" if v.ok else "DENIED",
    f"trust {v.trust:.4f} still passes ({v.trust_ok}); {v.authority_reason}",
)

passed = sum(results)
print(f"\n{passed}/{len(results)} cases matched the expected outcome")
sys.exit(0 if passed == len(results) else 1)
