#!/usr/bin/env python3
"""
Trust that decays until it is renewed.

A validator with the default HeartbeatValidator settings (initialTrust 1.0,
decayLambda 0.01 per second, a 120 second voucher) issues a signed
SessionVoucher. A verifier recomputes trust = initialTrust * exp(-lambda * t)
at the moment of each action and compares it with the threshold for that
action's tier: critical 0.9, sensitive 0.75, routine 0.5. Time comes from a
fake clock, so the run is instant and repeatable.

Run: python3 examples/ccg_demo/02_trust_decay.py
"""

from __future__ import annotations

import base64
import json
import math
import sys
from datetime import datetime, timedelta, timezone

from vouch import Signer, generate_identity, multikey
from vouch.heartbeat import HeartbeatSession, HeartbeatValidator
from vouch.trust_entropy import compute_trust_at, time_until_threshold, verify_session_voucher
from vouch.vc import sign_session_voucher

T0 = datetime(2026, 11, 10, 17, 0, 0, tzinfo=timezone.utc)  # fake clock
TIERS = (("critical", 0.9), ("sensitive", 0.75), ("routine", 0.5))


def did_key_signer() -> Signer:
    kp = generate_identity()
    raw = base64.urlsafe_b64decode(json.loads(kp.public_key_jwk)["x"] + "==")
    return Signer(
        private_key=kp.private_key_jwk, did="did:key:" + multikey.encode_ed25519_public(raw)
    )


agent = did_key_signer()
validator_key = did_key_signer()
validator = HeartbeatValidator(validator_did=validator_key.did, clock=lambda: T0)

session = HeartbeatSession(subject_did=agent.did, signer=agent)
result = validator.validate(session.build_request(now=T0).to_dict())
if not result.ok:
    print("the heartbeat was not accepted:", result.reasons)
    sys.exit(1)
voucher = sign_session_voucher(result.session_voucher, validator_key)
subject = voucher["credentialSubject"]
print(
    f"SessionVoucher issued at t=0: initialTrust {subject['initialTrust']}, "
    f"decayLambda {subject['decayLambda']}/s, valid {voucher['validFrom']} to {voucher['validUntil']}"
)
for tier, threshold in TIERS:
    crossing = time_until_threshold(voucher, threshold, from_time=T0).total_seconds()
    print(f"  {tier:<9} threshold {threshold:<4} is crossed at t = {crossing:5.1f} s")

results = []
print()
for t in (0, 10, 30, 70, 120):
    at = T0 + timedelta(seconds=t)
    ok, why = verify_session_voucher(voucher, validator_key.get_public_key_multikey(), at_time=at)
    trust = compute_trust_at(voucher, at)
    expected_trust = math.exp(-0.01 * t)
    verdicts = []
    for tier, threshold in TIERS:
        actual = "ALLOWED" if ok and trust >= threshold else "DENIED"
        expected = "ALLOWED" if expected_trust >= threshold else "DENIED"
        results.append(actual == expected)
        verdicts.append(f"{tier} {actual:<7}")
    match = "ok" if all(results[-3:]) and abs(trust - expected_trust) < 1e-9 else "UNEXPECTED"
    print(f"  t = {t:3d} s   trust {trust:.4f}   " + "  ".join(verdicts) + f"  [{match}]")
    results.append(abs(trust - expected_trust) < 1e-9 and ok)

passed = sum(results)
print(f"\n{passed}/{len(results)} checks matched the expected outcome")
sys.exit(0 if passed == len(results) else 1)
