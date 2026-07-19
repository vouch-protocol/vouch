"""
Hardware-seam demo: trust decisions driven by (simulated) sensors.

The disconnected-edge trust predicates consume measurements — a range, a clock, a
network epoch, a position, an integrity reading. `vouch.robotics.hardware` is the
seam where real devices supply those; this demo drives the whole flow through the
reference `Simulated*` implementations, so you can see how a platform's drivers
feed the trust logic without touching it. Swap any `Simulated*` object for a real
driver that duck-types the same Protocol and the trust code is unchanged.

The scenario: two spacecraft (A, an inspector; B, a target) that provisioned trust
anchors during a contact window now meet offline. B uses its own sensors to decide
whether to trust A for a physical proximity maneuver. As with the other edge demo,
the disconnected phase runs with the socket layer disabled to prove nothing phones
home.

Run it:  python examples/hardware_seam_demo.py
"""

from __future__ import annotations

import contextlib
import socket

from vouch import Signer, generate_identity
from vouch.status_list import CONSEQUENCE_CRITICAL
from vouch.robotics import (
    SimulatedClock,
    SimulatedEpochSource,
    SimulatedIntegrityMonitor,
    SimulatedNavigation,
    SimulatedRangeSensor,
    capture_integrity_risk,
    capture_presence_attestation,
    capture_range_observation,
    capture_time_quality,
    check_kinematics_live,
    integrity_authority_level,
    issue_freshness_token,
    location_confirmed,
    time_quality_permits,
    verify_freshness_token,
    verify_integrity_risk_attestation,
    verify_presence_live,
    verify_range_observation,
    verify_time_quality_attestation,
)


@contextlib.contextmanager
def network_disabled():
    real = socket.socket

    def _blocked(*_a, **_k):
        raise AssertionError("network access during the disconnected phase")

    socket.socket = _blocked  # type: ignore[assignment]
    try:
        yield
    finally:
        socket.socket = real  # type: ignore[assignment]


def _mk(domain):
    kp = generate_identity(domain=domain)
    return Signer(private_key=kp.private_key_jwk, did=kp.did), kp


def _rule(t):
    print(f"\n{'=' * 4} {t} {'=' * (66 - len(t))}")


def main() -> None:
    # Identities.
    relay, relay_kp = _mk("relay.control.example")
    a, a_kp = _mk("inspector.operator-a.example")  # the peer being judged
    b, b_kp = _mk("target.operator-b.example")  # the verifier
    obs2, obs2_kp = _mk("obs2.operator-b.example")  # extra observers for triangulation
    obs3, obs3_kp = _mk("obs3.operator-b.example")

    anchors = {
        a.get_did(): a_kp.public_key_jwk,
        b.get_did(): b_kp.public_key_jwk,
        relay.get_did(): relay_kp.public_key_jwk,
        obs2.get_did(): obs2_kp.public_key_jwk,
        obs3.get_did(): obs3_kp.public_key_jwk,
    }

    # A's true position in B's local metric frame (meters), and its motion.
    A_POSITION = [100.0, 0.0, 0.0]
    A_VELOCITY = [0.0, 5.0, 0.0]

    # B's sensor suite (simulated). A real deployment supplies drivers that
    # duck-type these same Protocols.
    b_nav = SimulatedNavigation([0.0, 0.0, 0.0], [0.0, 0.0, 0.0])
    b_radio = SimulatedRangeSensor({a.get_did(): 100.3})  # ranges A at ~100 m (true)
    epoch = SimulatedEpochSource(4412)

    print("Nodes: A (inspector, judged), B (target, verifier), + 2 observers, 1 relay")
    print(f"A true position {A_POSITION}, B at origin; B ranges A over its ISL radio.")

    # ----------------------------------------------------------------------- #
    _rule("Phase 1: IN CONTACT - a relay issues A a freshness token")
    # ----------------------------------------------------------------------- #
    a_freshness = issue_freshness_token(relay, subject_did=a.get_did(), epoch_source=epoch)
    print(f"  relay issued A a FreshnessToken at epoch {epoch.current_epoch()}")

    # A also attests its clock quality and its key-store integrity (from its own
    # hardware) while it can; B will judge these offline.
    a_clock = capture_time_quality(
        a, clock=SimulatedClock("gnss", since_discipline_s=8.0, uncertainty_s=0.4)
    )
    a_integrity = capture_integrity_risk(
        a, monitor=SimulatedIntegrityMonitor(0.12, {"doseRad": 180, "seu": 0})
    )
    print("  A attested its time-quality (GNSS, 0.4s) and integrity risk (0.12)")

    # ----------------------------------------------------------------------- #
    _rule("Phase 2: DISCONNECTED - B decides whether to trust A, offline")
    # ----------------------------------------------------------------------- #
    with network_disabled():
        # 2a. Freshness: is A's proof of recent contact fresh enough for a maneuver?
        ok_fresh, _ = verify_freshness_token(
            a_freshness,
            anchors[relay.get_did()],
            verifier_epoch=epoch.current_epoch(),
            tier=CONSEQUENCE_CRITICAL,
        )
        print(f"  [freshness] A contacted a relay this epoch: fresh_enough={ok_fresh}")

        # 2b. Presence: B ranges A and checks the measurement fits A's claimed position.
        att = capture_presence_attestation(
            b,
            peer_did=a.get_did(),
            nonce="maneuver-42",
            claimed_position=A_POSITION,
            range_sensor=b_radio,
            tolerance_m=1.0,
        )
        ok_present, _ = verify_presence_live(
            att, b_kp.public_key_jwk, nav=b_nav, expected_nonce="maneuver-42"
        )
        print(f"  [presence] B's measured range matches A's claimed position: {ok_present}")

        # An imposter at the wrong location: B's radio would read a different range.
        b_radio_spoof = SimulatedRangeSensor({a.get_did(): 480.0})
        att_spoof = capture_presence_attestation(
            b,
            peer_did=a.get_did(),
            nonce="x",
            claimed_position=A_POSITION,
            range_sensor=b_radio_spoof,
            tolerance_m=1.0,
        )
        ok_spoof, _ = verify_presence_live(att_spoof, b_kp.public_key_jwk, nav=b_nav)
        print(f"  [presence] an imposter 480 m away claiming A's spot: accepted={ok_spoof}")

        # 2c. Proof of location by triangulation: three observers range A.
        observers = [
            (
                b,
                SimulatedNavigation([0, 0, 0], [0, 0, 0]),
                SimulatedRangeSensor({a.get_did(): 100.0}),
            ),
            (
                obs2,
                SimulatedNavigation([200, 0, 0], [0, 0, 0]),
                SimulatedRangeSensor({a.get_did(): 100.0}),
            ),
            (
                obs3,
                SimulatedNavigation([0, 200, 0], [0, 0, 0]),
                SimulatedRangeSensor({a.get_did(): 100.0}),
            ),
        ]
        subjects = []
        for signer_obs, nav, radio in observers:
            o = capture_range_observation(
                signer_obs,
                target_did=a.get_did(),
                nav=nav,
                range_sensor=radio,
                nonce="tri-42",
                epoch_source=epoch,
            )
            key = anchors[signer_obs.get_did()]
            ok, sub = verify_range_observation(o, key)
            if ok:
                subjects.append(sub)
        confirmed = location_confirmed(subjects, A_POSITION, tolerance_m=2.0, threshold=2)
        print(
            f"  [location] {len(subjects)} signed observations, position confirmed (>=2): {confirmed}"
        )

        # 2d. Time quality: is A's clock good enough to trust its time-bound claims?
        _, tq = verify_time_quality_attestation(a_clock, anchors[a.get_did()])
        ok_time = time_quality_permits(tq, tier=CONSEQUENCE_CRITICAL)
        print(
            f"  [time] A's attested clock uncertainty {tq['uncertaintyS']}s ok for critical: {ok_time}"
        )

        # 2e. Kinematics: is A where it now claims, reachably, from 10 s ago?
        prior = [
            A_POSITION[0],
            A_POSITION[1] - A_VELOCITY[1] * 10,
            A_POSITION[2],
        ]  # 50 m south, 10 s ago
        a_nav_now = SimulatedNavigation(A_POSITION, A_VELOCITY)
        reachable = check_kinematics_live(
            prior_position=prior,
            nav=a_nav_now,
            elapsed_seconds=10.0,
            envelope={"maxSpeedMps": 8.0},
        )
        print(f"  [kinematics] A's current position reachable at <=8 m/s in 10 s: {reachable}")

        # 2f. Integrity: what authority does A's key-store integrity justify?
        _, isub = verify_integrity_risk_attestation(a_integrity, anchors[a.get_did()])
        level = integrity_authority_level(isub["cumulativeRisk"])
        print(
            f"  [integrity] A's cumulative risk {isub['cumulativeRisk']} -> authority level '{level}'"
        )

        # Composite decision.
        trust_for_maneuver = (
            ok_fresh and ok_present and confirmed and ok_time and reachable and level == "full"
        )
        print(f"\n  DECISION: trust A for the proximity maneuver = {trust_for_maneuver}")

    print("\nEvery check above ran with the network disabled, driven entirely by the")
    print("Simulated* sensor implementations. Swap in real drivers (same Protocols) unchanged.")


if __name__ == "__main__":
    main()
