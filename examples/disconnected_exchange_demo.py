"""
Disconnected trust exchange over a high-latency link (simulation).

Two nodes in different trust domains discover each other, authenticate, and
exchange a bounded grant of authority WITHOUT any live connection to a registry
or a home authority. This is the "edge autonomy" case that shows up wherever a
round trip home is impossible or too slow: a warehouse aisle, a mine, a subsea
ROV, a disaster zone, or (the extreme) a spacecraft minutes-to-hours of
light-time from Earth.

The point of this example is honesty about what is and is not new. Offline
verification is NOT blocked by latency; it is enabled by having distributed the
trust anchors *ahead of time*. So the simulation has two phases:

  1. IN CONTACT  - the nodes sync trust anchors and receive their leases from an
     authority. This is ordinary PKI provisioning; it must happen at some point.
  2. DISCONNECTED - the link to the authority is gone. The two nodes run the
     existing Vouch robot-to-robot handshake, present a delegation lease, and
     authorize a concrete action, all offline. To *prove* it is offline, the
     whole disconnected phase runs with the socket layer disabled: any
     accidental network call raises loudly instead of silently "working."

Everything here is built on primitives that already ship in `vouch.robotics`
and `vouch.status_list`. There is no new DID method and no new daemon. The
"high-latency link" is an in-process channel that reports one-way light-time so
the transcript reads like a real contact window.

The final act (`freshness gate`) demonstrates the bounded-staleness revocation
mechanism specified in docs/dtn-bounded-staleness-revocation.md: a disconnected
verifier decides whether its last-synced revocation snapshot is fresh ENOUGH for
the consequence of the action being requested, and fails closed when it is not.

Run it:  python examples/disconnected_exchange_demo.py
"""

from __future__ import annotations

import contextlib
import socket
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from vouch import Signer, generate_identity
from vouch.robotics import (
    PhysicalAction,
    TrustPolicy,
    build_accept,
    build_confirm,
    build_delegation_lease,
    build_hello,
    build_passport,
    lease_permits,
    verify_accept,
    verify_confirm,
    verify_delegation_lease,
    verify_passport,
)
from vouch.robotics.revocation import attach_credential_status
from vouch.robotics._signing import attach_proof
from vouch.status_list import (
    StatusList,
    build_status_list_credential,
    verify_status,
)


# --------------------------------------------------------------------------- #
# A simulated high-latency inter-node link.
# --------------------------------------------------------------------------- #

# One-way light-time to make the transcript concrete. 1.28s is roughly Earth<->Moon;
# swap for any figure you like - the protocol is identical, only the wait changes.
ONE_WAY_LIGHT_SECONDS = 1.28


@dataclass
class Link:
    """An in-process channel that reports (but does not actually sleep) light-time."""

    name: str
    elapsed_s: float = 0.0

    def send(self, sender: str, message: Dict[str, Any]) -> Dict[str, Any]:
        self.elapsed_s += ONE_WAY_LIGHT_SECONDS
        kind = message.get("type", "message")
        print(f"    ~{ONE_WAY_LIGHT_SECONDS:>4.2f}s light-time  {sender} --[{kind}]-->")
        return message


@contextlib.contextmanager
def network_disabled():
    """
    Disable the socket layer for the duration of the block, so any code path that
    tries to reach a network raises instead of silently succeeding. This is how we
    prove the disconnected phase really is offline.
    """
    real_socket = socket.socket

    def _blocked(*_a, **_k):
        raise AssertionError(
            "network access attempted during the disconnected phase - "
            "offline verification must not touch the network"
        )

    socket.socket = _blocked  # type: ignore[assignment]
    try:
        yield
    finally:
        socket.socket = real_socket  # type: ignore[assignment]


# --------------------------------------------------------------------------- #
# Bounded-staleness freshness gate (reference implementation of the spec).
# See docs/dtn-bounded-staleness-revocation.md for the normative description.
# --------------------------------------------------------------------------- #

# Consequence tiers and the maximum age of a revocation snapshot each will accept.
# A routine beacon tolerates a stale view; a physical maneuver does not.
MAX_STALENESS = {
    "routine": timedelta(days=30),
    "sensitive": timedelta(hours=24),
    "critical": timedelta(hours=1),
}


@dataclass
class FreshnessVerdict:
    allow: bool
    reason: str
    staleness: Optional[timedelta] = None


def evaluate_freshness(
    *,
    tier: str,
    snapshot: Optional[Dict[str, Any]],
    now: datetime,
) -> FreshnessVerdict:
    """
    Decide whether a locally-held revocation `snapshot` (a signed
    BitstringStatusListCredential the verifier synced at last contact) is fresh
    enough to authorize an action of the given consequence `tier`.

    Fail closed: a missing snapshot denies anything above routine; an
    over-age snapshot denies the action. The caller has ALREADY verified the
    snapshot's Data Integrity proof and the target bit; this function only
    judges age against the tier budget.
    """
    budget = MAX_STALENESS[tier]
    if snapshot is None:
        # No local revocation view at all.
        if tier == "routine":
            return FreshnessVerdict(True, "no snapshot, routine tier tolerates it")
        return FreshnessVerdict(False, f"no revocation snapshot; {tier} tier fails closed")

    as_of = _parse_iso(snapshot.get("validFrom"))
    staleness = now - as_of
    if staleness <= budget:
        return FreshnessVerdict(
            True,
            f"snapshot age {_fmt(staleness)} within {tier} budget {_fmt(budget)}",
            staleness,
        )
    return FreshnessVerdict(
        False,
        f"snapshot age {_fmt(staleness)} exceeds {tier} budget {_fmt(budget)}; fails closed",
        staleness,
    )


# --------------------------------------------------------------------------- #
# Scenario
# --------------------------------------------------------------------------- #


def _rule(title: str) -> None:
    print(f"\n{'=' * 4} {title} {'=' * (68 - len(title))}")


def main() -> None:
    now = datetime.now(timezone.utc)

    # Three parties. In a real deployment the authority is a mission control /
    # fleet CA; nodes A and B belong to different operators (different did:web
    # domains), which is exactly what the handshake's trust policy is for.
    authority_kp = generate_identity(domain="control.example.org")
    authority = Signer(private_key=authority_kp.private_key_jwk, did=authority_kp.did)

    a_kp = generate_identity(domain="surveyor.operator-a.example")
    node_a = Signer(private_key=a_kp.private_key_jwk, did=a_kp.did)

    b_kp = generate_identity(domain="relay.operator-b.example")
    node_b = Signer(private_key=b_kp.private_key_jwk, did=b_kp.did)

    print("Nodes:")
    print(f"  authority  {authority.get_did()}")
    print(f"  node A     {node_a.get_did()}   (operator A, the surveyor)")
    print(f"  node B     {node_b.get_did()}   (operator B, the relay)")

    # ----------------------------------------------------------------------- #
    _rule("Phase 1: IN CONTACT - provision trust anchors and a lease")
    # ----------------------------------------------------------------------- #
    # Each node is told, ahead of time, which peer DOMAINS it will trust in the
    # field, and each holds the other's public key. This is the provisioning that
    # makes later offline verification possible - it is not optional, and no
    # amount of clever protocol removes it.
    a_trust = TrustPolicy(trusted_domains={"relay.operator-b.example"})
    b_trust = TrustPolicy(trusted_domains={"surveyor.operator-a.example"})
    anchors = {
        node_a.get_did(): a_kp.public_key_jwk,
        node_b.get_did(): b_kp.public_key_jwk,
        authority.get_did(): authority_kp.public_key_jwk,  # the lease issuer's anchor
    }
    print("  synced peer trust policies and public keys (the trust anchors)")

    # The authority grants node A a short, scope-bounded delegation lease while it
    # can still reach it. Node A will present this in the field, offline.
    lease = build_delegation_lease(
        authority,
        robot_did=node_a.get_did(),
        lease_id="urn:lease:survey-window-42",
        scope={
            "maxSpeedMps": 1.5,
            "allowedZones": ["sector-7"],
            "actions": ["relay_uplink", "handoff_payload"],
        },
        valid_seconds=6 * 3600,
    )

    # The authority also publishes a revocation snapshot (a signed status list).
    # Node B syncs a COPY now; in the field it will judge that copy's freshness
    # rather than fetch a live one. Nothing is revoked in this snapshot.
    status_list = StatusList(status_list_id="https://control.example.org/status/1")
    lease_status_index = status_list.allocate_index()
    snapshot = attach_proof(
        build_status_list_credential(
            issuer_did=authority.get_did(),
            status_list=status_list,
            credential_id="https://control.example.org/status/1",
            valid_from=now - timedelta(minutes=20),  # last contact was 20 min ago
        ),
        authority,
    )
    # Bind the lease to that status list so it can be revoked surgically later.
    lease = attach_credential_status(
        lease,
        authority,
        status_list_credential="https://control.example.org/status/1",
        status_list_index=lease_status_index,
    )
    print("  authority issued node A a 6h delegation lease (scope: sector-7, <=1.5 m/s)")
    print("  node B synced a revocation snapshot (as-of 20 min ago, nothing revoked)")

    # A scannable passport node A can present to anyone, offline.
    passport = build_passport(
        node_a,
        robot_did=node_a.get_did(),
        make="Operator-A",
        model="Surveyor-1",
        owner="operator-a.example",
        authorized_actions=["relay_uplink", "handoff_payload"],
        certification="mission-42",
    )

    # ----------------------------------------------------------------------- #
    _rule("Phase 2: DISCONNECTED - the authority is now unreachable")
    # ----------------------------------------------------------------------- #
    print("  link home is dark. All verification below runs with sockets disabled.")
    link = Link(name="A<->B ISL")

    with network_disabled():
        # --- 2a. Mutual authentication via the 3-message handshake ---------- #
        print("\n  [handshake] A initiates, proposing a scope:")
        hello = build_hello(
            node_a,
            proposed_scope=["relay_uplink", "handoff_payload", "wide_broadcast"],
            peer_did=node_b.get_did(),
        )
        link.send("A", hello)

        # B verifies A against its trust policy and intersects the scope.
        accept = build_accept(
            node_b,
            hello=hello,
            hello_public_key=anchors[node_a.get_did()],
            policy=b_trust,
            offered_scope=["relay_uplink", "handoff_payload"],  # B won't offer wide_broadcast
            valid_seconds=1800,
        )
        link.send("B", accept)

        ok_accept, session = verify_accept(
            accept,
            anchors[node_b.get_did()],
            expected_nonce=hello["nonce"],
            policy=a_trust,
        )
        assert ok_accept and session is not None
        print(f"  [handshake] A verified B's ACCEPT. Bounded session scope: {session.scope}")

        confirm = build_confirm(node_a, session=session)
        link.send("A", confirm)
        ok_confirm = verify_confirm(
            confirm,
            anchors[node_a.get_did()],
            session_id=session.session_id,
            expected_nonce=hello["nonce"],
        )
        assert ok_confirm
        print("  [handshake] B verified A's CONFIRM. Both hold the same bounded session.")
        print("  [handshake] note the scope narrowed to the intersection, never the union.")

        # --- 2b. A presents its lease; B verifies it and a concrete action -- #
        print("\n  [lease] A presents its authority-issued delegation lease.")
        link.send("A", {"type": "lease_presentation"})
        ok_lease, subject = verify_delegation_lease(
            lease, anchors[authority.get_did()]
        )
        assert ok_lease and subject is not None
        print(f"  [lease] B verified the lease offline. lease_id={subject['leaseId']}")

        proposed = PhysicalAction(speed_mps=1.2, zone="sector-7")
        permitted = lease_permits(subject, proposed, lease)
        print(f"  [lease] proposed move (1.2 m/s in sector-7): permitted={permitted}")
        too_fast = PhysicalAction(speed_mps=3.0, zone="sector-7")
        print(f"  [lease] proposed move (3.0 m/s): permitted={lease_permits(subject, too_fast, lease)}")

        # --- 2c. Passport scan, offline ------------------------------------ #
        ok_passport, psub = verify_passport(passport, anchors[node_a.get_did()])
        print(f"\n  [passport] B scanned A's passport offline: ok={ok_passport}, "
              f"status={psub.get('status')}")

        # --- 2d. Bounded-staleness freshness gate -------------------------- #
        # B knows the lease's revocation BIT (from its synced snapshot), but the
        # snapshot is a point-in-time copy. Whether that copy is good enough
        # depends on how consequential the action is.
        print("\n  [freshness] B judges its revocation snapshot against action consequence:")
        revoked = verify_status(
            credential_status=lease["credentialStatus"],
            status_list_credential=snapshot,
        )
        for tier, action_label in [
            ("routine", "send a telemetry beacon"),
            ("sensitive", "accept a data-payload handoff"),
            ("critical", "execute a physical relay maneuver"),
        ]:
            verdict = evaluate_freshness(tier=tier, snapshot=snapshot, now=now)
            allow = verdict.allow and not revoked
            mark = "ALLOW" if allow else "DENY "
            print(f"    {mark} {action_label:<38} - {verdict.reason}")

        # Show the fail-closed edge: pretend last contact was 5 days ago.
        print("\n  [freshness] same checks, but last contact was 5 DAYS ago:")
        stale_snapshot = dict(snapshot, validFrom=_iso(now - timedelta(days=5)))
        for tier, action_label in [
            ("routine", "send a telemetry beacon"),
            ("sensitive", "accept a data-payload handoff"),
            ("critical", "execute a physical relay maneuver"),
        ]:
            verdict = evaluate_freshness(tier=tier, snapshot=stale_snapshot, now=now)
            mark = "ALLOW" if verdict.allow else "DENY "
            print(f"    {mark} {action_label:<38} - {verdict.reason}")

    print(f"\nContact window used ~{link.elapsed_s:.2f}s of one-way light-time across "
          f"{link.elapsed_s / ONE_WAY_LIGHT_SECONDS:.0f} messages.")
    print("Every verification above completed with the network disabled. Nothing phoned home.")


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #


def _parse_iso(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _fmt(td: timedelta) -> str:
    total = int(td.total_seconds())
    if total < 3600:
        return f"{total // 60}m"
    if total < 86400:
        return f"{total // 3600}h"
    return f"{total // 86400}d"


if __name__ == "__main__":
    main()
