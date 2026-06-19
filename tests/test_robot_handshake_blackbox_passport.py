"""
Tests for robot-to-robot handshake (5.4), black box + kill switch (5.5),
and the scannable passport (5.6).
"""

import os

import pytest

from vouch import Signer, generate_identity
from vouch.robotics import (
    BlackBoxLog,
    TrustPolicy,
    build_accept,
    build_confirm,
    build_hello,
    build_killswitch_credential,
    build_passport,
    decode_passport,
    encode_passport,
    open_entry,
    verify_accept,
    verify_blackbox_chain,
    verify_confirm,
    verify_killswitch_credential,
    verify_passport,
)
from vouch.robotics.handshake import HandshakeError


def _robot(domain):
    kp = generate_identity(domain=domain)
    return kp, Signer(private_key=kp.private_key_jwk, did=kp.did)


class TestHandshake:
    def test_full_handshake_bounds_scope(self):
        a_kp, a = _robot("robot-a.example.com")
        b_kp, b = _robot("robot-b.example.com")
        policy_b = TrustPolicy(trusted_domains={"robot-a.example.com"})

        hello = build_hello(a, proposed_scope=["lift", "carry", "scan"])
        accept = build_accept(
            b,
            hello=hello,
            hello_public_key=a_kp.public_key_jwk,
            policy=policy_b,
            offered_scope=["carry", "scan", "weld"],
        )
        ok, session = verify_accept(accept, b_kp.public_key_jwk, expected_nonce=hello["nonce"])
        assert ok is True
        # Bounded scope is the intersection.
        assert session.scope == ["carry", "scan"]

        confirm = build_confirm(a, session=session)
        assert (
            verify_confirm(
                confirm,
                a_kp.public_key_jwk,
                session_id=session.session_id,
                expected_nonce=session.nonce,
            )
            is True
        )

    def test_untrusted_domain_refused(self):
        a_kp, a = _robot("stranger.example.com")
        _, b = _robot("robot-b.example.com")
        policy_b = TrustPolicy(trusted_domains={"robot-a.example.com"})
        hello = build_hello(a, proposed_scope=["lift"])
        with pytest.raises(HandshakeError):
            build_accept(
                b,
                hello=hello,
                hello_public_key=a_kp.public_key_jwk,
                policy=policy_b,
                offered_scope=["lift"],
            )

    def test_nonce_must_echo(self):
        a_kp, a = _robot("robot-a.example.com")
        b_kp, b = _robot("robot-b.example.com")
        hello = build_hello(a, proposed_scope=["lift"])
        accept = build_accept(
            b,
            hello=hello,
            hello_public_key=a_kp.public_key_jwk,
            policy=TrustPolicy(accept_unknown=True),
            offered_scope=["lift"],
        )
        ok, _ = verify_accept(accept, b_kp.public_key_jwk, expected_nonce="wrong-nonce")
        assert ok is False


class TestBlackBox:
    def test_append_encrypt_decrypt_and_chain(self):
        key = os.urandom(32)
        log = BlackBoxLog(key=key)
        log.append("MOTION", {"joint": 3, "torque": 4.2})
        log.append("FAULT", {"code": "E12"})
        entries = log.entries()

        ok, _ = verify_blackbox_chain(entries)
        assert ok is True
        # Payloads are encrypted; only the key opens them.
        assert "torque" not in entries[0]["ciphertext"]
        assert open_entry(entries[0], key)["torque"] == 4.2

    def test_wrong_key_fails_to_open(self):
        log = BlackBoxLog(key=os.urandom(32))
        log.append("MOTION", {"x": 1})
        from vouch.robotics.blackbox import BlackBoxError

        with pytest.raises(BlackBoxError):
            open_entry(log.entries()[0], os.urandom(32))

    def test_tampering_ciphertext_breaks_chain(self):
        log = BlackBoxLog(key=os.urandom(32))
        log.append("A", {"x": 1})
        log.append("B", {"x": 2})
        entries = log.entries()
        entries[0]["ciphertext"] = entries[0]["ciphertext"][:-4] + "AAAA"
        ok, _ = verify_blackbox_chain(entries)
        assert ok is False


class TestKillSwitch:
    def test_build_and_verify_with_authority_allowlist(self):
        kp, authority = _robot("safety-authority.example.com")
        cred = build_killswitch_credential(
            authority,
            target="did:web:robot.example.com",
            reason="human in path",
        )
        assert "KillSwitchCredential" in cred["type"]
        ok, subject = verify_killswitch_credential(
            cred, kp.public_key_jwk, trusted_authorities={authority.get_did()}
        )
        assert ok is True
        assert subject["command"] == "emergency_stop"

    def test_untrusted_authority_refused(self):
        kp, attacker = _robot("attacker.example.com")
        cred = build_killswitch_credential(attacker, target="did:web:robot", reason="x")
        ok, _ = verify_killswitch_credential(
            cred, kp.public_key_jwk, trusted_authorities={"did:web:real-authority"}
        )
        assert ok is False


class TestPassport:
    def test_encode_decode_verify(self):
        kp, robot = _robot("robot.example.com")
        passport = build_passport(
            robot,
            robot_did=robot.get_did(),
            make="Acme",
            model="AR-7",
            owner="did:web:owner.example.com",
            authorized_actions=["carry", "scan"],
            certification="CE-2026-001",
            status="active",
        )
        uri = encode_passport(passport)
        assert uri.startswith("vouch-passport:u")
        assert decode_passport(uri)["credentialSubject"]["model"] == "AR-7"

        ok, summary = verify_passport(uri, kp.public_key_jwk)
        assert ok is True
        assert summary["owner"] == "did:web:owner.example.com"
        assert summary["status"] == "active"
        assert summary["authorizedActions"] == ["carry", "scan"]

    def test_tampered_passport_fails(self):
        kp, robot = _robot("robot.example.com")
        passport = build_passport(
            robot,
            robot_did=robot.get_did(),
            make="Acme",
            model="AR-7",
            owner="o",
            authorized_actions=["carry"],
        )
        passport["credentialSubject"]["authorizedActions"] = ["carry", "weld", "drive"]
        ok, _ = verify_passport(passport, kp.public_key_jwk)
        assert ok is False
