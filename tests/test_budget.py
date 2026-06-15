"""Tests for the budget-validator credential and reference payment verifier."""

import pytest

from vouch import Signer, generate_identity
from vouch.attribution import _pub_from_jwk
from vouch import budget as bud


@pytest.fixture
def principal():
    ident = generate_identity(domain="principal.example.com")
    return ident, Signer(private_key=ident.private_key_jwk, did=ident.did)


@pytest.fixture
def credential(principal):
    _, signer = principal
    return bud.build_budget_credential(
        signer,
        subject_did="did:web:agent.example.com",
        currency="USD",
        per_transaction=100.0,
        daily=250.0,
        monthly=1000.0,
        per_counterparty={"did:web:vendor.example.com": 150.0},
    )


def test_credential_is_signed_and_verifies(principal, credential):
    ident, _ = principal
    from vouch import data_integrity

    assert credential["type"][-1] == bud.BUDGET_CREDENTIAL_TYPE
    assert data_integrity.verify_proof(credential, _pub_from_jwk(ident.public_key_jwk))


def test_per_transaction_limit(credential):
    v = bud.BudgetVerifier(credential)
    assert v.check_payment(50.0).allowed is True
    over = v.check_payment(150.0)
    assert over.allowed is False
    assert any("over_per_transaction" in r for r in over.reasons)


def test_currency_mismatch(credential):
    v = bud.BudgetVerifier(credential)
    bad = v.check_payment(10.0, currency="EUR")
    assert not bad.allowed
    assert any("currency_mismatch" in r for r in bad.reasons)


def test_daily_limit_with_running_tally(credential):
    v = bud.BudgetVerifier(credential)
    # Spend up to the daily cap across several payments.
    for _ in range(2):
        assert v.check_payment(100.0).allowed
        v.record_payment(100.0)
    # 200 spent, daily cap 250: a 100 payment now exceeds it.
    third = v.check_payment(100.0)
    assert not third.allowed
    assert any("over_daily" in r for r in third.reasons)
    # But a 50 payment still fits.
    assert v.check_payment(50.0).allowed


def test_per_counterparty_limit(credential):
    v = bud.BudgetVerifier(credential)
    vendor = "did:web:vendor.example.com"
    assert v.check_payment(100.0, counterparty=vendor).allowed
    v.record_payment(100.0, counterparty=vendor)
    # 100 spent with vendor, cap 150: a 100 payment exceeds the counterparty cap.
    over = v.check_payment(100.0, counterparty=vendor)
    assert not over.allowed
    assert any("over_counterparty" in r for r in over.reasons)


def test_mandate_within_budget(principal, credential):
    ident, _ = principal
    # An AP2-style / x402-style mandate maps onto this dict shape.
    ok_mandate = {"amount": 80.0, "currency": "USD", "payee": "did:web:vendor.example.com"}
    verdict = bud.verify_mandate_within_budget(
        credential, ok_mandate, budget_public_key=_pub_from_jwk(ident.public_key_jwk)
    )
    assert verdict.allowed, verdict.reasons

    too_big = {"amount": 500.0, "currency": "USD", "payee": "did:web:vendor.example.com"}
    bad = bud.verify_mandate_within_budget(credential, too_big)
    assert not bad.allowed
    assert any("over_per_transaction" in r for r in bad.reasons)


def test_mandate_proof_failure_detected(principal, credential):
    # A wrong key makes the budget credential proof check fail.
    other = generate_identity(domain="attacker.example.com")
    verdict = bud.verify_mandate_within_budget(
        credential,
        {"amount": 10.0, "currency": "USD"},
        budget_public_key=_pub_from_jwk(other.public_key_jwk),
    )
    assert not verdict.allowed
    assert any("budget_credential_proof_invalid" in r for r in verdict.reasons)
