#!/usr/bin/env python3
"""
Budgeted agent payments: a demo of the budget credential and payment verifier.

Run it:

    pip install vouch-protocol
    python budget_payment_demo.py

A principal grants an agent a signed budget (per transaction, per day, per
counterparty). When the agent is asked to pay, the verifier checks the payment
against that budget before any money moves. The same check maps onto an
AP2-style payment mandate or an x402 payment requirement: the mandate is just a
dict carrying amount, currency, and payee.

Everything runs locally. No servers, no setup.
"""

from vouch import Signer, generate_identity
from vouch import budget as bud

G = "\033[92m"
R = "\033[91m"
B = "\033[94m"
DIM = "\033[2m"
BOLD = "\033[1m"
END = "\033[0m"


def verdict(v) -> str:
    if v.allowed:
        return f"{G}{BOLD}ALLOWED{END}"
    return f"{R}{BOLD}DENIED{END}  {DIM}({', '.join(v.reasons)}){END}"


def main() -> None:
    print()
    print(f"{BOLD}BUDGETED AGENT PAYMENTS{END}  {DIM}a Vouch Protocol demo{END}")
    print(DIM + "=" * 60 + END)

    principal = generate_identity(domain="principal.example.com")
    signer = Signer(private_key=principal.private_key_jwk, did=principal.did)

    credential = bud.build_budget_credential(
        signer,
        subject_did="did:web:shopper-agent.example.com",
        currency="USD",
        per_transaction=100.0,
        daily=250.0,
        per_counterparty={"did:web:vendor.example.com": 300.0},
    )
    print(f"{B}Budget granted to{END} did:web:shopper-agent.example.com")
    print(f"{DIM}per transaction 100, daily 250, vendor cap 300 (USD){END}")
    print()

    verifier = bud.BudgetVerifier(credential)
    vendor = "did:web:vendor.example.com"

    # Each mandate is the shape an AP2 mandate or an x402 requirement maps onto.
    mandates = [
        {"amount": 80.0, "currency": "USD", "payee": vendor},
        {"amount": 80.0, "currency": "USD", "payee": vendor},
        {"amount": 120.0, "currency": "USD", "payee": vendor},  # over per-transaction
        {"amount": 90.0, "currency": "USD", "payee": vendor},  # over daily after 160 spent
    ]

    for i, m in enumerate(mandates, 1):
        v = verifier.check_payment(m["amount"], counterparty=m["payee"], currency=m["currency"])
        print(f"  Payment {i}: {m['amount']:>6.0f} USD to vendor   {verdict(v)}")
        if v.allowed:
            verifier.record_payment(m["amount"], counterparty=m["payee"])

    print()
    print(DIM + "=" * 60 + END)
    print(f"{DIM}The agent can spend, but only inside limits it can prove it was given.{END}")
    print()


if __name__ == "__main__":
    main()
