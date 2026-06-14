"""
Budget-validator credential and a reference payment verifier (Specification §15).

A budget credential binds an agent to spending limits: per transaction, per day,
per month, and per counterparty. The reference verifier enforces those limits
against a running tally, and can check that an external signed payment mandate
(for example an AP2-style mandate, or an x402 payment requirement) stays within
the agent's budget before any money moves.

This is the open primitive plus a reference verifier. The hosted
spend-authorization gateway, metering, and billing are out of scope here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from . import data_integrity

CONTEXT = "https://vouch-protocol.com/budget/v1"
VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
BUDGET_CREDENTIAL_TYPE = "VouchBudgetCredential"


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _raw_priv(signer: Any):
    raw = getattr(signer, "_raw_priv", None)
    if raw is None:
        raise ValueError("budget credential signing requires a Signer with an Ed25519 key")
    return raw


def build_budget_credential(
    signer: Any,
    *,
    subject_did: str,
    currency: str,
    per_transaction: Optional[float] = None,
    daily: Optional[float] = None,
    monthly: Optional[float] = None,
    per_counterparty: Optional[Dict[str, float]] = None,
    scope: Optional[List[str]] = None,
    valid_seconds: int = 86400,
) -> Dict[str, Any]:
    """
    Build a signed budget credential delegating spending limits to an agent.

    The issuer (signer) is the principal granting the budget; subject_did is the
    agent the budget applies to. All limits are optional; only the ones present
    are enforced. Amounts are in the given currency's minor or major units, the
    verifier just compares numbers, so be consistent.
    """
    now = datetime.now(timezone.utc)
    budget: Dict[str, Any] = {"currency": currency}
    if per_transaction is not None:
        budget["perTransaction"] = per_transaction
    if daily is not None:
        budget["daily"] = daily
    if monthly is not None:
        budget["monthly"] = monthly
    if per_counterparty:
        budget["perCounterparty"] = dict(per_counterparty)

    credential = {
        "@context": [VC_CONTEXT_V2, CONTEXT],
        "type": ["VerifiableCredential", BUDGET_CREDENTIAL_TYPE],
        "issuer": signer.get_did(),
        "validFrom": _iso(now),
        "validUntil": _iso(now + timedelta(seconds=valid_seconds)),
        "credentialSubject": {
            "id": subject_did,
            "budget": budget,
            "scope": scope or ["payments"],
        },
    }
    credential["proof"] = data_integrity.build_proof(
        credential, _raw_priv(signer), signer.verification_method_id()
    )
    return credential


@dataclass
class BudgetVerdict:
    allowed: bool
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"allowed": self.allowed, "reasons": list(self.reasons)}


class BudgetVerifier:
    """
    Enforces a budget credential against a running tally of spend. In-memory
    reference: tracks spend per day, per month, per counterparty, and total.
    """

    def __init__(self, credential: Dict[str, Any]) -> None:
        self.budget = credential["credentialSubject"]["budget"]
        self.currency = self.budget.get("currency")
        self._by_day: Dict[str, float] = {}
        self._by_month: Dict[str, float] = {}
        self._by_counterparty: Dict[str, float] = {}

    @staticmethod
    def _day_key(now: datetime) -> str:
        return now.astimezone(timezone.utc).strftime("%Y-%m-%d")

    @staticmethod
    def _month_key(now: datetime) -> str:
        return now.astimezone(timezone.utc).strftime("%Y-%m")

    def check_payment(
        self,
        amount: float,
        *,
        counterparty: Optional[str] = None,
        currency: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> BudgetVerdict:
        """Check a proposed payment against the budget. Does not record it."""
        now = now or datetime.now(timezone.utc)
        reasons: List[str] = []

        if amount <= 0:
            reasons.append("amount_not_positive")
        if currency is not None and self.currency is not None and currency != self.currency:
            reasons.append(f"currency_mismatch:{currency}!={self.currency}")

        per_tx = self.budget.get("perTransaction")
        if per_tx is not None and amount > per_tx:
            reasons.append(f"over_per_transaction:{amount}>{per_tx}")

        daily = self.budget.get("daily")
        if daily is not None:
            spent = self._by_day.get(self._day_key(now), 0.0)
            if spent + amount > daily:
                reasons.append(f"over_daily:{spent}+{amount}>{daily}")

        monthly = self.budget.get("monthly")
        if monthly is not None:
            spent = self._by_month.get(self._month_key(now), 0.0)
            if spent + amount > monthly:
                reasons.append(f"over_monthly:{spent}+{amount}>{monthly}")

        per_cp = self.budget.get("perCounterparty") or {}
        if counterparty is not None and counterparty in per_cp:
            limit = per_cp[counterparty]
            spent = self._by_counterparty.get(counterparty, 0.0)
            if spent + amount > limit:
                reasons.append(f"over_counterparty:{counterparty}:{spent}+{amount}>{limit}")

        return BudgetVerdict(allowed=not reasons, reasons=reasons)

    def record_payment(
        self,
        amount: float,
        *,
        counterparty: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> None:
        """Record a completed payment in the running tally."""
        now = now or datetime.now(timezone.utc)
        self._by_day[self._day_key(now)] = self._by_day.get(self._day_key(now), 0.0) + amount
        self._by_month[self._month_key(now)] = self._by_month.get(self._month_key(now), 0.0) + amount
        if counterparty is not None:
            self._by_counterparty[counterparty] = (
                self._by_counterparty.get(counterparty, 0.0) + amount
            )


def verify_mandate_within_budget(
    budget_credential: Dict[str, Any],
    mandate: Dict[str, Any],
    *,
    budget_public_key: Optional[Any] = None,
) -> BudgetVerdict:
    """
    Check that an external signed payment mandate fits inside the agent's budget.

    The mandate is a transport-neutral dict carrying at least `amount`, and
    optionally `currency` and `payee`. It maps cleanly onto an AP2-style payment
    mandate or an x402 payment requirement. This checks per-transaction and
    per-counterparty limits and (optionally) the budget credential's own proof;
    it does not consult the running tally (use BudgetVerifier for that).
    """
    reasons: List[str] = []
    if budget_public_key is not None:
        try:
            if not data_integrity.verify_proof(budget_credential, budget_public_key):
                reasons.append("budget_credential_proof_invalid")
        except Exception as exc:
            reasons.append(f"budget_credential_proof_error:{exc}")

    amount = mandate.get("amount")
    if amount is None:
        return BudgetVerdict(allowed=False, reasons=reasons + ["mandate_missing_amount"])

    verifier = BudgetVerifier(budget_credential)
    verdict = verifier.check_payment(
        float(amount),
        counterparty=mandate.get("payee") or mandate.get("counterparty"),
        currency=mandate.get("currency"),
    )
    return BudgetVerdict(allowed=verdict.allowed and not reasons, reasons=reasons + verdict.reasons)
