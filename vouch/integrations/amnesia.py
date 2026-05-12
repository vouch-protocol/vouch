"""
Vouch <-> Amnesia bridge.

Optional integration: when an Amnesia ``EgressDecision`` is available, wrap
it in a Verifiable Credential 2.0 with a Data Integrity proof
(``eddsa-jcs-2022`` or ``hybrid-eddsa-mldsa44-jcs-2026``) so that the
egress decision becomes a verifiable, replayable audit artifact in the
broader Vouch ecosystem.

This is the "pro mode" cryptographic attestation referenced in PAD-050
section 5.3.

The integration is **optional and one-directional**. Vouch does not
require Amnesia to function; Amnesia does not require Vouch to function.
Customers who deploy both gain unified attestations.

Typical use::

  from vouch.integrations.amnesia import attest_decision
  from vouch.signer import Signer

  decision = json.loads(open('.vouch/blocks.log').read().splitlines()[-1])
  signer = Signer.from_did_web('did:web:agent.example.com')
  vc = attest_decision(decision['decision'], signer)
  # vc is a dict ready to POST to an audit endpoint, store on disk, etc.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from vouch.data_integrity import sign_vc as _sign_vc_eddsa
from vouch.signer import Signer

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AmnesiaEgressAttestation:
  """Vouch's signed wrapper around an Amnesia EgressDecision."""

  credential: Dict[str, Any]
  """The full VC 2.0 with proof."""
  decision_overall: str
  """One of 'allow', 'block', 'attest'."""
  rule_count: int
  """Number of rules that matched."""


def attest_decision(
  decision: Dict[str, Any],
  signer: Signer,
  *,
  issuer_did: Optional[str] = None,
  cryptosuite: str = "eddsa-jcs-2022",
  contexts: Optional[List[str]] = None,
) -> AmnesiaEgressAttestation:
  """Wrap an Amnesia EgressDecision in a signed VC 2.0.

  Args:
    decision: The ``EgressDecision`` dict produced by Amnesia.Cortex
      (matches the shape defined in ``amnesia/src/shared/policy.ts``).
    signer: A configured Vouch ``Signer`` with access to the issuer's
      private key.
    issuer_did: Optional override for ``vc.issuer``. Defaults to the
      signer's DID.
    cryptosuite: ``eddsa-jcs-2022`` (classical) or
      ``hybrid-eddsa-mldsa44-jcs-2026`` (post-quantum hybrid). The
      corresponding proof type is selected automatically.
    contexts: Optional extra ``@context`` entries appended to the VC.

  Returns:
    An ``AmnesiaEgressAttestation`` containing the signed credential and
    a small structured summary for convenience.

  Raises:
    ValueError: if ``decision`` is missing required fields.
  """
  _validate_decision(decision)

  issuer = issuer_did or signer.did
  rule_decisions = decision.get("rule_decisions", [])
  matched = [r for r in rule_decisions if r.get("matched")]

  base_contexts = [
    "https://www.w3.org/ns/credentials/v2",
    "https://vouch-protocol.com/contexts/amnesia/v1",
  ]
  if contexts:
    base_contexts.extend(contexts)

  vc: Dict[str, Any] = {
    "@context": base_contexts,
    "type": ["VerifiableCredential", "AmnesiaEgressAttestation"],
    "issuer": issuer,
    "issuanceDate": _now_iso(),
    "credentialSubject": {
      "type": "AmnesiaEgressAttestation",
      "policyVersion": decision.get("policy_hash", ""),
      "diffHash": decision.get("diff_hash", ""),
      "evaluatedAt": decision.get("decided_at", _now_iso()),
      "decision": decision.get("overall", "unknown"),
      "blockReason": decision.get("block_reason"),
      "ruleDecisions": rule_decisions,
      "matchedRuleCount": len(matched),
      "evaluator": "amnesia-cortex/0.1",
    },
  }

  if cryptosuite == "eddsa-jcs-2022":
    signed = _sign_vc_eddsa(vc, signer)
  elif cryptosuite == "hybrid-eddsa-mldsa44-jcs-2026":
    from vouch.data_integrity_hybrid import sign_vc_hybrid as _sign_vc_hybrid

    signed = _sign_vc_hybrid(vc, signer)
  else:
    raise ValueError(f"unsupported cryptosuite: {cryptosuite}")

  return AmnesiaEgressAttestation(
    credential=signed,
    decision_overall=decision.get("overall", "unknown"),
    rule_count=len(matched),
  )


def attest_decision_from_log(
  log_path: str,
  signer: Signer,
  **kwargs: Any,
) -> List[AmnesiaEgressAttestation]:
  """Convenience: read all decisions from ``.vouch/blocks.log`` and sign each.

  The blocks log is a newline-delimited JSON file written by
  ``Cortex.Notifier``. Each line has shape ``{"ts": ..., "decision": {...}}``.

  Returns one ``AmnesiaEgressAttestation`` per parseable line. Lines that
  cannot be parsed are skipped with a warning.
  """
  out: List[AmnesiaEgressAttestation] = []
  try:
    with open(log_path, "r", encoding="utf-8") as fh:
      for ln in fh:
        ln = ln.strip()
        if not ln:
          continue
        try:
          entry = json.loads(ln)
          decision = entry.get("decision")
          if not decision:
            continue
          out.append(attest_decision(decision, signer, **kwargs))
        except (json.JSONDecodeError, ValueError) as e:
          logger.warning(
            "amnesia bridge: skipping malformed log line: %s", e
          )
  except FileNotFoundError:
    logger.info("amnesia bridge: blocks log not found at %s", log_path)
  return out


def _validate_decision(d: Dict[str, Any]) -> None:
  required = {"workspace", "decided_at", "diff_hash", "policy_hash", "overall"}
  missing = required - set(d.keys())
  if missing:
    raise ValueError(
      f"decision is missing required fields: {sorted(missing)}"
    )
  if d["overall"] not in {"allow", "block", "attest"}:
    raise ValueError(
      f"unexpected overall value: {d['overall']!r}; "
      "expected one of allow|block|attest"
    )


def _now_iso() -> str:
  return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = [
  "AmnesiaEgressAttestation",
  "attest_decision",
  "attest_decision_from_log",
]
