# PAD-004: Automated Liability Adjudication & Dynamic Insurance Pricing for Autonomous Agents

**Publication Date:** January 03, 2026  
**Author:** Vouch Protocol Maintainers  
**Subject:** The "AI Black Box" — Cryptographic flight recorders for liability attribution  
**Status:** Public Prior Art  
**License:** Apache 2.0

## 1. Abstract

This disclosure places into the public domain a system and method for automated liability attribution in autonomous AI agents. It describes the use of a cryptographically signed "Chain of Intent" (similar to a flight data recorder) to programmatically resolve disputes, process insurance claims, and adjust real-time risk premiums for non-deterministic AI systems.

## 2. Problem Statement

Traditional liability frameworks fail for AI agents due to the "Black Box Problem." When an agent causes damage (e.g., deletes a production database or executes a bad trade), it is often impossible to distinguish between:

1. **Malice:** The agent was hijacked by an attacker.
2. **Hallucination:** The agent's stochastic model failed despite valid inputs.
3. **Misalignment:** The agent technically followed a vague user instruction but produced a harmful outcome.

Without a tamper-proof audit trail of the *intent* (reasoning) at the moment of action, insurers cannot accurately price risk or adjudicate claims.

### 2.1 The Liability Gap

```
┌─────────────────────────────────────────────────────────┐
│                    AI Agent Action                       │
│                          ↓                               │
│              Damage Occurs ($100,000)                    │
│                          ↓                               │
│    ┌─────────────────────────────────────────┐          │
│    │           WHO IS LIABLE?                 │          │
│    ├─────────────────────────────────────────┤          │
│    │ • User who gave instructions?           │          │
│    │ • Model provider (OpenAI, Anthropic)?   │          │
│    │ • Agent framework (LangChain)?          │          │
│    │ • Infrastructure provider?              │          │
│    │ • External attacker?                    │          │
│    └─────────────────────────────────────────┘          │
│                          ↓                               │
│              IMPOSSIBLE TO DETERMINE                     │
│            (No cryptographic evidence)                  │
└─────────────────────────────────────────────────────────┘
```

## 3. The Novel Solution: Cryptographic Adjudication

We disclose a method where an "AI Liability Policy" is enforced via a protocol (like Vouch) that binds actions to signed intent logs.

### 3.1 The Adjudication Logic

The system defines a "Smart Adjudicator" that processes the cryptographic log:

| Case | Condition | Attribution | Policy Triggered |
|------|-----------|-------------|------------------|
| **A: The Breach** | Signature invalid OR chain broken | External Attacker | Cybersecurity Policy |
| **B: The Alignment Failure** | Signature valid, intent contradicts outcome | Model Failure | E&O (Errors & Omissions) |
| **C: The Negligence** | Signature valid, user authorized risky action | User Operator | Claim Denied |

### 3.2 Adjudication Flow

```python
def adjudicate_claim(vouch_token: str, damage_report: dict) -> ClaimResult:
    """
    Automated liability adjudication using Vouch Protocol.
    """
    # Step 1: Verify cryptographic chain
    valid, passport = Verifier.verify(vouch_token)
    
    if not valid:
        # Case A: Signature invalid = Attacker
        return ClaimResult(
            attribution="EXTERNAL_ATTACKER",
            policy="CYBERSECURITY",
            payout=damage_report.amount
        )
    
    # Step 2: Check intent alignment
    intent = passport.payload
    outcome = damage_report.actual_outcome
    
    if not is_intent_aligned(intent, outcome):
        # Case B: Model hallucinated/misaligned
        return ClaimResult(
            attribution="MODEL_FAILURE",
            policy="ERRORS_AND_OMISSIONS",
            payout=damage_report.amount
        )
    
    # Case C: User explicitly authorized the action
    return ClaimResult(
        attribution="USER_OPERATOR",
        policy="NONE",
        payout=0,
        reason="User authorized risky action in signed intent"
    )
```

### 3.3 Dynamic Risk Pricing (The "Pay-How-You-Drive" for AI)

We further disclose a method for real-time premium adjustment based on protocol usage:

| Risk Factor | Premium Adjustment | Rationale |
|-------------|-------------------|-----------|
| Uses Identity Sidecar (PAD-003) | -20% | Keys isolated from LLM |
| Enforces Chain of Custody (PAD-002) | -15% | Full audit trail |
| Implements policy guardrails | -10% | Pre-signing validation |
| No Vouch integration | +50% | Black box risk |

### 3.4 Insurance Provider as Root Verifier

The insurance provider acts as a "Root Verifier," rejecting coverage for any transaction that does not carry a valid Vouch proof:

```
┌─────────────────────────────────────────────────────────┐
│                   Insurance Policy                       │
├─────────────────────────────────────────────────────────┤
│  COVERAGE REQUIREMENTS:                                  │
│                                                          │
│  ✓ All high-value actions (>$1000) MUST include         │
│    valid Vouch-Token with signed intent                 │
│                                                          │
│  ✓ Chain of Custody required for delegated actions      │
│                                                          │
│  ✗ Unverified actions are NOT covered                   │
└─────────────────────────────────────────────────────────┘
```

## 4. Implementation Architecture

### 4.1 Components

1. **Intent Logger** - Captures and signs all agent decisions
2. **Policy Engine** - Validates intents before signing
3. **Claim Processor** - Automated adjudication
4. **Premium Calculator** - Real-time risk scoring

### 4.2 Integration with Vouch Protocol

```python
class InsuredAgent:
    def __init__(self, signer: Signer, policy_id: str):
        self.signer = signer
        self.policy_id = policy_id
        self.intent_log = []
    
    async def execute_action(self, action: dict) -> Result:
        # 1. Sign the intent BEFORE execution
        vouch_token = self.signer.sign(
            payload={
                "action": action,
                "policy_id": self.policy_id,
                "risk_assessment": self.assess_risk(action)
            }
        )
        
        # 2. Log for insurance purposes
        self.intent_log.append(vouch_token)
        
        # 3. Execute with proof attached
        result = await self.perform_action(action, vouch_token)
        
        return result
    
    async def file_claim(self, damage: dict) -> ClaimResult:
        # Submit intent log for adjudication
        return await insurance_api.adjudicate(
            intent_log=self.intent_log,
            damage_report=damage
        )
```

## 5. Prior Art Statement

By publishing this disclosure, we establish prior art for any system that uses cryptographic intent logging to automate:

1. **AI Professional Liability Insurance claims** - Automated E&O processing
2. **Smart Contract-based insurance payouts** - On-chain adjudication
3. **Legal dispute resolution** - Cryptographic evidence for AI liability
4. **Real-time risk pricing** - Dynamic premiums based on protocol compliance
5. **Regulatory compliance** - Audit trails for AI governance

### 5.1 Related Work

| Concept | Source | Differentiation |
|---------|--------|-----------------|
| Usage-based insurance | Auto insurance | Applies to AI agent behavior |
| Smart contract claims | DeFi insurance | Uses intent chains, not just transactions |
| E&O insurance | Professional liability | Automated adjudication via crypto proofs |

### 5.2 Claims Established as Prior Art

This disclosure precludes patents on:

1. "Cryptographic liability attribution for AI agents"
2. "Intent-based insurance adjudication for autonomous systems"
3. "Dynamic premium pricing based on AI agent security practices"
4. "Flight recorder patterns for AI agent liability"

## 6. Reference Implementation

- **Repository:** https://github.com/vouch-protocol/vouch
- **Reputation System:** `vouch/reputation.py`
- **Related Disclosures:** PAD-002 (Chain of Custody), PAD-003 (Identity Sidecar)

---

*This document is published as prior art to prevent patent assertion on the described concepts while allowing free use by the community under the Apache 2.0 license.*
