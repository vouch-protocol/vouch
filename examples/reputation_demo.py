"""
Evidence-backed reputation, end to end.

Reputation in Vouch is a verifiable aggregate of signed, interaction-bound
receipts, computed by a public deterministic function. You trust the signatures
and the math, never a server's stored number. This walks the whole flow:

  receipts  ->  ledger  ->  signed snapshot  ->  policy gate
            ->  privacy-preserving threshold proof  ->  dispute

Run:
    python examples/reputation_demo.py
"""

from vouch import Signer, generate_identity
from vouch.accountability import attest_outcome, commit_outcome
from vouch.receipts import build_penalty_receipt, build_state_receipt
from vouch.reputation_disputes import build_dispute, build_dispute_resolution
from vouch.reputation_ledger import ReputationLedger, verify_reputation_credential
from vouch.reputation_policy import evaluate_reputation, policy_for_stakes
from vouch.reputation_portability import build_reputation_proof, verify_reputation_proof


def ident(domain):
    kp = generate_identity(domain=domain)
    return kp, Signer(private_key=kp.private_key_jwk, did=kp.did)


def main() -> None:
    agent_kp, agent = ident("agent.example.com")
    market_kp, market = ident("market.example.com")  # a relying party
    validator_kp, validator = ident("validator.example.com")  # an authority
    registry_kp, registry = ident("registry.example.com")  # the ledger operator
    agent_did = agent.get_did()

    # 1) The ledger admits only receipts it can verify. It resolves issuer keys.
    keys = {
        market.get_did(): market_kp.public_key_jwk,
        validator.get_did(): validator_kp.public_key_jwk,
    }
    ledger = ReputationLedger(resolver=lambda did: keys.get(did))

    # 2) Objective evidence: the market signs receipts for the agent's actions.
    ledger.append(
        build_state_receipt(
            market,
            agent=agent_did,
            interaction_id="t1",
            action="trade",
            result="success",
            sla_met=True,
        )
    )
    ledger.append(
        build_state_receipt(
            market,
            agent=agent_did,
            interaction_id="t2",
            action="trade",
            result="success",
            sla_met=True,
        )
    )
    # A pre-committed call by the agent, settled by the market (a neutral settler).
    c, secret = commit_outcome(
        agent,
        claim={"dir": "up"},
        settlement={"method": "market", "resolutionCriteria": "close"},
        private=True,
    )
    ledger.append(
        attest_outcome(market, commitment=c, outcome={"result": "up"}, secret=secret, matches=True)
    )
    # A penalty from an authority.
    penalty = build_penalty_receipt(
        validator, agent=agent_did, interaction_id="t3", kind="policy-violation", severity=0.4
    )
    ledger.append(penalty)

    print("receipts in ledger:", ledger.count(agent_did))

    # 3) The registry signs a snapshot of the agent's standing.
    snap = ledger.snapshot(registry, agent_did)
    ok, subject = verify_reputation_credential(snap, registry_kp.public_key_jwk)
    print(
        "snapshot verifies:",
        ok,
        "| composite:",
        subject["score"]["composite"],
        "| dims:",
        subject["score"]["dimensions"],
    )

    # 4) A skeptical consumer ignores the number and applies a policy after
    #    verifying the snapshot signature.
    decision = evaluate_reputation(
        snap, policy_for_stakes("high"), public_key=registry_kp.public_key_jwk
    )
    print("high-stakes gate allows:", decision.allowed, decision.failures)

    # 5) Privacy: the agent proves a threshold without revealing the score.
    proof = build_reputation_proof(
        registry,
        agent_did,
        ledger.score(agent_did),
        predicates=[{"path": "composite", "op": ">=", "value": 70}],
        audience="did:web:counterparty.example.com",
    )
    ok, assertions = verify_reputation_proof(
        proof,
        registry_kp.public_key_jwk,
        require=[{"path": "composite", "op": ">=", "value": 70}],
        audience="did:web:counterparty.example.com",
    )
    print(
        "threshold proof (composite >= 70) holds:",
        ok,
        "| score disclosed:",
        "composite" in str(proof["credentialSubject"].get("score", "")),
    )

    # 6) A dispute: an arbiter upholds a challenge, and the penalty drops out.
    _, challenger = ident("challenger.example.com")
    arbiter_kp, arbiter = ident("arbiter.example.com")
    dispute = build_dispute(challenger, receipt=penalty, reason="penalty was issued in error")
    resolution = build_dispute_resolution(arbiter, dispute=dispute, upheld=True)
    ledger.apply_resolution(resolution, arbiter_kp.public_key_jwk)
    print(
        "after upheld dispute -> composite:",
        ledger.score(agent_did).composite,
        "| receipts:",
        ledger.count(agent_did),
    )


if __name__ == "__main__":
    main()
