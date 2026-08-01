"""
Authority Freshness: a state change collapses the window to now.

Time-decay trust answers how long ago trust was established. That is not enough
for a treasury agent whose mandate can be suspended seconds after a valid
credential is issued. An authority publishes a signed state carrying a counter
that only goes up. Once a verifier has seen a newer counter, the same time-valid
session voucher minted under the old one is refused for a high-consequence
action, even though its decayed trust still passes.

Run:
    python examples/authority_freshness_demo.py
"""

from vouch import Signer, generate_identity
from vouch.authority_state import (
    STATUS_SUSPENDED,
    evaluate_authority_freshness,
    sign_authority_state,
    verify_authority_state,
)
from vouch.status_list import (
    CONSEQUENCE_CRITICAL,
    CONSEQUENCE_ROUTINE,
    CONSEQUENCE_SENSITIVE,
)
from vouch.trust_check import verify_agent_call
from vouch.vc import build_session_voucher

INTENT = {
    "action": "transfer_funds",
    "target": "vendor-1",
    "resource": "https://bank.example.com/transfers",
}


def main() -> None:
    treasury = generate_identity(domain="treasury.example.com")
    agent = generate_identity(domain="agent.example.com")
    signer = Signer(private_key=agent.private_key_jwk, did=agent.did)
    credential = signer.sign(intent=INTENT, valid_seconds=300)

    # The agent holds a voucher minted under authority epoch 5. It stays
    # time-valid for the whole demo; only the authority's state moves.
    voucher = build_session_voucher(
        subject_did=agent.did,
        validator_dids=["did:web:validator.example.com"],
        decay_lambda=0.001,
        initial_trust=1.0,
        max_ttl_seconds=3600,
        scope=["agent_actions"],
        valid_seconds=300,
        authority_epoch=5,
    )
    print("voucher minted under authorityEpoch 5, time-valid throughout")

    # Nothing has happened yet. The verifier has seen epoch 5 too.
    v = verify_agent_call(
        credential,
        public_key=signer.get_public_key_multikey(),
        session_voucher=voucher,
        trust_threshold=0.9,
        consequence=CONSEQUENCE_SENSITIVE,
        last_seen_authority_epoch=5,
    )
    print(f"\nbefore the fraud signal, transfer accepted? {'yes' if v.ok else 'no'}")
    print(f"  decayed trust {v.trust:.4f} · {v.authority_reason}")

    # A fraud signal fires. The treasury publishes a suspended state, which
    # bumps the counter to 6, and signs it with its own key.
    treasury_signer = Signer(private_key=treasury.private_key_jwk, did=treasury.did)
    suspended = sign_authority_state(treasury_signer, 6, status=STATUS_SUSPENDED)
    ok, passport = verify_authority_state(suspended, treasury.public_key_jwk)
    print(
        f"\nauthority publishes epoch {passport.authority_epoch} · {passport.status} (verified: {ok})"
    )

    # The SAME voucher, still time-valid, is now refused for the transfer.
    v = verify_agent_call(
        credential,
        public_key=signer.get_public_key_multikey(),
        session_voucher=voucher,
        trust_threshold=0.9,
        consequence=CONSEQUENCE_SENSITIVE,
        last_seen_authority_epoch=passport.authority_epoch,
    )
    print(f"\nafter the fraud signal, transfer accepted? {'yes' if v.ok else 'no'}")
    print(f"  decayed trust {v.trust:.4f} still passes ({v.trust_ok})")
    print(f"  refused by the state gate: {v.authority_reason}")

    # A routine read is unaffected: it never depended on authority state.
    v = verify_agent_call(
        credential,
        public_key=signer.get_public_key_multikey(),
        session_voucher=voucher,
        trust_threshold=0.5,
        consequence=CONSEQUENCE_ROUTINE,
        last_seen_authority_epoch=passport.authority_epoch,
    )
    print(f"\na routine read still accepted? {'yes' if v.ok else 'no'} (time-decay only)")

    # The top tier does not trust a cached counter at all. It requires a live
    # quorum co-sign read at the moment of the action.
    verdict = evaluate_authority_freshness(
        tier=CONSEQUENCE_CRITICAL,
        voucher_epoch=5,
        last_seen_epoch=5,
        live_cosign_ok=None,
    )
    print(f"\ncritical action without a live co-sign: {verdict.reason}")
    verdict = evaluate_authority_freshness(
        tier=CONSEQUENCE_CRITICAL,
        voucher_epoch=5,
        last_seen_epoch=5,
        live_cosign_ok=True,
    )
    print(f"critical action with a live co-sign:    allowed ({verdict.allow})")


if __name__ == "__main__":
    main()
