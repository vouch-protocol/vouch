"""
Inference provenance: prove an agent's output came from this model on this
context, and catch a fabricated or substituted context.

Reasoned actions prove an agent stated why. This proves the decision actually
came from a specific model processing a specific context, and lets an auditor
re-fetch the sources or re-run the model and byte-compare.

Run:
    python examples/provenance_demo.py
"""

from vouch import Signer, generate_identity
from vouch.provenance import (
    check_replay,
    sign_inference_provenance,
    verify_context,
    verify_inference_provenance,
    weights_hash,
)


def main() -> None:
    agent_kp = generate_identity(domain="agent.example.com")
    agent = Signer(private_key=agent_kp.private_key_jwk, did=agent_kp.did)

    # The model the agent ran (in practice the hash is computed once at load).
    model_hash = weights_hash(b"...llama-3-8b-instruct weight bytes...")

    # The retrieved context the answer is grounded in.
    context = [
        {"source": "policy://refunds/v4", "text": "Refunds allowed within 30 days of delivery."},
        {"source": "order://A-1007", "text": "Delivered 2026-06-20. Amount 120 USD."},
    ]
    output = {"action": "approve_refund", "order": "A-1007", "amount": "usd:120"}
    sampler = {"seed": 42, "temperature": 0.0, "topP": 1.0}

    cred = sign_inference_provenance(
        agent,
        output=output,
        model_weights_hash=model_hash,
        context_chunks=context,
        sampler=sampler,
    )
    print("provenance credential:", cred["id"])
    print(
        "context root:", cred["credentialSubject"]["provenance"]["contextRoot"]["root"][:22], "..."
    )

    # ---- Auditor ----
    ok, subject = verify_inference_provenance(cred, agent_kp.public_key_jwk)
    print("\ncredential verifies?      ", ok)

    # 1) Re-fetch the SAME sources -> context root reproduces.
    good, _ = verify_context(context, subject)
    print("context reproduces?       ", good, "(sources were not fabricated or substituted)")

    # 2) Deterministic replay: same model + context + seed -> same output.
    r = check_replay(subject, output=output, model_weights_hash=model_hash)
    print("replay matches?           ", r is None, "(this model produced this output)")

    # ---- Two attacks this catches ----
    print("\nAttacks:")

    # A) A substituted context (agent claimed different sources).
    forged_context = [
        {"source": "policy://refunds/v4", "text": "Refunds allowed any time, no limit."},
        {"source": "order://A-1007", "text": "Delivered 2026-06-20. Amount 120 USD."},
    ]
    _, reason = verify_context(forged_context, subject)
    print("  substituted context:   rejected ->", reason)

    # B) A different model claiming to have produced the output.
    other_model = weights_hash(b"...a different, fine-tuned model...")
    print(
        "  swapped model:         rejected ->",
        check_replay(subject, model_weights_hash=other_model),
    )

    print(
        "\nThis does not read the model's mind. It makes the provenance of a\n"
        "decision reproducible and its inputs non-repudiable: which model, on which\n"
        "context, with which seed. It is the anchor point for zero-knowledge proofs\n"
        "of inference later."
    )


if __name__ == "__main__":
    main()
