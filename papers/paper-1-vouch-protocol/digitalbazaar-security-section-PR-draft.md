# Security Considerations (draft for digitalbazaar/mldsa44-rdfc-2024-cryptosuite README)

> **For Vouch editor:** Paste the content below into the Security section of the README in a fork of `digitalbazaar/mldsa44-rdfc-2024-cryptosuite` and open a PR titled something like *"docs: fill TBD Security section with ML-DSA-44 security considerations"*. Sign the PR as yourself / Vouch Protocol; reference Manu's review thread for context if you want.
>
> The content is generic to ML-DSA-44 as a cryptographic primitive. It does not mention Vouch Protocol, so it reads as a contribution by an implementer who cares about the cryptosuite, not as a Vouch marketing piece.
>
> Length: ~360 words. Cut a paragraph if it feels long for their README style.

---

## Security

### Security level

This cryptosuite uses ML-DSA-44, parameter set 2 of FIPS 204 (the NIST standardization of CRYSTALS-Dilithium). ML-DSA-44 targets NIST PQC Security Category 2, providing approximately 128-bit post-quantum security under standard model-of-quantum-computation assumptions. Practical attack cost against ML-DSA-44 by a fault-tolerant quantum adversary is estimated to require Grover-amplified key search well beyond the reach of any near-term quantum hardware. Classical attacks against ML-DSA-44 are infeasible for the foreseeable future.

### Determinism

ML-DSA signatures are deterministic under FIPS 204: signing the same message twice with the same private key produces the same signature, with no per-signature randomness required. This eliminates an entire class of nonce-reuse and randomness-failure vulnerabilities that affect classical schemes (most notably ECDSA). Implementations need not source high-quality entropy at signing time.

### Side-channel considerations

ML-DSA-44 implementations vary in their resistance to timing and power side-channel attacks. The reference implementation underlying this cryptosuite (FIPS 204 Section 4) is structured for constant-time execution, but downstream consumers should verify that their chosen ML-DSA library claims constant-time signing and verification on the deployment platform. For server-side issuance, this is usually adequate. For client-side or embedded signing, additional masking may be warranted.

### What this cryptosuite protects against

- Forgery of Verifiable Credentials by a classical or quantum adversary without knowledge of the issuer's ML-DSA-44 private key.
- Cryptanalytic compromise of Ed25519 (or any other classical algorithm) when this cryptosuite is paired with a classical proof on the same credential.
- Long-term verifiability of audit credentials retained past the lifetime of classical signatures.

### What this cryptosuite does not protect against

- Compromise of the signing key itself (key exfiltration, hardware compromise, social engineering).
- Replay of a valid credential against a different resource or in a different time window. Mitigation is the responsibility of the credential format and verifier policy, not the cryptosuite.
- Transport-layer attacks (TLS interception, downgrade). Use TLS 1.3 with PFS for credential transmission.
- Cross-cryptosuite confusion attacks. Verifiers MUST validate that the cryptosuite identifier in the proof matches the cryptosuite they expect; accepting any proof opens the door to algorithm-substitution attacks.

### Migration from classical-only deployments

Deployments transitioning from `eddsa-rdfc-2022-cryptosuite` to ML-DSA-44 should publish both a classical and a post-quantum verification method in the DID Document during the migration window, allowing credentials issued under either cryptosuite to verify. The credential's `proof.cryptosuite` field unambiguously declares which algorithm signed the credential; the verification method is resolved from the DID Document accordingly.

### References

- [FIPS 204 (ML-DSA Standard)](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST PQC Security Categories](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization/evaluation-criteria/security-(evaluation-criteria))
- [W3C Data Integrity 1.0](https://www.w3.org/TR/vc-data-integrity/)
