# Hybrid Ed25519 + ML-DSA-44 Test Vectors

Cross-implementation interop vectors for the
`hybrid-eddsa-mldsa44-jcs-2026` cryptosuite (W3C CG Report §13.2,
PAD-040).

All Vouch Protocol implementations (Python, TypeScript, Go) MUST be
able to:

1. **Verify** any credential in `vector.json` against the published
   public keys.
2. **Reproduce** the canonical bytes of each credential via JCS
   canonicalization (cross-checked against `../jcs/vectors.json`).
3. **Verify in all three modes**:
   - Mode A (classical-only): Ed25519 signature alone.
   - Mode B (post-quantum-only): ML-DSA-44 signature alone.
   - Mode C (both required): both signatures must validate.

The vectors are generated deterministically from the seeds in
`generation-params.json` so any implementation can regenerate them
locally for self-validation.

## Files

- `vector.json`: One canonical hybrid credential. Use as a smoke test.
- `generation-params.json`: Seeds used to deterministically derive the
  Ed25519 and ML-DSA-44 keypairs and the credential timestamps. Useful
  for regenerating vectors when test conditions need updating.

## Properties demonstrated

The single vector demonstrates the **same-bytes** property of the
hybrid cryptosuite (PAD-040): the Ed25519 signature and the ML-DSA-44
signature are computed over the **same** JCS-canonicalized bytes, with
a single SHA-256 digest. The `proofValue` is the multibase-encoded
concatenation of the two signatures (Ed25519 first, then ML-DSA-44).

## Adding new vectors

When adding a new vector, ensure:

1. The vector validates in Python, TypeScript, and Go reference
   implementations.
2. The canonical form is reproducible from the input via JCS.
3. The vector's intent payload includes the required `action`,
   `target`, and `resource` fields.
4. Both signature components are included in the proofValue.

The canonical fixtures are generated in CI; do not edit `vector.json`
by hand once it has been signed.
