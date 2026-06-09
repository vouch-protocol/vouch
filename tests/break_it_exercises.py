"""
Vouch Protocol - "Break It" learning exercises (Phase 3 of the mastery plan).

These are NOT part of the real test suite. They are a learning scaffold for
the editor to gain confidence by proving, with his own hands, exactly how
Vouch refuses bad input. Each exercise has a TODO you fill in, and an
assertion describing the refusal you should observe.

How to use:
  1. Read the target module + spec section named in each exercise.
  2. Fill in the TODO so the test constructs a VALID artifact first.
  3. Then tamper as described, and confirm the assertion (the refusal) holds.
  4. If an assertion FAILS (i.e. bad input was accepted), you've found either
     a real bug or a gap in your understanding. Either is valuable.

Run with:  python -m pytest tests/break_it_exercises.py -v
(Adjust imports to the actual current API; the point is the exercise, not
that these pass out of the box. Check vouch/signer.py and vouch/verifier.py
for the real signatures.)
"""

import pytest


# ---------------------------------------------------------------------------
# Exercise 1 - Tampered proof must fail verification
# Target: vouch/data_integrity.py, vouch/verifier.py   Spec: section 5.5, 8
# ---------------------------------------------------------------------------
def test_tampered_credential_subject_is_rejected():
    """A signed credential whose intent is changed after signing must fail."""
    # TODO: build identity, sign a credential for intent {read, customer, acct:42}
    # cred = signer.sign_credential(intent={...})
    # TODO: mutate cred["credentialSubject"]["intent"]["action"] = "delete"
    # result = verifier.verify_credential(tampered, public_key=...)
    # assert result is False  # signature no longer covers the bytes
    pytest.skip("fill in: tamper the subject, confirm verify returns False")


# ---------------------------------------------------------------------------
# Exercise 2 - Wrong issuer DID must fail
# Target: vouch/verifier.py, vouch/did_web.py          Spec: section 6, 8
# ---------------------------------------------------------------------------
def test_issuer_swap_is_rejected():
    """Changing issuer to a DID that didn't sign must fail verification."""
    # TODO: sign with did:web:good.example, then set issuer = did:web:evil.example
    # assert verify fails (signature/DID mismatch or resolution failure)
    pytest.skip("fill in: swap issuer DID, confirm refusal")


# ---------------------------------------------------------------------------
# Exercise 3 - Expired credential must fail
# Target: vouch/verifier.py                            Spec: section 5.3, 8.2
# ---------------------------------------------------------------------------
def test_expired_credential_is_rejected():
    """validUntil in the past must fail (allowing for clock-skew window)."""
    # TODO: sign with valid_until_seconds in the past (or set validUntil manually)
    # assert verify fails with an expiry error
    pytest.skip("fill in: backdate validUntil, confirm expiry refusal")


# ---------------------------------------------------------------------------
# Exercise 4 - Revoked credential must fail
# Target: vouch/revocation.py                          Spec: section 11.2
# ---------------------------------------------------------------------------
def test_revoked_status_is_rejected():
    """A credential whose status-list bit is flipped to revoked must fail."""
    # TODO: build a StatusList, allocate an index, issue a credential with that
    #       status entry, verify it passes, then flip the bit to revoked and
    #       confirm verification now fails.
    pytest.skip("fill in: revoke via status list, confirm refusal")


# ---------------------------------------------------------------------------
# Exercise 5 - Delegation that WIDENS resource must fail
# Target: chain validation                             Spec: section 9.3 step 5
# ---------------------------------------------------------------------------
def test_resource_widening_in_delegation_is_rejected():
    """Child link whose resource is broader than the parent's must fail."""
    # TODO: root delegates resource=acct:42; child tries resource=acct:* (wider)
    # assert chain validation rejects (resource-narrowing rule)
    pytest.skip("fill in: widen resource in child link, confirm refusal")


# ---------------------------------------------------------------------------
# Exercise 6 - Delegation that WIDENS the time window must fail
# Target: chain validation                             Spec: section 9.3 step 6
# ---------------------------------------------------------------------------
def test_time_widening_in_delegation_is_rejected():
    """Child link whose validity window exceeds the parent's must fail."""
    # TODO: parent valid 09:00-11:00; child tries 09:00-13:00 (wider)
    # assert chain validation rejects (temporal-bounds rule)
    pytest.skip("fill in: widen time window in child link, confirm refusal")


# ---------------------------------------------------------------------------
# Exercise 7 - Dual-proof: tamper must fail BOTH modes
# Target: vouch/data_integrity_hybrid.py               Spec: section 13
# ---------------------------------------------------------------------------
def test_dual_proof_tamper_fails_classical_and_pq():
    """A tampered dual-proof credential must fail Mode A and Mode B."""
    # TODO: sign hybrid, tamper subject, verify with required=[eddsa-jcs-2022] -> fail
    #       and with required=[mldsa44-jcs-2026] -> fail
    pytest.skip("fill in: tamper dual-proof, confirm both modes refuse")


# ---------------------------------------------------------------------------
# Exercise 8 - Cross-impl: same input -> byte-identical canonical form
# Target: vouch/jcs.py                                 Spec: section 5, 15
# ---------------------------------------------------------------------------
def test_jcs_is_deterministic_for_reordered_keys():
    """Two dicts with the same content in different key order canonicalize
    to identical bytes (this is what makes Python/TS/Go agree)."""
    # TODO: jcs({"b":1,"a":2}) == jcs({"a":2,"b":1})  byte-for-byte
    pytest.skip("fill in: confirm JCS key-order independence")
