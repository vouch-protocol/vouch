"""
Additively homomorphic commitments for period compute accounting.

A device commits to a work magnitude without disclosing it. The commitments
multiply, so an operator can demonstrate a period total (or a per-workload
aggregate) by opening one aggregate value rather than every record, and a
verifier confirms the aggregate really is the sum of the committed parts.

The group is the 2048-bit MODP group of RFC 3526 (a safe prime ``p = 2q + 1``),
with commitments taken in the prime-order-``q`` subgroup of quadratic residues.
The generator ``g`` is a fixed quadratic residue; the second generator ``h`` is
derived by hashing a fixed domain string into the field and squaring, so no
party knows ``log_g h``, which is the binding requirement. Pure Python integer
arithmetic, no additional dependency.

Commit(m, r) = g^m * h^r mod p, and Commit(m1, r1) * Commit(m2, r2) =
Commit(m1 + m2, r1 + r2).
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Iterable, Tuple

from ._common import PacingError, mb64, unmb64

# RFC 3526 MODP Group 14, a 2048-bit safe prime.
_P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"
)

P = int(_P_HEX, 16)
Q = (P - 1) // 2

# g = 2^2 mod p is a quadratic residue and therefore lies in the order-q subgroup.
G = 4

_H_DOMAIN = b"vouch-pacing-pedersen-h/v1"


def _derive_h() -> int:
    """Derive the second generator by hashing a domain string and squaring."""
    acc = b""
    material = b""
    counter = 0
    while len(material) < 256:
        acc = hashlib.sha512(_H_DOMAIN + counter.to_bytes(4, "big")).digest()
        material += acc
        counter += 1
    candidate = int.from_bytes(material[:256], "big") % P
    if candidate < 2:
        candidate = 2
    return pow(candidate, 2, P)


H = _derive_h()


def random_blinding() -> int:
    """A fresh blinding scalar in [1, q)."""
    return secrets.randbelow(Q - 1) + 1


def commit(magnitude: int, blinding: int) -> int:
    """Commit to a non-negative magnitude under a blinding scalar."""
    if not isinstance(magnitude, int) or isinstance(magnitude, bool):
        raise PacingError("magnitude must be an int")
    if magnitude < 0:
        raise PacingError("magnitude must be non-negative")
    if magnitude >= Q:
        raise PacingError("magnitude exceeds the group order")
    if not isinstance(blinding, int) or not 0 < blinding < Q:
        raise PacingError("blinding must be an int in (0, q)")
    return (pow(G, magnitude, P) * pow(H, blinding, P)) % P


def aggregate(commitments: Iterable[int]) -> int:
    """Multiply commitments, yielding a commitment to the sum of their values."""
    product = 1
    for value in commitments:
        if not isinstance(value, int) or not 0 < value < P:
            raise PacingError("commitment out of range")
        product = (product * value) % P
    return product


def aggregate_blindings(blindings: Iterable[int]) -> int:
    """Sum blinding scalars modulo the group order, matching :func:`aggregate`."""
    total = 0
    for value in blindings:
        total = (total + int(value)) % Q
    return total


def verify_opening(commitment: int, magnitude: int, blinding: int) -> bool:
    """Check that (magnitude, blinding) opens the commitment. Default-deny."""
    try:
        return commit(int(magnitude), int(blinding)) == int(commitment)
    except (PacingError, TypeError, ValueError):
        return False


def encode(value: int) -> str:
    """Encode a group element or scalar as a multibase big-endian integer."""
    if not isinstance(value, int) or value < 0:
        raise PacingError("value must be a non-negative int")
    length = max(1, (value.bit_length() + 7) // 8)
    return mb64(value.to_bytes(length, "big"))


def decode(value: str) -> int:
    """Inverse of :func:`encode`."""
    return int.from_bytes(unmb64(value), "big")


def commit_encoded(magnitude: int, blinding: int) -> Tuple[str, str]:
    """Commit and return the (commitment, blinding) pair already encoded."""
    return encode(commit(magnitude, blinding)), encode(blinding)
