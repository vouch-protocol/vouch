"""
Generate the cross-implementation test vector for BitstringStatusList.

This script is the single source of truth for the canonical encoded bitstring.
TypeScript and Go implementations verify they produce byte-identical encodedList
output from the same revoked indices, and decode the same bits back.

Run with the project venv:

    /home/rampy/venvvouch/bin/python test-vectors/bitstring-status-list/generate.py
"""

import json
from pathlib import Path

from vouch.status_list import (
    StatusList,
    build_status_list_credential,
    build_status_list_entry,
)


STATUS_URL = "https://issuer.example/status/1"
ISSUER_DID = "did:web:issuer.example"

# Indices that should be flipped to 1 (revoked) in the canonical vector.
# Selected to exercise: first bit, byte boundaries, mid-range, near end, exact end.
REVOKED_INDICES = [0, 1, 7, 8, 15, 100, 1023, 65535, 131_070, 131_071]


def main() -> None:
    sl = StatusList(status_list_id=STATUS_URL)
    for idx in REVOKED_INDICES:
        sl.revoke(idx)

    encoded_list = sl.encode()

    status_credential = build_status_list_credential(
        issuer_did=ISSUER_DID,
        status_list=sl,
        # Use fixed timestamps so the vector is deterministic.
        valid_seconds=30 * 24 * 60 * 60,
    )
    # Replace timestamps with deterministic placeholders so cross-impl
    # comparison stays exact even across days.
    status_credential["validFrom"] = "2026-01-01T00:00:00Z"
    status_credential["validUntil"] = "2026-01-31T00:00:00Z"

    sample_revoked_entry = build_status_list_entry(
        status_list_credential=STATUS_URL,
        status_list_index=REVOKED_INDICES[0],
    )
    sample_active_entry = build_status_list_entry(
        status_list_credential=STATUS_URL,
        status_list_index=42,  # not in REVOKED_INDICES
    )

    vector = {
        "description": (
            "Canonical cross-implementation test vector for W3C BitstringStatusList "
            "as implemented by Vouch Protocol. Encodes a 131,072-bit list with "
            "specific indices revoked. Python, TypeScript, and Go implementations "
            "must produce byte-identical encodedList output and report the same "
            "bits when decoded."
        ),
        "spec_reference": "https://www.w3.org/TR/vc-bitstring-status-list/",
        "status_list_id": STATUS_URL,
        "issuer_did": ISSUER_DID,
        "bitstring_length_bits": sl.length,
        "status_purpose": sl.status_purpose,
        "revoked_indices": REVOKED_INDICES,
        "active_indices_sample": [42, 99, 1024, 65534, 131_069],
        "expected_encoded_list": encoded_list,
        "status_list_credential": status_credential,
        "sample_credential_status_revoked": sample_revoked_entry,
        "sample_credential_status_active": sample_active_entry,
    }

    out_path = Path(__file__).parent / "vector.json"
    out_path.write_text(json.dumps(vector, indent=2, sort_keys=False) + "\n")
    print(f"Wrote {out_path}")
    print(f"  encodedList length: {len(encoded_list)} chars")
    print(f"  revoked indices: {REVOKED_INDICES}")


if __name__ == "__main__":
    main()
