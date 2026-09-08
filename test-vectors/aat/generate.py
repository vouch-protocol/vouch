#!/usr/bin/env python3
"""Regenerate the AAT chain fixtures.

Run from the repository root::

    python3 test-vectors/aat/generate.py

These fixtures are produced with the AAT reference implementation
(``tenuo``, Apache-2.0, https://github.com/tenuo-ai/tenuo). Nothing here builds
a token by hand: the root is minted and the leaf is derived through the
reference implementation's own API, so the fixtures are exactly what that
implementation emits.

Unlike the cryptographic vectors elsewhere in ``test-vectors/``, these are not
byte-reproducible. Warrant identifiers are UUIDv7-style and expiry is wall-clock,
so every run produces different bytes. They are illustrative chain fixtures, not
a deterministic interop contract -- see README.md.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from tenuo import Pattern, SigningKey, Warrant

HERE = Path(__file__).resolve().parent

# Fixed test seeds so the fixtures' keys are stable across regenerations.
# These are test-only keys published deliberately, matching the convention of
# the other vectors in this directory. They protect nothing.
ROOT_SEED = bytes([0x01] * 32)
HOLDER_SEED = bytes([0x02] * 32)
ATTACKER_SEED = bytes([0x03] * 32)

# 90 days, the reference implementation's maximum warrant TTL.
FIXTURE_TTL_SECONDS = 7_776_000


def _document(root_public_key_pem: str, warrants) -> dict:
    return {
        "aat_chain_version": 1,
        "root_public_key_pem": root_public_key_pem,
        "warrants": [w.to_base64() for w in warrants],
    }


def main() -> int:
    root_key = SigningKey.from_bytes(ROOT_SEED)
    holder_key = SigningKey.from_bytes(HOLDER_SEED)
    attacker_key = SigningKey.from_bytes(ATTACKER_SEED)

    # --- valid narrowing chain -------------------------------------------
    # Root grants read_file and write_file over reports/*.
    root = (
        Warrant.mint_builder()
        .capability("read_file", path=Pattern("reports/*"))
        .capability("write_file", path=Pattern("reports/*"))
        .ttl(FIXTURE_TTL_SECONDS)
        .holder(holder_key.public_key)
        .mint(root_key)
    )
    # Derived offline by the holder: read_file only. No authorization server.
    leaf = root.attenuate(
        capabilities={"read_file": {"path": Pattern("reports/*")}},
        signing_key=holder_key,
    )

    valid = _document(root_key.public_key.to_pem(), [root, leaf])

    # --- widening chain ---------------------------------------------------
    # The reference implementation refuses to *derive* a widened token at all:
    # attenuate() raises MonotonicityError rather than minting one. So a
    # widening fixture cannot be produced through derivation. What an attacker
    # can actually do is mint their own token claiming wider authority and
    # splice it in behind a genuine root -- which is what this fixture is.
    #
    # It is rejected on the I5 cryptographic-linkage invariant: the spliced
    # token carries no parent_hash binding it to the root.
    forged = (
        Warrant.mint_builder()
        .capability("read_file", path=Pattern("reports/*"))
        .capability("write_file", path=Pattern("reports/*"))
        .capability("delete_file", path=Pattern("*"))
        .ttl(FIXTURE_TTL_SECONDS)
        .holder(holder_key.public_key)
        .mint(attacker_key)
    )
    widening = _document(root_key.public_key.to_pem(), [root, forged])

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for name, doc, note in [
        (
            "valid-narrowing-chain.json",
            valid,
            "Root grants read_file + write_file on reports/*; the leaf is derived "
            "offline by the holder and grants read_file only.",
        ),
        (
            "widening-chain.json",
            widening,
            "A token minted by a third key claiming delete_file, spliced in behind "
            "a genuine root. MUST fail verification.",
        ),
    ]:
        payload = dict(doc)
        payload["_comment"] = note
        payload["_generated_at"] = generated_at
        payload["_generated_by"] = "test-vectors/aat/generate.py"
        (HERE / name).write_text(json.dumps(payload, indent=2) + "\n")
        print(f"wrote {name}")

    keys = {
        "_comment": (
            "Test-only Ed25519 seeds for the AAT fixtures. Published deliberately; "
            "they protect nothing. The holder seed is needed to mint the "
            "proof-of-possession for a call against the valid chain."
        ),
        "root_seed_hex": ROOT_SEED.hex(),
        "holder_seed_hex": HOLDER_SEED.hex(),
        "attacker_seed_hex": ATTACKER_SEED.hex(),
    }
    (HERE / "keys.json").write_text(json.dumps(keys, indent=2) + "\n")
    print("wrote keys.json")

    expiry = root.expires_at()
    print(f"\nFixtures expire at {expiry}. Re-run this script to refresh them.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
