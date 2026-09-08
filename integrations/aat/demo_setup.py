#!/usr/bin/env python3
"""Set up Scene 4 of the demo: an AAT chain narrowed offline.

Writes a demo directory containing the root AAT, a leaf derived offline from it,
the holder key, and a sample file for the agent to read.

    python3 integrations/aat/demo_setup.py --out /tmp/aat-demo

Everything here uses the AAT reference implementation
(https://github.com/tenuo-ai/tenuo, Apache-2.0). The derivation step contacts
nothing: narrowing an AAT is a local signing operation.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from tenuo import Pattern, SigningKey, Warrant

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from integrations.aat import ChainDocument, verify_chain_file  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="/tmp/aat-demo", help="demo directory")
    parser.add_argument("--ttl", type=int, default=3600, help="root TTL in seconds")
    args = parser.parse_args()

    out = Path(args.out)
    (out / "reports").mkdir(parents=True, exist_ok=True)

    root_key = SigningKey.generate()
    holder_key = SigningKey.generate()

    # 1. The root AAT: read_file AND write_file over reports/*.
    root = (
        Warrant.mint_builder()
        .capability("read_file", path=Pattern("reports/*"))
        .capability("write_file", path=Pattern("reports/*"))
        .ttl(args.ttl)
        .holder(holder_key.public_key)
        .mint(root_key)
    )

    # 2. Narrowed offline by the holder: read_file only. No server contacted.
    leaf = root.attenuate(
        capabilities={"read_file": {"path": Pattern("reports/*")}},
        signing_key=holder_key,
    )

    ChainDocument(
        root_public_key_pem=root_key.public_key.to_pem(),
        warrants_b64=[root.to_base64()],
    ).write(out / "root.json")

    ChainDocument(
        root_public_key_pem=root_key.public_key.to_pem(),
        warrants_b64=[root.to_base64(), leaf.to_base64()],
    ).write(out / "leaf.json")

    (out / "holder.pem").write_text(holder_key.to_pem())
    (out / "reports" / "q3.txt").write_text("Q3 revenue: up and to the right.\n")

    # Prove the written chain verifies before anyone points a camera at it.
    chain = verify_chain_file(out / "leaf.json")

    summary = {
        "root_tools": sorted(str(t) for t in root.tools),
        "leaf_tools": chain.tools,
        "leaf_jti": chain.leaf_jti,
        "chain_root": chain.root_jti,
        "leaf_depth": chain.depth,
        "leaf_expires_at": chain.expires_at,
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")

    print(f"Demo directory: {out}")
    print(f"  root AAT grants : {', '.join(summary['root_tools'])} on reports/*")
    print(f"  leaf AAT grants : {', '.join(summary['leaf_tools'])} on reports/*")
    print(f"  leaf jti        : {summary['leaf_jti']}")
    print(f"  chain root      : {summary['chain_root']}")
    print(f"  leaf depth      : {summary['leaf_depth']}")
    print("\nNarrowed offline. No authorization server was contacted.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
