#!/usr/bin/env python3
"""Make one gated tool call against an AAT chain. Scene 4's working part.

    python3 integrations/aat/demo_call.py --chain /tmp/aat-demo/leaf.json \
        --holder-key /tmp/aat-demo/holder.pem \
        --tool read_file --path reports/q3.txt

Allowed calls run the tool and print the Vouch credential that records which
AAT authorised the action. Blocked calls print why, and the tool is never
invoked -- the counter at the end says so.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from integrations.aat import (  # noqa: E402
    AatError,
    AatGate,
    extract_aat_link,
    sign_with_aat_link,
    verify_chain_file,
)

INVOCATIONS: list = []


def read_file(base: Path, path: str) -> str:
    INVOCATIONS.append(("read_file", path))
    return (base / path).read_text()


def write_file(base: Path, path: str, content: str = "OVERWRITTEN\n") -> str:
    INVOCATIONS.append(("write_file", path))
    (base / path).write_text(content)
    return "written"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chain", required=True)
    parser.add_argument("--holder-key", required=True)
    parser.add_argument("--tool", required=True)
    parser.add_argument("--path", required=True)
    parser.add_argument("--base", default=None, help="defaults to the chain's directory")
    args = parser.parse_args()

    base = Path(args.base) if args.base else Path(args.chain).resolve().parent

    try:
        chain = verify_chain_file(args.chain)
    except AatError as exc:
        print(f"BLOCKED: the AAT chain did not verify -- {type(exc).__name__}: {exc}")
        return 1

    from tenuo import SigningKey

    holder_key = SigningKey.from_pem(Path(args.holder_key).read_text())
    gate = AatGate(chain, holder_key=holder_key)

    print(f"AAT leaf     : {chain.leaf_jti}")
    print(f"leaf permits : {', '.join(chain.tools)} on reports/*")
    print(f"requested    : {args.tool} {args.path}")
    print()

    decision = gate.check(args.tool, {"path": args.path})

    if not decision.allowed:
        print(f"BLOCKED before execution: {decision.reason}")
        print(f"tool invocations: {len(INVOCATIONS)}  <- the tool never ran")
        return 1

    tool = {"read_file": read_file, "write_file": write_file}.get(args.tool)
    if tool is None:
        print(f"BLOCKED: no such demo tool: {args.tool}")
        return 1

    result = tool(base, args.path)
    print(f"ALLOWED. Tool ran, returned: {result.strip()[:60]!r}")

    from vouch.keys import generate_identity
    from vouch.signer import Signer

    identity = generate_identity(domain="demo-agent.example.com")
    signer = Signer(private_key=identity.private_key_jwk, did=identity.did)

    credential = sign_with_aat_link(
        signer,
        chain,
        action=args.tool,
        target=args.path,
        resource=f"file://{args.path}",
    )

    print("\nVouch credential issued for this action:")
    print(json.dumps(credential, indent=2))
    print(f"\nAAT link on the credential: {json.dumps(extract_aat_link(credential))}")
    print(f"tool invocations: {len(INVOCATIONS)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
