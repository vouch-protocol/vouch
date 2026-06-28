#!/usr/bin/env python3
"""Run the Agent Trust Index sweep and write data/results.json.

This is the crawl runner. It calls ati.core.run(), which pages the whole public
Model Context Protocol registry, resolves each agent's did:web identity, scores
the trust signals, and returns a flat list of records. We write that list to
data/results.json, which is exactly what extract-ati.py (Next.js site data) and
build_site.py (legacy static HTML) read.

Usage:
    python run_sweep.py            # full sweep of the whole registry
    python run_sweep.py 25         # quick test: only the first 25 servers
"""

import json
import sys
from pathlib import Path

from ati.core import run

OUT = Path(__file__).resolve().parent / "data" / "results.json"


def main() -> None:
    cap = int(sys.argv[1]) if len(sys.argv) > 1 else None
    records = run(max_servers=cap, workers=16)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(records, indent=2))
    print(f"wrote {len(records)} records -> {OUT}")


if __name__ == "__main__":
    main()
