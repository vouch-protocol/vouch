"""
Run the Agent Trust Index MVP.

    python run.py [limit]

It scans agents from the MCP registry, scores each on whether it publishes a
verifiable identity, writes data/results.json, and prints a summary.
"""

import json
import sys
from pathlib import Path

from ati.core import run


def main() -> None:
    max_servers = int(sys.argv[1]) if len(sys.argv) > 1 else None
    results = run(max_servers=max_servers)

    Path("data").mkdir(exist_ok=True)
    Path("data/results.json").write_text(json.dumps(results, indent=2))

    # The registry lists multiple versions per agent, so dedupe to unique agents
    # (an agent counts as verifiable if any of its versions is). This keeps the
    # published number defensible.
    best = {}
    for r in results:
        cur = best.get(r["name"])
        if cur is None or r["score"] > cur["score"]:
            best[r["name"]] = r
    agents = list(best.values())

    rows = len(results)
    total = len(agents)
    with_did = sum(1 for a in agents if a["signals"]["has_did"])
    pct = (with_did / total * 100) if total else 0.0
    grades = {g: 0 for g in ["A", "B", "C", "D", "F"]}
    for a in agents:
        grades[a["grade"]] = grades.get(a["grade"], 0) + 1

    print("Agent Trust Index (MVP)")
    print("=" * 48)
    print(f"Scanned {rows} registry entries, {total} unique agents.")
    print(f"Can prove who they are (resolvable identity): {with_did} ({pct:.2f}%)")
    print(f"Cannot prove who they are: {total - with_did} ({(total - with_did) / total * 100 if total else 0:.2f}%)")
    print("Grade distribution: " + ", ".join(f"{g}={grades[g]}" for g in ["A", "B", "C", "D", "F"]))
    print("Results written to data/results.json")

    top = sorted(agents, key=lambda a: -a["score"])
    top = [a for a in top if a["score"] > 0][:10]
    if top:
        print("\nA sample of agents that can prove who they are:")
        for a in top:
            print(f"  {a['grade']} {a['score']:>3}  {a['name']}  ({', '.join(a['domains']) or 'no domain'})")
    else:
        print("\nNo unique agent publishes a verifiable identity.")
        print("That is the gap. An agent with Vouch would score an A and stand alone.")


if __name__ == "__main__":
    main()
