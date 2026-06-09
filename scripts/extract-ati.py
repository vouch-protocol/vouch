import json
from datetime import datetime
from pathlib import Path

SRC = Path("/home/rampy/agent-trust-index/data/results.json")
OUT = Path("/home/rampy/vouch-protocol/website/src/app/agent-trust-index/ati-data.ts")

data = json.loads(SRC.read_text())
results = data["results"] if isinstance(data, dict) and "results" in data else data

# Dedupe by name, keep the highest-scoring record (same logic as build_site.py).
best = {}
for r in results:
    cur = best.get(r["name"])
    if cur is None or r["score"] > cur["score"]:
        best[r["name"]] = r
agents = list(best.values())

total = len(agents)
with_did = sum(1 for a in agents if a["signals"].get("has_did"))
cannot = total - with_did
grade_a = sum(1 for a in agents if a.get("grade") == "A")
card = sum(1 for a in agents if a["signals"].get("has_card_identity"))
pq = sum(1 for a in agents if a["signals"].get("pq_ready"))
rev = sum(1 for a in agents if a["signals"].get("has_revocation"))

def pct(n):
    return round(n / total * 100, 1) if total else 0

# Sweep date from the data.
dates = [a.get("checked_at", "") for a in agents if a.get("checked_at")]
when = "7 June 2026"
if dates:
    try:
        d = datetime.fromisoformat(max(dates))
        when = d.strftime("%-d %B %Y")
    except Exception:
        pass

verifiable = sorted([a for a in agents if a["score"] > 0], key=lambda a: (-a["score"], a["name"]))
agents_out = [{
    "grade": a["grade"],
    "score": a["score"],
    "name": a["name"],
    "domains": ", ".join(a.get("domains") or []),
    "method": a["signals"].get("method") or "did:web",
    "did": a["signals"].get("did") or "",
} for a in verifiable]

summary = {
    "total": total,
    "verifiable": with_did,
    "cannot": cannot,
    "gradeA": grade_a,
    "pctVerifiable": pct(with_did),
    "pctCannot": pct(cannot),
    "pctCard": pct(card),
    "pctRev": pct(rev),
    "pctPq": pct(pq),
    "cardCount": card,
    "revCount": rev,
    "pqCount": pq,
    "generated": when,
}

ts = "// Generated from the Agent Trust Index sweep (agent-trust-index/data/results.json).\n"
ts += "// Do not edit by hand; regenerate with scripts/extract-ati.py.\n\n"
ts += "export const ATI_SUMMARY = " + json.dumps(summary, indent=2) + " as const;\n\n"
ts += "export type AtiAgent = { grade: string; score: number; name: string; domains: string; method: string; did: string };\n\n"
ts += "export const ATI_AGENTS: AtiAgent[] = " + json.dumps(agents_out, indent=2) + ";\n"
OUT.write_text(ts)

print(f"total={total} verifiable={with_did} ({pct(with_did)}%) cannot={cannot} ({pct(cannot)}%) gradeA={grade_a}")
print(f"card={card} ({pct(card)}%) endpoint(rev)={rev} ({pct(rev)}%) pq={pq} ({pct(pq)}%) date={when}")
print(f"wrote {len(agents_out)} verifiable agents -> {OUT}")
# em-dash guard on the generated file
import io
if "—" in OUT.read_text():
    print("WARNING: em-dash present in generated data (from agent names/domains)")
