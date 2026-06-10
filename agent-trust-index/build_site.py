"""
Build the static Agent Trust Index site from data/results.json.

Produces site/index.html and grade badges in site/badges/. The page is styled to
match vouch-protocol.com (parchment, ink, burgundy, Source Serif 4, JetBrains
Mono). It leads with accountability, puts the call to action up top, and shows
what each verifiable agent uses.

    python build_site.py
"""

import html
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).parent
SITE = ROOT / "site"
(SITE / "badges").mkdir(parents=True, exist_ok=True)

COLORS = {"A": "#2f7d4f", "B": "#3fa05f", "C": "#9a7d1f", "D": "#b56b28", "F": "#9b3b44"}


def badge_svg(grade: str) -> str:
    color = COLORS.get(grade, "#7c2d3a")
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" width="150" height="20" role="img" '
        f'aria-label="Agent Trust: {grade}">'
        '<rect width="100" height="20" fill="#0f172a"/>'
        f'<rect x="100" width="50" height="20" fill="{color}"/>'
        '<g fill="#faf7ee" font-family="JetBrains Mono,Verdana,sans-serif" font-size="11" text-anchor="middle">'
        '<text x="50" y="14">Agent Trust</text>'
        f'<text x="125" y="14" font-weight="bold">{grade}</text>'
        "</g></svg>"
    )


def main() -> None:
    results = json.loads((ROOT / "data" / "results.json").read_text())

    best = {}
    for r in results:
        cur = best.get(r["name"])
        if cur is None or r["score"] > cur["score"]:
            best[r["name"]] = r
    agents = list(best.values())

    total = len(agents)
    with_did = sum(1 for a in agents if a["signals"]["has_did"])
    cannot = total - with_did
    grade_a = sum(1 for a in agents if a["grade"] == "A")
    pct_cannot = (cannot / total * 100) if total else 0
    pct_verif = (with_did / total * 100) if total else 0
    verifiable = sorted([a for a in agents if a["score"] > 0], key=lambda a: (-a["score"], a["name"]))
    generated = datetime.now(timezone.utc).strftime("%d %B %Y")

    card_count = sum(1 for a in agents if a["signals"].get("has_card_identity"))
    pq_count = sum(1 for a in agents if a["signals"].get("pq_ready"))
    rev_count = sum(1 for a in agents if a["signals"].get("has_revocation"))
    pct_did = (with_did / total * 100) if total else 0
    pct_card = (card_count / total * 100) if total else 0
    pct_pq = (pq_count / total * 100) if total else 0
    pct_rev = (rev_count / total * 100) if total else 0

    for grade in COLORS:
        (SITE / "badges" / f"{grade}.svg").write_text(badge_svg(grade))

    rows = []
    for a in verifiable:
        grade = a["grade"]
        color = COLORS.get(grade, "#7c2d3a")
        name = html.escape(a["name"])
        domains = html.escape(", ".join(a["domains"]))
        method = html.escape(a["signals"].get("method") or "did:web")
        rows.append(
            f'<tr data-grade="{grade}"><td><span class="g" style="background:{color}">{grade}</span></td>'
            f'<td class="num">{a["score"]}</td><td>{name}</td>'
            f'<td class="dim">{domains}</td><td class="dim">{method}</td></tr>'
        )
    rows_html = "\n".join(rows)

    template = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Agent Trust Index</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Source+Serif+4:ital,opsz,wght@0,8..60,400;0,8..60,600;0,8..60,700;1,8..60,400&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>
:root{
 --parchment:#FAF7EE; --parchment-warm:#F2EBD9; --parchment-deep:#EFE9D5;
 --ink:#0F172A; --ink-soft:#334155; --ink-faint:#64748b;
 --burgundy:#7C2D3A; --burgundy-dark:#5C1F2C; --rule:#D9CFB6; --rule-light:#E7DEC8;
}
*{box-sizing:border-box}
body{margin:0;background:var(--parchment);color:var(--ink);font-family:"Source Serif 4",Georgia,serif;line-height:1.6;font-feature-settings:"kern","liga","onum"}
.wrap{max-width:1080px;margin:0 auto;padding:0 24px}
.mono{font-family:"JetBrains Mono",ui-monospace,monospace}
.eyebrow{font-family:"JetBrains Mono",monospace;text-transform:uppercase;color:var(--burgundy);font-size:0.7rem;letter-spacing:0.16em}
header.top{padding:44px 0 0;text-align:center}
header.top h1{font-weight:700;font-size:2.4rem;line-height:1.12;letter-spacing:-0.01em;margin:10px 0 0}
header.top .lede{font-style:italic;color:var(--ink-soft);font-size:1.15rem;max-width:58ch;margin:12px auto 0}
.hero{text-align:center;padding:44px 0 8px}
.hero .big{font-weight:700;font-size:6rem;line-height:1;color:var(--burgundy)}
.hero .sub{font-size:1.25rem;margin-top:8px}
.hero .src{color:var(--ink-faint);font-size:0.9rem;margin-top:10px}
.cta{background:var(--parchment-warm);border:1px solid var(--rule);padding:30px 28px;margin:28px 0;text-align:center}
.cta h2{font-weight:600;font-size:1.5rem;margin:0 0 8px}
.cta p{margin:0 auto 12px;max-width:60ch}
.cta code{font-family:"JetBrains Mono",monospace;font-size:0.9rem;background:var(--ink);color:var(--parchment);padding:6px 12px;display:inline-block}
.cta a{color:var(--burgundy);text-decoration:underline;text-underline-offset:2px}
.section{padding:30px 0;border-top:1px solid var(--rule)}
.section h2{font-weight:600;font-size:1.5rem;margin:0 0 10px}
.cols{display:grid;grid-template-columns:1fr 1fr 1fr;gap:18px;margin-top:14px}
.col h3{font-family:"JetBrains Mono",monospace;text-transform:uppercase;font-size:0.7rem;letter-spacing:0.14em;color:var(--burgundy);margin:0 0 6px}
.col p{margin:0;color:var(--ink-soft);font-size:0.98rem}
.stats{display:flex;gap:16px;flex-wrap:wrap;padding:8px 0 0}
.card{flex:1;min-width:200px;background:var(--parchment-warm);border:1px solid var(--rule);padding:18px}
.card .n{font-size:2rem;font-weight:700}
.card .l{color:var(--ink-faint);font-size:0.9rem;margin-top:2px}
table{width:100%;border-collapse:collapse;font-size:0.92rem;margin-top:8px}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--rule-light);vertical-align:top}
th{font-family:"JetBrains Mono",monospace;text-transform:uppercase;font-size:0.62rem;letter-spacing:0.12em;color:var(--ink-faint);font-weight:600}
td.num{font-variant-numeric:tabular-nums}
.dim{color:var(--ink-soft);word-break:break-all}
.g{display:inline-block;min-width:22px;text-align:center;border-radius:4px;color:#fff;font-weight:700;padding:1px 7px;font-family:"JetBrains Mono",monospace;font-size:0.78rem}
.note{color:var(--ink-soft);font-size:0.95rem}
.legend{display:flex;gap:16px;flex-wrap:wrap;margin:12px 0 4px;font-size:0.85rem;color:var(--ink-soft);align-items:center}
.legend span span.g{margin-right:6px}
.filters{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0 10px}
.filters button{font-family:"JetBrains Mono",monospace;font-size:0.7rem;text-transform:uppercase;letter-spacing:0.1em;border:1px solid var(--rule);background:var(--parchment-warm);color:var(--ink);padding:5px 13px;cursor:pointer}
.filters button.active{background:var(--ink);color:var(--parchment);border-color:var(--ink)}
.tablebox{max-height:520px;overflow:auto;border:1px solid var(--rule)}
.tablebox table{margin:0}
.tablebox td,.tablebox th{white-space:nowrap}
.tablebox thead th{position:sticky;top:0;background:var(--parchment-deep)}
footer{color:var(--ink-faint);font-size:0.85rem;padding:36px 0;border-top:1px solid var(--rule);margin-top:36px}
footer a{color:var(--burgundy)}
@media(max-width:760px){.cols{grid-template-columns:1fr}.hero .big{font-size:4rem}header.top h1{font-size:1.8rem}}
</style>
</head>
<body>
<div class="wrap">

<header class="top">
<p class="eyebrow">An open benchmark, built on the Vouch Protocol</p>
<h1>Agent Trust Index</h1>
<p class="lede">The AI agents running in the world today take real actions. The Index measures a simple thing for each one: can it prove who it is, and can anyone be held accountable for what it does?</p>
</header>

<section class="hero">
<div class="big">__PCT_CANNOT__%</div>
<div class="sub">of AI agents we checked do not publish an identity anyone can verify</div>
<div class="src">__TOTAL__ unique agents from the public Model Context Protocol registry, checked __GENERATED__.</div>
</section>

<div class="cta">
<h2>Most agents are anonymous. Yours does not have to be.</h2>
<p>Give your agent a verifiable identity in one command. It is free and open source, and you keep control of your own keys.</p>
<p><code>pip install vouch-protocol</code></p>
<p><a href="https://github.com/vouch-protocol/vouch">github.com/vouch-protocol/vouch</a></p>
</div>

<section class="section">
<h2>Identity is the floor. Accountability is the point.</h2>
<p class="note">Knowing which agent acted is only the start. The harder questions are who authorized it, whether it is still behaving, and whether it can be stopped. A bare identity does not answer those. The Vouch Protocol does, and this Index will grow to measure all of it.</p>
<div class="cols">
<div class="col"><h3>Who authorized it</h3><p>A delegation chain shows who gave the agent its authority, on whose behalf, and within what limits, all verifiable.</p></div>
<div class="col"><h3>Is it still trustworthy</h3><p>Continuous trust means an agent has to keep proving itself, not get trusted once and forever.</p></div>
<div class="col"><h3>Can it be stopped</h3><p>Revocation lets you pull an agent's authority the moment it goes wrong, and anyone can check the status.</p></div>
</div>
</section>

<section class="section">
<div class="stats">
<div class="card"><div class="n">__TOTAL__</div><div class="l">unique agents checked</div></div>
<div class="card"><div class="n">__WITH_DID__</div><div class="l">can prove who they are (__PCT_VERIF__%)</div></div>
<div class="card"><div class="n">__GRADE_A__</div><div class="l">fully verifiable (grade A)</div></div>
</div>
</section>

<section class="section">
<h2>Where the ecosystem stands, property by property</h2>
<p class="note">Some trust properties an agent can publish, so we can measure them. Others, like who authorized an agent and whether its trust is continuously renewed, only show up when the agent presents a credential while it works, so a static scan cannot count them. We report only what we measured, and we do not put a number on what we cannot see.</p>
<table>
<thead><tr><th>Trust property</th><th>Agents with it</th><th>Share</th></tr></thead>
<tbody>
<tr><td>Can prove who they are (resolvable did:web identity)</td><td class="num">__WITH_DID__</td><td class="num">__PCT_DID__%</td></tr>
<tr><td>Agent card references a key or signature</td><td class="num">__CARD_COUNT__</td><td class="num">__PCT_CARD__%</td></tr>
<tr><td>Post-quantum ready (an ML-DSA key)</td><td class="num">__PQ_COUNT__</td><td class="num">__PCT_PQ__%</td></tr>
<tr><td>Publishes a service endpoint (revocation, MCP, A2A)</td><td class="num">__REV_COUNT__</td><td class="num">__PCT_REV__%</td></tr>
<tr><td>Delegation provenance (who authorized it)</td><td class="dim">not measured</td><td class="dim">a runtime property a static scan cannot see</td></tr>
<tr><td>Continuous trust (renewed, not trusted once)</td><td class="dim">not measured</td><td class="dim">a runtime property a static scan cannot see</td></tr>
</tbody>
</table>
</section>

<section class="section">
<h2>Agents that can prove who they are</h2>
<p class="note">Everyone else scores F: no resolvable identity at all. A verifiable agent stands out because almost none have one. The grade is the Trust Score band.</p>
<div class="legend">
<span><span class="g" style="background:#2f7d4f">A</span>90 to 100, full verifiable identity</span>
<span><span class="g" style="background:#3fa05f">B</span>75 to 89</span>
<span><span class="g" style="background:#9a7d1f">C</span>60 to 74, an identity but no usable key</span>
<span><span class="g" style="background:#b56b28">D</span>40 to 59</span>
<span><span class="g" style="background:#9b3b44">F</span>below 40, cannot prove who it is</span>
</div>
<div class="filters">
<button class="active" data-f="all">All</button>
<button data-f="A">A only</button>
<button data-f="C">C only</button>
</div>
<div class="tablebox">
<table>
<thead><tr><th>Grade</th><th>Score</th><th>Agent</th><th>Domain</th><th>What they use</th></tr></thead>
<tbody>
__ROWS__
</tbody>
</table>
</div>
<script>
(function(){
 var btns=document.querySelectorAll('.filters button');
 var rows=document.querySelectorAll('.tablebox tbody tr');
 btns.forEach(function(b){b.addEventListener('click',function(){
   btns.forEach(function(x){x.classList.remove('active')});
   b.classList.add('active');
   var f=b.getAttribute('data-f');
   rows.forEach(function(r){r.style.display=(f==='all'||r.getAttribute('data-grade')===f)?'':'none';});
 });});
})();
</script>
</section>

<section class="section">
<h2>How this was measured</h2>
<p class="note">We scan the public Model Context Protocol registry, take each agent's own domain, and check whether it publishes a resolvable identity with a usable key. Today we check one signal, a resolvable did:web identity, so this number is a floor on the gap and real adoption may be slightly higher. The full method is open. A high score means an agent can prove who it is, not that it is good or safe.</p>
</section>

<footer>
Data from the public Model Context Protocol registry, dedicated to the public domain under CC0. The Agent Trust Index is an open project built on the Vouch Protocol. The number moves as agents adopt verifiable identity.
</footer>

</div>
</body>
</html>
"""

    out = (
        template.replace("__PCT_CANNOT__", f"{pct_cannot:.1f}")
        .replace("__PCT_VERIF__", f"{pct_verif:.2f}")
        .replace("__TOTAL__", f"{total:,}")
        .replace("__WITH_DID__", f"{with_did}")
        .replace("__GRADE_A__", f"{grade_a}")
        .replace("__GENERATED__", generated)
        .replace("__PCT_DID__", f"{pct_did:.2f}")
        .replace("__CARD_COUNT__", f"{card_count}")
        .replace("__PCT_CARD__", f"{pct_card:.2f}")
        .replace("__PQ_COUNT__", f"{pq_count}")
        .replace("__PCT_PQ__", f"{pct_pq:.2f}")
        .replace("__REV_COUNT__", f"{rev_count}")
        .replace("__PCT_REV__", f"{pct_rev:.2f}")
        .replace("__ROWS__", rows_html)
    )
    (SITE / "index.html").write_text(out)

    print(f"Built site/index.html ({total:,} agents, {with_did} verifiable, {pct_cannot:.1f}% cannot prove identity)")
    print(f"Listed {len(verifiable)} verifiable agents with a 'what they use' column.")


if __name__ == "__main__":
    main()
