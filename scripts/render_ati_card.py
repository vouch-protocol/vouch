#!/usr/bin/env python3
"""
Render the Agent Trust Index social card (1200x630 PNG).

Reads the headline numbers from the generated site data (ati-data.ts) and writes
a branded card to website/public/assets/ati-card.png. The weekly rescan workflow
runs this after regenerating the data, so the share image always matches the
current numbers. Used as the og:image / twitter:image for the explainer page.

Rasterizes with cairosvg (pure-pip; libcairo is present on GitHub runners).
"""

import json
import re
from pathlib import Path

import cairosvg

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "website" / "src" / "app" / "agent-trust-index" / "ati-data.ts"
OUT_SVG = ROOT / "website" / "public" / "assets" / "ati-card.svg"
OUT_PNG = ROOT / "website" / "public" / "assets" / "ati-card.png"


def load_summary() -> dict:
    text = DATA.read_text(encoding="utf-8")
    m = re.search(r"ATI_SUMMARY\s*=\s*(\{.*?\})\s*as const", text, re.S)
    if not m:
        raise SystemExit("Could not find ATI_SUMMARY in ati-data.ts")
    return json.loads(m.group(1))


def esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_svg(s: dict) -> str:
    pct = s["pctCannot"]
    total = f"{s['total']:,}"
    when = s.get("generated", "")
    verifiable = s.get("verifiable", 0)
    serif = "Georgia, 'Times New Roman', serif"
    mono = "'DejaVu Sans Mono', 'Courier New', monospace"
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
  <rect width="1200" height="630" fill="#FAF7EE"/>
  <rect x="0" y="0" width="14" height="630" fill="#7C2D3A"/>
  <text x="80" y="120" font-family="{mono}" font-size="26" letter-spacing="6" fill="#7C2D3A">THE AGENT TRUST INDEX</text>
  <text x="76" y="320" font-family="{serif}" font-size="200" font-weight="700" fill="#0F172A">{pct}%</text>
  <text x="80" y="404" font-family="{serif}" font-size="52" fill="#0F172A">of AI agents cannot prove who they are.</text>
  <text x="80" y="470" font-family="{serif}" font-size="34" fill="#334155" font-style="italic">Only {verifiable} of {total} public agents can.</text>
  <text x="80" y="566" font-family="{mono}" font-size="24" letter-spacing="2" fill="#64748B">AS OF {esc(when).upper()}  ·  PUBLIC MCP REGISTRY</text>
  <text x="1120" y="566" text-anchor="end" font-family="{mono}" font-size="26" letter-spacing="2" fill="#7C2D3A">VOUCH-PROTOCOL.COM</text>
</svg>"""


def main() -> None:
    s = load_summary()
    svg = build_svg(s)
    OUT_SVG.parent.mkdir(parents=True, exist_ok=True)
    OUT_SVG.write_text(svg, encoding="utf-8")
    cairosvg.svg2png(bytestring=svg.encode("utf-8"), write_to=str(OUT_PNG), output_width=1200, output_height=630)
    print(f"wrote {OUT_PNG} ({OUT_PNG.stat().st_size} bytes) for {s['pctCannot']}% / {s['total']} agents / {s.get('generated')}")


if __name__ == "__main__":
    main()
