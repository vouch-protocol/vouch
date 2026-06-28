#!/usr/bin/env python3
"""Render a static Vouch Verified Integration certificate page from a credential.

Matches the contributor certificate design (parchment theme, Vouch Verified wax
seal, ruled sections), but recognizes a reference integration rather than a
merged pull request. The certificate is backed by a signed Verifiable
Credential issued by the Adopter Authority and is verifiable by anyone against
the published DID document. Intended for /i/<slug>/.
"""

import argparse
import html
import json
import os
from datetime import datetime

ADOPTER_DID_URL = "https://vouch-protocol.com/adopters/did.json"


def fmt_date(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).strftime("%-d %b %Y")
    except Exception:
        return iso or ""


def esc(s: object) -> str:
    return html.escape(str(s)) if s is not None else ""


def section(eyebrow: str, body: str, cls: str = "") -> str:
    return f"""  <div class="section{(" " + cls) if cls else ""}">
    <div class="section-head"><div class="rule-line"></div><span class="eyebrow">{esc(eyebrow)}</span><div class="rule-line"></div></div>
    <div class="section-body">
{body}
    </div>
  </div>"""


def render(cred: dict, slug: str) -> str:
    subject = cred.get("credentialSubject", {})
    intent = subject.get("intent", {})
    chain = subject.get("delegationChain") or []
    root = chain[0].get("issuer", "") if chain else ""
    issuer = cred.get("issuer", "")
    proof = cred.get("proof", {})
    proof_value = proof.get("proofValue", "")
    cryptosuite = proof.get("cryptosuite", "eddsa-jcs-2022")
    issued = fmt_date(cred.get("validFrom", ""))

    name = intent.get("name", slug)
    focus = intent.get("integrates", "")
    by = intent.get("by", "")
    live_surface = intent.get("liveSurface", "")
    discussion = intent.get("discussion", "")
    cert_url = f"https://vouch-protocol.com/i/{slug}/"

    by_html = ""
    if by:
        by_html = (
            f' &middot; by <a href="https://github.com/{esc(by)}" target="_blank" '
            f'rel="noopener noreferrer">@{esc(by)}</a>'
        )

    sections = [
        section(
            "Integration",
            f'      <div class="mono-text">{esc(focus)}</div>\n'
            '      <div class="signer-caption">The first system to integrate this layer of Vouch Protocol</div>',
        ),
        section(
            "Issued by",
            f'      <div class="mono-text">{esc(issuer)}</div>\n'
            '      <div class="signer-caption">Vouch Adopter Authority</div>',
        ),
    ]
    if root:
        sections.append(
            section("Chained to root", f'      <div class="mono-text dim">{esc(root)}</div>')
        )
    sections.append(
        section(
            "Cryptosuite",
            f'      <div class="mono-text dim">{esc(cryptosuite)} &middot; Ed25519 over RFC 8785 JCS</div>',
        )
    )
    sections.append(
        section("Signature", f'      <div class="mono-text dim">{esc(proof_value)}</div>')
    )
    if live_surface:
        sections.append(
            section(
                "Live surface",
                f'      <a class="mono-text" href="{esc(live_surface)}" target="_blank" '
                f'rel="noopener noreferrer">{esc(live_surface.replace("https://", ""))}</a>',
            )
        )
    terminal = (
        '      <div class="terminal"><span class="comment"># Fetch the issuer DID document</span>\n'
        f'<span class="prompt">$</span> curl {ADOPTER_DID_URL}\n\n'
        '<span class="comment"># Verify the credential proof against it</span>\n'
        '<span class="prompt">&gt;&gt;&gt;</span> Verifier.verify_credential(cred, public_key)  # True</div>'
    )
    sections.append(section("Verify locally", terminal, cls="no-print"))
    sections_html = "\n  \n".join(sections)

    discussion_html = ""
    if discussion:
        discussion_html = (
            f"    <p>See the integration record on "
            f'<a href="{esc(discussion)}" target="_blank" rel="noopener noreferrer">GitHub</a>.</p>\n'
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Vouch Verified Integration &middot; {esc(name)}</title>
<meta property="og:title" content="Vouch Verified Integration &middot; {esc(name)}">
<meta property="og:description" content="A cryptographically signed certificate for a reference integration of Vouch Protocol, the open standard for AI agent identity and accountability.">
<meta property="og:image" content="https://vouch-protocol.com/android-chrome-512x512.png">
<meta property="og:url" content="{esc(cert_url)}">
<meta name="twitter:card" content="summary">
<link rel="icon" type="image/png" sizes="32x32" href="https://vouch-protocol.com/favicon-32x32.png">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Source+Serif+4:ital,wght@0,400;0,600;1,400&family=JetBrains+Mono&display=swap" rel="stylesheet">
<style>
:root {{ --parchment:#FAF7EE; --parchment-warm:#F2EBD9; --ink:#0F172A; --ink-soft:#334155; --ink-faint:#64748B; --burgundy:#7C2D3A; --burgundy-dark:#5C1F2C; --rule:#D9CFB6; --rule-light:#E8DFC9; --code-bg:#0F172A; --code-fg:#FAF7EE; }}
* {{ box-sizing: border-box; }}
html, body {{ margin: 0; padding: 0; }}
body {{ background: var(--parchment); color: var(--ink); font-family: "Source Serif 4", Georgia, serif; font-size: 17px; line-height: 1.6; padding: 64px 24px; min-height: 100vh; }}
.frame {{ max-width: 720px; margin: 0 auto; }}
.eyebrow {{ font-family: "JetBrains Mono", monospace; font-size: 0.7rem; letter-spacing: 0.18em; text-transform: uppercase; color: var(--ink-faint); }}
.seal-wrap {{ display: flex; justify-content: center; margin-bottom: 16px; }}
.seal-img {{ width: 200px; height: 200px; object-fit: contain; }}
.issued-line {{ text-align: center; font-family: "JetBrains Mono", monospace; font-size: 0.72rem; letter-spacing: 0.14em; text-transform: uppercase; color: var(--ink-faint); margin: 0 0 40px; }}
h1.title {{ text-align: center; font-weight: 600; font-size: 1.5rem; line-height: 1.3; margin: 0 0 12px; letter-spacing: -0.01em; }}
.byline {{ text-align: center; color: var(--ink-soft); margin: 0 0 48px; font-style: italic; }}
.byline a {{ color: var(--burgundy); text-decoration: none; }}
.byline a:hover {{ color: var(--burgundy-dark); text-decoration: underline; }}
.section {{ margin: 36px 0; }}
.section-head {{ display: flex; align-items: center; gap: 12px; margin-bottom: 14px; }}
.section-head .rule-line {{ flex: 1; height: 1px; background: var(--rule); }}
.section-body {{ text-align: center; }}
.mono-text {{ font-family: "JetBrains Mono", monospace; font-size: 0.9rem; word-break: break-word; color: var(--ink); }}
.mono-text.dim {{ color: var(--ink-soft); font-size: 0.85rem; }}
.signer-caption {{ color: var(--ink-faint); font-style: italic; font-size: 0.9rem; margin-top: 6px; }}
.section-body a {{ color: var(--burgundy); text-decoration: none; border-bottom: 1px solid var(--burgundy); }}
.section-body a:hover {{ color: var(--burgundy-dark); border-bottom-color: var(--burgundy-dark); }}
.terminal {{ font-family: "JetBrains Mono", monospace; font-size: 0.85rem; background: var(--code-bg); color: var(--code-fg); padding: 16px 18px; margin: 12px auto; text-align: left; overflow-x: auto; max-width: 560px; white-space: pre-wrap; }}
.terminal .prompt {{ color: #80c08a; user-select: none; }}
.terminal .comment {{ color: #91a4b8; font-style: italic; }}
.about {{ margin-top: 56px; padding-top: 28px; border-top: 1px solid var(--rule-light); text-align: center; }}
.about p {{ color: var(--ink-soft); margin: 14px auto; max-width: 600px; }}
.about a {{ color: var(--burgundy); text-decoration: none; border-bottom: 1px solid var(--burgundy); }}
.about .cta {{ font-family: "JetBrains Mono", monospace; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.12em; margin-top: 22px; }}
.actions {{ text-align: center; margin-top: 28px; }}
.actions button {{ font-family: "JetBrains Mono", monospace; font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.12em; border: 1px solid var(--burgundy); background: var(--parchment); color: var(--burgundy); padding: 9px 16px; cursor: pointer; }}
.actions button:hover {{ background: var(--burgundy); color: var(--parchment); }}
.pagefoot {{ margin-top: 40px; padding-top: 24px; border-top: 1px solid var(--rule-light); text-align: center; color: var(--ink-faint); font-size: 0.85rem; }}
.pagefoot a {{ color: var(--ink-faint); text-decoration: none; border-bottom: 1px dotted var(--rule); }}
@media print {{
  .about, .actions, .no-print {{ display: none !important; }}
  @page {{ margin: 0.8cm; }}
  body {{ padding: 0; font-size: 12.5px; min-height: 0; -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
  .frame {{ max-width: none; margin: 0; padding: 30px 56px 22px; border: 2px double var(--burgundy); }}
  .seal-img {{ width: 150px; height: 150px; }}
  .section {{ margin: 18px 0; }}
}}
</style>
</head>
<body>
<div class="frame">
<section>
  <div class="seal-wrap">
    <img class="seal-img" src="https://vouch-protocol.com/seal-verified.png" alt="Vouch Protocol Verified" />
  </div>
  <p class="issued-line">{esc(issued)} &middot; First Reference Integration</p>
  <h1 class="title">Vouch Verified Integration</h1>
  <p class="byline">{esc(name)}{by_html}</p>

{sections_html}

  <div class="about">
    <div class="section-head"><div class="rule-line"></div><span class="eyebrow">An Open Standard</span><div class="rule-line"></div></div>
    <p>Vouch gives AI agents a cryptographic identity, verifiable accountability, and a heartbeat
    protocol for continuous trust, so anyone can prove who acted, under whose authority, and that the
    agent is still trustworthy. The accountability layer adds commit-before-outcome evidence and an
    AccountabilityRecord a counterparty can recompute rather than trust.</p>
{discussion_html}    <p>See everyone building on the protocol on the <a href="https://vouch-protocol.com/adopters/" target="_blank" rel="noopener noreferrer">Vouch adopters</a> page.</p>
    <p class="cta"><a href="https://vouch-protocol.com" target="_blank" rel="noopener noreferrer">Build on Vouch</a></p>
  </div>

  <div class="actions no-print">
    <button type="button" onclick="window.print()">Download</button>
  </div>
</section>
<div class="pagefoot"><a href="https://vouch-protocol.com/" target="_blank" rel="noopener noreferrer">vouch-protocol.com</a></div>
</div>
</body>
</html>
"""


def main() -> int:
    ap = argparse.ArgumentParser(description="Render an adopter integration certificate page")
    ap.add_argument("--credential", required=True, help="Path to the adopter credential JSON")
    ap.add_argument("--slug", required=True, help="URL slug under /i/<slug>/")
    ap.add_argument("--out", required=True, help="Output HTML path")
    args = ap.parse_args()

    with open(args.credential, encoding="utf-8") as handle:
        cred = json.load(handle)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as handle:
        handle.write(render(cred, args.slug))
    print(f"Wrote certificate for {args.slug} to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
