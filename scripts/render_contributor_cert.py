#!/usr/bin/env python3
"""Render a static Vouch Verified Contributor certificate page.

Matches the live vouch-protocol.com/v/ certificate design (parchment theme,
burgundy seal, ruled sections). A right-side icon rail lets the contributor
share to WhatsApp, X, LinkedIn, and Instagram. The print view is a compact,
single-page, framed certificate. Intended for /c/<login>/<pr>/.
"""

import argparse
import html
import json
import os
from datetime import datetime
from urllib.parse import quote

ISSUES_URL = "https://github.com/vouch-protocol/vouch/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22"

# Social handles. Fill INSTAGRAM_URL when the account exists.
X_HANDLE = "@Vouch_Protocol"
LINKEDIN_URL = "https://www.linkedin.com/company/vouch-protocol-ai/"
INSTAGRAM_URL = ""  # e.g. "https://instagram.com/vouch_protocol"

ICON_WHATSAPP = (
    '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M17.5 14.4c-.3-.1-1.7-.9'
    '-2-1-.3-.1-.5-.1-.6.1-.2.3-.7.9-.9 1.1-.2.2-.3.2-.6.1-1.5-.8-2.5-1.4-3.5-3.1-.3-.5.3-.5.8-1.5.1-.2'
    '0-.4 0-.5-.1-.1-.7-1.6-.9-2.2-.2-.6-.5-.5-.7-.5h-.5c-.2 0-.5.1-.8.4-.3.3-1 1-1 2.4 0 1.5 1.1 2.9 '
    '1.2 3.1.2.2 2.1 3.3 5.2 4.6 2.9 1.1 2.9.8 3.4.7.5 0 1.7-.7 1.9-1.4.2-.7.2-1.2.2-1.3-.1-.2-.3-.3-.6'
    '-.4zM12 2C6.5 2 2 6.5 2 12c0 1.8.5 3.5 1.3 5L2 22l5.1-1.3c1.4.8 3.1 1.2 4.9 1.2 5.5 0 10-4.5 10-10'
    'S17.5 2 12 2zm0 18.2c-1.6 0-3.1-.4-4.4-1.2l-.3-.2-3 .8.8-2.9-.2-.3C4 15.1 3.5 13.6 3.5 12 3.5 7.3 '
    '7.3 3.5 12 3.5 16.7 3.5 20.5 7.3 20.5 12S16.7 20.2 12 20.2z"/></svg>'
)
ICON_X = (
    '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M18.244 2.25h3.308l-7.227 '
    '8.26 8.502 11.24h-6.66l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 '
    '17.52h1.833L7.084 4.126H5.117z"/></svg>'
)
ICON_LINKEDIN = (
    '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M20.45 20.45h-3.56v-5.57c0'
    '-1.33-.02-3.04-1.85-3.04-1.85 0-2.13 1.45-2.13 2.94v5.67H9.35V9h3.41v1.56h.05c.48-.9 1.64-1.85 3.37'
    '-1.85 3.6 0 4.27 2.37 4.27 5.45v6.29zM5.34 7.43a2.06 2.06 0 1 1 0-4.13 2.06 2.06 0 0 1 0 4.13zM7.12 '
    '20.45H3.56V9h3.56v11.45zM22.22 0H1.77C.79 0 0 .77 0 1.72v20.56C0 23.23.79 24 1.77 24h20.45c.98 0 '
    '1.78-.77 1.78-1.72V1.72C24 .77 23.2 0 22.22 0z"/></svg>'
)
ICON_INSTAGRAM = (
    '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 2.2c3.2 0 3.6 0 4.9.1 '
    '1.2.1 1.8.2 2.2.4.6.2 1 .5 1.4.9.4.4.7.8.9 1.4.2.4.3 1 .4 2.2.1 1.3.1 1.6.1 4.8s0 3.5-.1 4.8c-.1 '
    '1.2-.2 1.8-.4 2.2-.2.6-.5 1-.9 1.4-.4.4-.8.7-1.4.9-.4.2-1 .3-2.2.4-1.3.1-1.6.1-4.9.1s-3.6 0-4.9-.1'
    'c-1.2-.1-1.8-.2-2.2-.4-.6-.2-1-.5-1.4-.9-.4-.4-.7-.8-.9-1.4-.2-.4-.3-1-.4-2.2C2.2 15.5 2.2 15.2 2.2 '
    '12s0-3.5.1-4.8c.1-1.2.2-1.8.4-2.2.2-.6.5-1 .9-1.4.4-.4.8-.7 1.4-.9.4-.2 1-.3 2.2-.4C8.4 2.2 8.8 2.2 '
    '12 2.2zm0 1.8c-3.1 0-3.5 0-4.7.1-1.1.1-1.7.2-2.1.4-.5.2-.9.4-1.3.8-.4.4-.6.8-.8 1.3-.2.4-.3 1-.4 '
    '2.1C2.6 10 2.6 10.3 2.6 12s0 2 .1 3.2c.1 1.1.2 1.7.4 2.1.2.5.4.9.8 1.3.4.4.8.6 1.3.8.4.2 1 .3 2.1.4 '
    '1.2.1 1.6.1 4.7.1s3.5 0 4.7-.1c1.1-.1 1.7-.2 2.1-.4.5-.2.9-.4 1.3-.8.4-.4.6-.8.8-1.3.2-.4.3-1 .4-2.1'
    '.1-1.2.1-1.6.1-3.2s0-2-.1-3.2c-.1-1.1-.2-1.7-.4-2.1-.2-.5-.4-.9-.8-1.3-.4-.4-.8-.6-1.3-.8-.4-.2-1-.3'
    '-2.1-.4-1.2-.1-1.6-.1-4.7-.1zm0 3a5 5 0 1 1 0 10 5 5 0 0 1 0-10zm0 8.2a3.2 3.2 0 1 0 0-6.4 3.2 3.2 0 '
    '0 0 0 6.4zm6.4-8.4a1.2 1.2 0 1 1-2.4 0 1.2 1.2 0 0 1 2.4 0z"/></svg>'
)
ICON_DOWNLOAD = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">'
    '<path d="M12 3v12m0 0l-4-4m4 4l4-4M4 21h16"/></svg>'
)
ICON_SHARE = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" '
    'stroke-linejoin="round" aria-hidden="true"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/>'
    '<circle cx="18" cy="19" r="3"/><path d="M8.6 13.5l6.8 4M15.4 6.5l-6.8 4"/></svg>'
)
ICON_BLUESKY = (
    '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M5.06 3.51C7.6 5.42 10.33 '
    '9.28 11.33 11.36c.13.28.4.28.53 0C12.87 9.28 15.6 5.42 18.14 3.51c1.83-1.37 4.8-2.43 4.8.96 0 .68'
    '-.39 5.7-.62 6.52-.79 2.83-3.67 3.55-6.24 3.11 4.49.77 5.63 3.3 3.16 5.83-4.69 4.8-6.74-1.2-7.27'
    '-2.74-.1-.28-.14-.41-.14-.3 0-.11-.05.02-.14.3-.53 1.54-2.58 7.54-7.27 2.74-2.47-2.53-1.33-5.06 '
    '3.16-5.83-2.57.44-5.45-.28-6.24-3.11C.66 10.17.27 5.15.27 4.47.27 1.08 3.23 2.14 5.06 3.51z"/></svg>'
)


def fmt_date(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).strftime("%-d %b %Y")
    except Exception:
        return iso or ""


def fmt_time(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).strftime("%H:%M UTC")
    except Exception:
        return ""


def esc(s: object) -> str:
    return html.escape(str(s)) if s is not None else ""


def section(eyebrow: str, body: str, cls: str = "") -> str:
    return f"""  <div class="section{(" " + cls) if cls else ""}">
    <div class="section-head"><div class="rule-line"></div><span class="eyebrow">{esc(eyebrow)}</span><div class="rule-line"></div></div>
    <div class="section-body">
{body}
    </div>
  </div>"""


def render(cred: dict, login: str, pr: str, title: str = "") -> str:
    subject = cred.get("credentialSubject", {})
    intent = subject.get("intent", {})
    chain = subject.get("delegationChain") or []
    root = chain[0].get("issuer", "") if chain else ""
    issuer = cred.get("issuer", "")
    proof_value = cred.get("proof", {}).get("proofValue", "")
    issued = fmt_date(cred.get("validFrom", ""))
    issued_time = fmt_time(cred.get("validFrom", ""))
    repo = intent.get("repository", "vouch-protocol/vouch")
    pr_url = f"https://github.com/{repo}/pull/{pr}" if pr else ""
    cert_url = f"https://vouch-protocol.com/c/{login}/{pr}".rstrip("/")
    work = title or "a contribution"

    pr_html = (
        f'<a href="{esc(pr_url)}" target="_blank" rel="noopener noreferrer">Pull Request #{esc(pr)}</a>'
        if pr_url
        else "Contribution merged"
    )
    sections = [
        section(
            "Contribution",
            f'      <div class="mono-text">{pr_html}</div>\n'
            f'      <div class="signer-caption">Merged into {esc(repo)}</div>',
        ),
        section(
            "Issued by",
            f'      <div class="mono-text">{esc(issuer)}</div>\n'
            f'      <div class="signer-caption">Vouch Contributor Authority</div>',
        ),
    ]
    if root:
        sections.append(section("Chained to root", f'      <div class="mono-text dim">{esc(root)}</div>'))
    sections.append(
        section("Cryptosuite", '      <div class="mono-text dim">eddsa-jcs-2022 · Ed25519 over RFC 8785 JCS</div>')
    )
    sections.append(section("Signature", f'      <div class="mono-text dim">{esc(proof_value)}</div>'))
    terminal = (
        '      <div class="terminal"><span class="comment"># Fetch the issuer DID document</span>\n'
        '<span class="prompt">$</span> curl https://vouch-protocol.com/contributors/did.json\n\n'
        '<span class="comment"># Verify the credential proof against it</span>\n'
        '<span class="prompt">&gt;&gt;&gt;</span> Verifier.verify_credential(cred, public_key)  # True</div>'
    )
    sections.append(section("Verify locally", terminal, cls="no-print"))
    sections_html = "\n  \n".join(sections)

    cert_title = esc(title) if title else "@" + esc(login)
    byline = ("@" + esc(login) + " · " + esc(repo)) if title else "Vouch Verified Contributor · " + esc(repo)

    # Share text, tailored per platform, with a CTA into the issues.
    x_text = (
        f'Just earned my Vouch Verified Contributor certificate for "{work}". '
        f"Vouch {X_HANDLE} is the open standard for AI agent identity and accountability, and open source. "
        "Pick up a good first issue and build with us: " + ISSUES_URL
    )
    wa_text = (
        f'I just earned a Vouch Verified Contributor certificate for "{work}". '
        "Vouch is the open standard for AI agent identity and accountability, and open source. "
        "Build with us: " + ISSUES_URL + " " + cert_url
    )
    linkedin_text = (
        "I am now a Vouch Verified Contributor.\n\n"
        f'My contribution to Vouch Protocol ("{work}") is now cryptographically certified: '
        "the certificate is signed by Vouch and verifiable by anyone.\n\n"
        "Vouch is the open standard for AI agent identity and accountability. If you build or secure "
        "AI agents, it gives them a cryptographic identity, verifiable accountability, and a heartbeat "
        "protocol for continuous trust.\n\n"
        "The project is open source and welcoming contributors. Good first issues are ready to pick up:\n"
        f"{ISSUES_URL}\n\n"
        f"Vouch Protocol on LinkedIn: {LINKEDIN_URL}\n\n"
        f"My certificate: {cert_url}\n\n"
        "#AIagents #OpenSource #Cryptography #Vouch"
    )
    bsky_text = (
        f'Just earned my Vouch Verified Contributor certificate for "{work}". '
        "Vouch is the open standard for AI agent identity and accountability, and open source. "
        "Pick up a good first issue and build with us: " + ISSUES_URL + " " + cert_url
    )
    x_intent = f"https://twitter.com/intent/tweet?text={quote(x_text)}&url={quote(cert_url)}"
    wa_intent = f"https://wa.me/?text={quote(wa_text)}"
    bsky_intent = f"https://bsky.app/intent/compose?text={quote(bsky_text)}"
    linkedin_share = f"https://www.linkedin.com/sharing/share-offsite/?url={quote(cert_url)}"
    linkedin_js = json.dumps(linkedin_text)
    linkedin_url_js = json.dumps(linkedin_share)
    share_text_js = json.dumps(
        f'I earned a Vouch Verified Contributor certificate for "{work}". '
        "Vouch is the open standard for AI agent identity and accountability. Build with us: " + ISSUES_URL
    )
    cert_url_js = json.dumps(cert_url)

    insta_btn = (
        f'<a class="srx" href="{esc(INSTAGRAM_URL)}" target="_blank" rel="noopener noreferrer" title="Vouch on Instagram">{ICON_INSTAGRAM}</a>'
        if INSTAGRAM_URL
        else f'<span class="srx disabled" title="Instagram coming soon">{ICON_INSTAGRAM}</span>'
    )
    rail = f"""<div class="share-rail no-print" aria-label="Share">
  <button class="srx" type="button" onclick="nativeShare()" title="Share">{ICON_SHARE}</button>
  <a class="srx" href="{esc(wa_intent)}" target="_blank" rel="noopener noreferrer" title="Share on WhatsApp">{ICON_WHATSAPP}</a>
  <a class="srx" href="{esc(x_intent)}" target="_blank" rel="noopener noreferrer" title="Share on X">{ICON_X}</a>
  <a class="srx" href="{esc(bsky_intent)}" target="_blank" rel="noopener noreferrer" title="Share on Bluesky">{ICON_BLUESKY}</a>
  <button class="srx" type="button" onclick="shareLinkedIn()" title="Share on LinkedIn">{ICON_LINKEDIN}</button>
  {insta_btn}
  <button class="srx" type="button" onclick="window.print()" title="Download">{ICON_DOWNLOAD}</button>
</div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Vouch Verified Contributor · @{esc(login)}</title>
<meta property="og:title" content="Vouch Verified Contributor · @{esc(login)}">
<meta property="og:description" content="A cryptographically signed certificate for a contribution to Vouch Protocol, the open standard for AI agent identity and accountability.">
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
.seal-wrap {{ display: flex; justify-content: center; margin-bottom: 40px; }}
.seal {{ width: 220px; height: 220px; border: 2px solid var(--burgundy); outline: 2px solid var(--burgundy); outline-offset: 6px; background: var(--parchment); display: flex; flex-direction: column; align-items: center; justify-content: center; text-align: center; padding: 16px; }}
.seal img {{ width: 48px; height: 48px; margin-bottom: 12px; }}
.seal .check {{ color: var(--burgundy); font-size: 1.6rem; line-height: 1; margin-bottom: 6px; font-weight: 600; }}
.seal .seal-line {{ font-family: "JetBrains Mono", monospace; font-size: 0.7rem; letter-spacing: 0.16em; text-transform: uppercase; color: var(--burgundy); margin: 2px 0; }}
.seal .seal-line.muted {{ color: var(--ink-faint); letter-spacing: 0.1em; }}
h1.title {{ text-align: center; font-family: "Source Serif 4", Georgia, serif; font-weight: 600; font-size: 1.5rem; line-height: 1.3; margin: 0 0 12px; letter-spacing: -0.01em; }}
.byline {{ text-align: center; color: var(--ink-soft); margin: 0 0 48px; font-style: italic; }}
.section {{ margin: 36px 0; }}
.section-head {{ display: flex; align-items: center; gap: 12px; margin-bottom: 14px; }}
.section-head .rule-line {{ flex: 1; height: 1px; background: var(--rule); }}
.section-body {{ text-align: center; }}
.mono-text {{ font-family: "JetBrains Mono", monospace; font-size: 0.9rem; word-break: break-all; color: var(--ink); }}
.mono-text.dim {{ color: var(--ink-soft); font-size: 0.85rem; }}
.signer-caption {{ color: var(--ink-faint); font-style: italic; font-size: 0.9rem; margin-top: 6px; }}
.section-body a {{ color: var(--burgundy); text-decoration: none; border-bottom: 1px solid var(--burgundy); }}
.section-body a:hover {{ color: var(--burgundy-dark); border-bottom-color: var(--burgundy-dark); }}
.terminal {{ font-family: "JetBrains Mono", monospace; font-size: 0.85rem; background: var(--code-bg); color: var(--code-fg); padding: 16px 18px; margin: 12px auto; text-align: left; overflow-x: auto; max-width: 540px; white-space: pre; }}
.terminal .prompt {{ color: #80c08a; user-select: none; }}
.terminal .comment {{ color: #91a4b8; font-style: italic; }}
.share-rail {{ position: fixed; right: 22px; top: 32%; transform: translateY(-50%); display: flex; flex-direction: column; gap: 12px; z-index: 20; }}
.srx {{ display: inline-flex; align-items: center; justify-content: center; width: 42px; height: 42px; border: 1px solid var(--burgundy); background: var(--parchment); color: var(--burgundy); cursor: pointer; text-decoration: none; padding: 0; }}
.srx:hover {{ background: var(--burgundy); color: var(--parchment); }}
.srx.disabled {{ opacity: 0.3; pointer-events: none; }}
.srx svg {{ width: 19px; height: 19px; }}
.about {{ margin-top: 56px; padding-top: 28px; border-top: 1px solid var(--rule-light); text-align: center; }}
.about p {{ color: var(--ink-soft); margin: 14px auto; max-width: 600px; }}
.about a {{ color: var(--burgundy); text-decoration: none; border-bottom: 1px solid var(--burgundy); }}
.about a:hover {{ color: var(--burgundy-dark); border-bottom-color: var(--burgundy-dark); }}
.about .cta {{ font-family: "JetBrains Mono", monospace; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.12em; margin-top: 22px; }}
.footer-cta {{ margin-top: 36px; text-align: center; font-style: italic; color: var(--ink-soft); line-height: 1.9; }}
.footer-cta a {{ color: var(--burgundy); text-decoration: none; border-bottom: 1px solid var(--burgundy); }}
.pagefoot {{ margin-top: 40px; padding-top: 24px; border-top: 1px solid var(--rule-light); text-align: center; color: var(--ink-faint); font-size: 0.85rem; }}
.pagefoot a {{ color: var(--ink-faint); text-decoration: none; border-bottom: 1px dotted var(--rule); }}
@media (max-width: 980px) {{ .share-rail {{ position: static; transform: none; flex-direction: row; justify-content: center; margin: 0 0 40px; }} }}
@media print {{
  .share-rail, .about, .footer-cta, .no-print {{ display: none !important; }}
  @page {{ margin: 1cm; }}
  body {{ padding: 0; font-size: 12.5px; min-height: 0; -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
  .frame {{ border: 2px double var(--burgundy); padding: 44px 48px 30px; }}
  .seal-wrap {{ margin-bottom: 24px; }}
  .seal {{ width: 152px; height: 152px; padding: 12px; outline-offset: 5px; }}
  .seal img {{ width: 34px; height: 34px; margin-bottom: 8px; }}
  .seal .check {{ font-size: 1.3rem; margin-bottom: 4px; }}
  h1.title {{ font-size: 1.2rem; margin-bottom: 6px; }}
  .byline {{ margin-bottom: 26px; }}
  .section {{ margin: 16px 0; }}
  .section-head {{ margin-bottom: 7px; }}
  .pagefoot {{ margin-top: 26px; padding-top: 14px; border-top: none; }}
}}
</style>
</head>
<body>
{rail}
<div class="frame">
<section>
  <div class="seal-wrap"><div class="seal">
    <img src="https://vouch-protocol.com/apple-touch-icon.png" alt="Vouch">
    <div class="check">✓</div>
    <div class="seal-line">Verified Contributor</div>
    <div class="seal-line muted">{esc(issued)}</div>
    <div class="seal-line muted">{esc(issued_time)}</div>
  </div></div>
  <h1 class="title">{cert_title}</h1>
  <p class="byline">{byline}</p>

{sections_html}

  <div class="about">
    <div class="section-head"><div class="rule-line"></div><span class="eyebrow">An Open Standard</span><div class="rule-line"></div></div>
    <p>Vouch gives AI agents a cryptographic identity, verifiable accountability, and a heartbeat
    protocol for continuous trust, so anyone can prove who acted, under whose authority, and that the
    agent is still trustworthy.</p>
    <p>The <a href="https://vouch-protocol.com/agent-trust-index" target="_blank" rel="noopener noreferrer">Agent Trust Index</a> grades how verifiable and accountable an AI agent is, an open, public scorecard.</p>
    <p class="cta"><a href="https://vouch-protocol.com" target="_blank" rel="noopener noreferrer">Secure your AI agent with Vouch</a></p>
  </div>

  <div class="footer-cta">
    See everyone on the <a href="https://vouch-protocol.com/contributors" target="_blank" rel="noopener noreferrer">Vouch contributors</a> page.<br>
    <a href="{esc(ISSUES_URL)}" target="_blank" rel="noopener noreferrer">Earn yours: pick up a good first issue</a>.
  </div>
</section>
<div class="pagefoot"><a href="https://vouch-protocol.com/" target="_blank" rel="noopener noreferrer">vouch-protocol.com</a></div>
</div>
<script>
const LINKEDIN_POST = {linkedin_js};
const LINKEDIN_URL = {linkedin_url_js};
const SHARE_TEXT = {share_text_js};
const CERT_URL = {cert_url_js};
function openLinkedIn() {{ window.open(LINKEDIN_URL, "_blank", "noopener"); }}
function nativeShare() {{
  if (navigator.share) {{
    navigator.share({{ title: document.title, text: SHARE_TEXT, url: CERT_URL }}).catch(function () {{}});
  }} else if (navigator.clipboard) {{
    navigator.clipboard.writeText(SHARE_TEXT + " " + CERT_URL).then(function () {{
      alert("Copied. Paste it anywhere.");
    }});
  }} else {{
    window.prompt("Copy this to share:", SHARE_TEXT + " " + CERT_URL);
  }}
}}
function shareLinkedIn() {{
  if (navigator.share) {{
    navigator.share({{ title: document.title, text: LINKEDIN_POST, url: CERT_URL }}).catch(openLinkedIn);
    return;
  }}
  if (navigator.clipboard) {{
    navigator.clipboard.writeText(LINKEDIN_POST).then(function () {{
      openLinkedIn();
      alert("Your LinkedIn post is copied. Paste it into the box that opens.");
    }}).catch(openLinkedIn);
    return;
  }}
  openLinkedIn();
}}
</script>
</body>
</html>
"""


def main() -> int:
    ap = argparse.ArgumentParser(description="Render a contributor certificate page")
    ap.add_argument("--credential", required=True, help="Path to the contributor credential JSON")
    ap.add_argument("--login", required=True, help="GitHub handle")
    ap.add_argument("--pr", default="", help="Pull request number")
    ap.add_argument("--title", default="", help="Pull request title")
    ap.add_argument("--out", required=True, help="Output HTML path")
    args = ap.parse_args()

    with open(args.credential, encoding="utf-8") as handle:
        cred = json.load(handle)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as handle:
        handle.write(render(cred, args.login, args.pr, args.title))
    print(f"Wrote certificate for @{args.login} to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
