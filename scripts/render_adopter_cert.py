#!/usr/bin/env python3
"""Render a static Vouch Verified Integration certificate page from a credential.

Matches the contributor certificate design (parchment theme, Vouch Verified wax
seal, ruled sections, right-side share rail, single-page print view), but
recognizes a reference integration rather than a merged pull request. The
certificate is backed by a signed Verifiable Credential issued by the Adopter
Authority and is verifiable by anyone against the published DID document.
Intended for /i/<slug>/.
"""

import argparse
import html
import json
import os
from datetime import datetime
from urllib.parse import quote

ADOPTERS_URL = "https://vouch-protocol.com/adopters/"
DISCUSSIONS_URL = "https://github.com/vouch-protocol/vouch/discussions"

# Social handles.
X_HANDLE = "@Vouch_Protocol"
BLUESKY_HANDLE = "@vouch-protocol.com"
LINKEDIN_URL = "https://www.linkedin.com/company/vouch-protocol-ai/"
INSTAGRAM_URL = "https://www.instagram.com/vouch.protocol/"

ICON_WHATSAPP = (
    '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">'
    '<path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347m-5.421 7.403h-.004a9.87 9.87 0 01-5.031-1.378l-.361-.214-3.741.982.998-3.648-.235-.374a9.86 9.86 0 01-1.51-5.26c.001-5.45 4.436-9.884 9.888-9.884 2.64 0 5.122 1.03 6.988 2.898a9.825 9.825 0 012.893 6.994c-.003 5.45-4.437 9.884-9.885 9.884m8.413-18.297A11.815 11.815 0 0012.05 0C5.495 0 .16 5.335.157 11.892c0 2.096.547 4.142 1.588 5.945L.057 24l6.305-1.654a11.882 11.882 0 005.683 1.448h.005c6.554 0 11.89-5.335 11.893-11.893a11.821 11.821 0 00-3.48-8.413Z"/></svg>'
)
ICON_X = (
    '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M18.244 2.25h3.308l-7.227 '
    "8.26 8.502 11.24h-6.66l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 "
    '17.52h1.833L7.084 4.126H5.117z"/></svg>'
)
ICON_LINKEDIN = (
    '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M20.45 20.45h-3.56v-5.57c0'
    "-1.33-.02-3.04-1.85-3.04-1.85 0-2.13 1.45-2.13 2.94v5.67H9.35V9h3.41v1.56h.05c.48-.9 1.64-1.85 3.37"
    "-1.85 3.6 0 4.27 2.37 4.27 5.45v6.29zM5.34 7.43a2.06 2.06 0 1 1 0-4.13 2.06 2.06 0 0 1 0 4.13zM7.12 "
    "20.45H3.56V9h3.56v11.45zM22.22 0H1.77C.79 0 0 .77 0 1.72v20.56C0 23.23.79 24 1.77 24h20.45c.98 0 "
    '1.78-.77 1.78-1.72V1.72C24 .77 23.2 0 22.22 0z"/></svg>'
)
ICON_INSTAGRAM = (
    '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 2.2c3.2 0 3.6 0 4.9.1 '
    "1.2.1 1.8.2 2.2.4.6.2 1 .5 1.4.9.4.4.7.8.9 1.4.2.4.3 1 .4 2.2.1 1.3.1 1.6.1 4.8s0 3.5-.1 4.8c-.1 "
    "1.2-.2 1.8-.4 2.2-.2.6-.5 1-.9 1.4-.4.4-.8.7-1.4.9-.4.2-1 .3-2.2.4-1.3.1-1.6.1-4.9.1s-3.6 0-4.9-.1"
    "c-1.2-.1-1.8-.2-2.2-.4-.6-.2-1-.5-1.4-.9-.4-.4-.7-.8-.9-1.4-.2-.4-.3-1-.4-2.2C2.2 15.5 2.2 15.2 2.2 "
    "12s0-3.5.1-4.8c.1-1.2.2-1.8.4-2.2.2-.6.5-1 .9-1.4.4-.4.8-.7 1.4-.9.4-.2 1-.3 2.2-.4C8.4 2.2 8.8 2.2 "
    "12 2.2zm0 1.8c-3.1 0-3.5 0-4.7.1-1.1.1-1.7.2-2.1.4-.5.2-.9.4-1.3.8-.4.4-.6.8-.8 1.3-.2.4-.3 1-.4 "
    "2.1C2.6 10 2.6 10.3 2.6 12s0 2 .1 3.2c.1 1.1.2 1.7.4 2.1.2.5.4.9.8 1.3.4.4.8.6 1.3.8.4.2 1 .3 2.1.4 "
    "1.2.1 1.6.1 4.7.1s3.5 0 4.7-.1c1.1-.1 1.7-.2 2.1-.4.5-.2.9-.4 1.3-.8.4-.4.6-.8.8-1.3.2-.4.3-1 .4-2.1"
    ".1-1.2.1-1.6.1-3.2s0-2-.1-3.2c-.1-1.1-.2-1.7-.4-2.1-.2-.5-.4-.9-.8-1.3-.4-.4-.8-.6-1.3-.8-.4-.2-1-.3"
    "-2.1-.4-1.2-.1-1.6-.1-4.7-.1zm0 3a5 5 0 1 1 0 10 5 5 0 0 1 0-10zm0 8.2a3.2 3.2 0 1 0 0-6.4 3.2 3.2 0 "
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
    "9.28 11.33 11.36c.13.28.4.28.53 0C12.87 9.28 15.6 5.42 18.14 3.51c1.83-1.37 4.8-2.43 4.8.96 0 .68"
    "-.39 5.7-.62 6.52-.79 2.83-3.67 3.55-6.24 3.11 4.49.77 5.63 3.3 3.16 5.83-4.69 4.8-6.74-1.2-7.27"
    "-2.74-.1-.28-.14-.41-.14-.3 0-.11-.05.02-.14.3-.53 1.54-2.58 7.54-7.27 2.74-2.47-2.53-1.33-5.06 "
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
    issued_time = fmt_time(cred.get("validFrom", ""))

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
        f'<span class="prompt">$</span> curl {ADOPTERS_URL}did.json\n\n'
        '<span class="comment"># Verify the credential proof against it</span>\n'
        '<span class="prompt">&gt;&gt;&gt;</span> Verifier.verify_credential(cred, public_key)  # True</div>'
    )
    sections.append(section("Verify locally", terminal, cls="no-print"))
    sections_html = "\n  \n".join(sections)

    # Share text, tailored per platform, with a CTA into the adopters program.
    x_text = (
        f"{name} is now a Vouch Verified Integration. "
        f"Vouch {X_HANDLE} is the open standard for AI agent identity and accountability, and open source.\n\n"
        "Build a reference integration: " + ADOPTERS_URL
    )
    wa_text = (
        f"{name} is now a Vouch Verified Integration. "
        "Vouch is the open standard for AI agent identity and accountability, and open source.\n\n"
        "Build on Vouch: " + ADOPTERS_URL + "\n\n" + cert_url
    )
    linkedin_text = (
        f"{name} is now a Vouch Verified Integration.\n\n"
        "The integration is cryptographically certified: the certificate is signed by the Vouch Adopter "
        "Authority, chained to the protocol root, and verifiable by anyone.\n\n"
        "Vouch Protocol is the open standard for AI agent identity and accountability. If you build or secure "
        "AI agents, it gives them a cryptographic identity, verifiable accountability, and a heartbeat "
        "protocol for continuous trust.\n\n"
        "See everyone building on the protocol:\n"
        f"{ADOPTERS_URL}\n\n"
        f"Vouch Protocol on LinkedIn: {LINKEDIN_URL}\n\n"
        f"The certificate: {cert_url}\n\n"
        "#AIagents #OpenSource #Cryptography #Vouch"
    )
    bsky_text = (
        f"{name} is now a Vouch Verified Integration. "
        f"Vouch {BLUESKY_HANDLE} is the open standard for AI agent identity and accountability, and open source.\n\n"
        "Build a reference integration: " + ADOPTERS_URL + "\n\n" + cert_url
    )
    x_intent = f"https://twitter.com/intent/tweet?text={quote(x_text)}&url={quote(cert_url)}"
    wa_intent = f"https://wa.me/?text={quote(wa_text)}"
    bsky_intent = f"https://bsky.app/intent/compose?text={quote(bsky_text)}"
    linkedin_share = f"https://www.linkedin.com/sharing/share-offsite/?url={quote(cert_url)}"
    linkedin_js = json.dumps(linkedin_text)
    linkedin_url_js = json.dumps(linkedin_share)
    share_text_js = json.dumps(
        f"{name} is now a Vouch Verified Integration. "
        "Vouch is the open standard for AI agent identity and accountability.\n\n"
        "Build on Vouch: " + ADOPTERS_URL + "\n\n" + cert_url
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

    discussion_html = ""
    if discussion:
        discussion_html = (
            "    <p>See the integration record on "
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
.seal-wrap a {{ display: inline-flex; line-height: 0; }}
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
.mono-text {{ font-family: "JetBrains Mono", monospace; font-size: 0.9rem; word-break: break-all; color: var(--ink); }}
.mono-text.dim {{ color: var(--ink-soft); font-size: 0.85rem; }}
.signer-caption {{ color: var(--ink-faint); font-style: italic; font-size: 0.9rem; margin-top: 6px; }}
.section-body a {{ color: var(--burgundy); text-decoration: none; border-bottom: 1px solid var(--burgundy); }}
.section-body a:hover {{ color: var(--burgundy-dark); border-bottom-color: var(--burgundy-dark); }}
.terminal {{ font-family: "JetBrains Mono", monospace; font-size: 0.85rem; background: var(--code-bg); color: var(--code-fg); padding: 16px 18px; margin: 12px auto; text-align: left; overflow-x: auto; max-width: 560px; white-space: pre-wrap; }}
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
  @page {{ margin: 0.8cm; }}
  body {{ padding: 0; font-size: 12.5px; min-height: 0; -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
  .frame {{ max-width: none; margin: 0; min-height: calc(100vh - 0.5cm); padding: 30px 56px 22px; border: 2px double var(--burgundy); display: flex; flex-direction: column; }}
  .frame > section {{ flex: 1 1 auto; display: flex; flex-direction: column; }}
  .cert-body {{ flex: 1 1 auto; display: flex; flex-direction: column; justify-content: space-evenly; }}
  .seal-wrap {{ margin-bottom: 10px; }}
  .seal-img {{ width: 150px; height: 150px; }}
  .issued-line {{ font-size: 0.66rem; margin-bottom: 22px; }}
  h1.title {{ font-size: 1.2rem; margin-bottom: 6px; }}
  .byline {{ margin-bottom: 26px; }}
  .section {{ margin: 0; }}
  .section-head {{ margin-bottom: 7px; }}
  .pagefoot {{ margin-top: 26px; padding-top: 14px; border-top: none; }}
}}
</style>
</head>
<body>
{rail}
<div class="frame">
<section>
  <div class="cert-head">
  <div class="seal-wrap">
    <a href="https://vouch-protocol.com" target="_blank" rel="noopener noreferrer" aria-label="Vouch Protocol">
      <img class="seal-img" src="https://vouch-protocol.com/seal-verified.png" alt="Vouch Protocol Verified" />
    </a>
  </div>
  <p class="issued-line">{esc(issued)} &middot; {esc(issued_time)}</p>
  <h1 class="title">Vouch Verified Integration</h1>
  <p class="byline">{esc(name)}{by_html}</p>
  </div>

  <div class="cert-body">
{sections_html}
  </div>

  <div class="about">
    <div class="section-head"><div class="rule-line"></div><span class="eyebrow">An Open Standard</span><div class="rule-line"></div></div>
    <p>Vouch gives AI agents a cryptographic identity, verifiable accountability, and a heartbeat
    protocol for continuous trust, so anyone can prove who acted, under whose authority, and that the
    agent is still trustworthy. The accountability layer adds commit-before-outcome evidence and an
    AccountabilityRecord a counterparty can recompute rather than trust.</p>
    <p>The <a href="https://vouch-protocol.com/agent-trust-index" target="_blank" rel="noopener noreferrer">Agent Trust Index</a> grades how verifiable and accountable an AI agent is, an open, public scorecard.</p>
    <p class="cta"><a href="https://vouch-protocol.com/the-trust-gap" target="_blank" rel="noopener noreferrer">See the AI trust gap</a></p>
  </div>

  <div class="footer-cta">
{discussion_html}    See everyone building on the protocol on the <a href="{esc(ADOPTERS_URL)}" target="_blank" rel="noopener noreferrer">Vouch adopters</a> page.<br>
    <a href="{esc(DISCUSSIONS_URL)}" target="_blank" rel="noopener noreferrer">Build a reference integration</a>.
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
    navigator.share({{ title: document.title, text: SHARE_TEXT }}).catch(function () {{}});
  }} else if (navigator.clipboard) {{
    navigator.clipboard.writeText(SHARE_TEXT).then(function () {{
      alert("Copied. Paste it anywhere.");
    }});
  }} else {{
    window.prompt("Copy this to share:", SHARE_TEXT);
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
