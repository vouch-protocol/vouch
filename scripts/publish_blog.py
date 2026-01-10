import re
import os
import datetime

# --- CONFIG ---
SOURCE_FILE = "/home/rampy/.gemini/antigravity/brain/34db09bd-73b1-4423-9d6b-179f6430de81/blog_series_technical_digest.md"
OUTPUT_DIR = "/home/rampy/vouch-protocol/docs/blog"
BLOG_INDEX = "/home/rampy/vouch-protocol/docs/blog/index.html"

# --- POST METADATA (SEO Optimized) ---
POST_METADATA = {
    "PAD-001": {
        "slug": "who-authorized-this-problem",
        "tech_id": "tech001",
        "og_desc": "How Vouch Protocol binds AI agent identity to specific actions with cryptographic proof. Stop asking 'who are you?' and start asking 'who authorized this?'",
        "arxiv_url": "https://vouch-protocol.com/docs/disclosures/PAD-001-cryptographic-agent-identity.md",
        "reading_time": "3 min read",
    },
    "PAD-002": {
        "slug": "ai-agent-delegation-chains",
        "tech_id": "tech002",
        "og_desc": "When AI agents delegate to other AI agents, who's accountable? Vouch creates an auditable chain of custody for multi-agent systems.",
        "arxiv_url": "https://vouch-protocol.com/docs/disclosures/PAD-002-delegation-chain.md",
        "reading_time": "3 min read",
    },
    "PAD-003": {
        "slug": "identity-sidecar-architecture",
        "tech_id": "tech003",
        "og_desc": "Why AI agents should never hold private keys. The Identity Sidecar pattern keeps secrets secure while agents sign requests.",
        "arxiv_url": "https://vouch-protocol.com/docs/disclosures/PAD-003-identity-sidecar.md",
        "reading_time": "3 min read",
    },
    "PAD-004": {
        "slug": "ambient-verification-browser",
        "tech_id": "tech004",
        "og_desc": "Making signature verification invisible. How browser extensions can automatically verify signed content as you browse.",
        "arxiv_url": "https://vouch-protocol.com/docs/disclosures/PAD-004-ambient-verification.md",
        "reading_time": "3 min read",
    },
    "PAD-005": {
        "slug": "orphaned-content-signatures",
        "tech_id": "tech005",
        "og_desc": "Finding signatures for content that got copy-pasted without attribution. The Hash Registry approach for orphaned content.",
        "arxiv_url": "https://vouch-protocol.com/docs/disclosures/PAD-005-hash-registry.md",
        "reading_time": "3 min read",
    },
    "PAD-006": {
        "slug": "web-of-trust-urls",
        "tech_id": "tech006",
        "og_desc": "Building decentralized trust using DNS and URLs. How did:web enables verifiable identity without blockchain.",
        "arxiv_url": "https://vouch-protocol.com/docs/disclosures/PAD-006-web-trust.md",
        "reading_time": "3 min read",
    },
    "PAD-007": {
        "slug": "ai-coding-assistant-signatures",
        "tech_id": "tech007",
        "og_desc": "Proving you wrote code with AI assistance. Cryptographic signatures for IDE-generated code to demonstrate human involvement.",
        "arxiv_url": "https://vouch-protocol.com/docs/disclosures/PAD-007-ghost-signature-telemetry.md",
        "reading_time": "4 min read",
    },
    "PAD-008": {
        "slug": "zero-friction-ssh-identity",
        "tech_id": "tech008",
        "og_desc": "Zero-friction identity for 100M+ developers. Use your existing GitHub SSH keys to sign with Vouch instantly.",
        "arxiv_url": "https://vouch-protocol.com/docs/disclosures/PAD-008-hybrid-ssh-verification.md",
        "reading_time": "3 min read",
    },
}

# --- TEMPLATES ---
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} - Vouch Protocol</title>
    <meta name="description" content="{og_description}">
    <meta name="author" content="Ramprasad Anandam Gaddam">
    
    <!-- Canonical URL -->
    <link rel="canonical" href="https://vouch-protocol.com/blog/{filename}">
    
    <!-- Open Graph -->
    <meta property="og:title" content="{title}">
    <meta property="og:description" content="{og_description}">
    <meta property="og:type" content="article">
    <meta property="og:url" content="https://vouch-protocol.com/blog/{filename}">
    <meta property="og:image" content="https://vouch-protocol.com/images/og-blog-{slug}.png">
    <meta property="og:site_name" content="Vouch Protocol">
    <meta property="article:author" content="Ramprasad Anandam Gaddam">
    <meta property="article:published_time" content="2026-01-10T00:00:00Z">
    
    <!-- Twitter Card -->
    <meta name="twitter:card" content="summary_large_image">
    <meta name="twitter:site" content="@vouchprotocol">
    <meta name="twitter:title" content="{title}">
    <meta name="twitter:description" content="{og_description}">
    <meta name="twitter:image" content="https://vouch-protocol.com/images/og-blog-{slug}.png">

    <!-- Favicon -->
    <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>�</text></svg>">

    <!-- Fonts -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">

    <!-- JSON-LD Structured Data -->
    <script type="application/ld+json">
    {{
        "@context": "https://schema.org",
        "@type": "Article",
        "headline": "{title}",
        "description": "{og_description}",
        "author": {{
            "@type": "Person",
            "name": "Ramprasad Anandam Gaddam",
            "url": "https://github.com/rampyg"
        }},
        "publisher": {{
            "@type": "Organization",
            "name": "Vouch Protocol",
            "url": "https://vouch-protocol.com"
        }},
        "datePublished": "2026-01-10",
        "mainEntityOfPage": "https://vouch-protocol.com/blog/{filename}",
        "url": "https://vouch-protocol.com/blog/{filename}"
    }}
    </script>

    <style>
        :root {{
            --bg-primary: #0a0a0f;
            --bg-secondary: #12121a;
            --bg-card: #1a1a24;
            --text-primary: #ffffff;
            --text-secondary: #a0a0b0;
            --accent: #6366f1;
            --accent-glow: rgba(99, 102, 241, 0.3);
            --success: #10b981;
            --border: rgba(255, 255, 255, 0.08);
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Inter', sans-serif; background: var(--bg-primary); color: var(--text-primary); line-height: 1.8; }}
        .gradient-bg {{ position: fixed; top: 0; left: 0; right: 0; height: 100vh; background: radial-gradient(ellipse at 50% 0%, rgba(99, 102, 241, 0.15) 0%, transparent 60%); pointer-events: none; z-index: -1; }}
        nav {{ padding: 1.5rem 2rem; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); }}
        .logo {{ font-size: 1.5rem; font-weight: 800; color: var(--text-primary); text-decoration: none; }}
        .logo span {{ color: var(--accent); }}
        .nav-links {{ display: flex; gap: 2rem; list-style: none; }}
        .nav-links a {{ color: var(--text-secondary); text-decoration: none; font-weight: 500; }}
        .nav-links a:hover {{ color: var(--text-primary); }}
        article {{ max-width: 800px; margin: 0 auto; padding: 4rem 2rem; }}
        h1 {{ font-size: 2.5rem; font-weight: 800; margin-bottom: 1rem; line-height: 1.2; }}
        .post-meta {{ color: var(--text-secondary); font-size: 0.9rem; margin-bottom: 2rem; display: flex; gap: 1rem; align-items: center; flex-wrap: wrap; }}
        .verify-badge {{ background: rgba(16, 185, 129, 0.1); color: var(--success); padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.8rem; font-weight: 600; text-decoration: none; border: 1px solid rgba(16, 185, 129, 0.2); }}
        .verify-badge:hover {{ background: rgba(16, 185, 129, 0.2); }}
        .paper-link {{ background: rgba(99, 102, 241, 0.1); color: var(--accent); padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.8rem; font-weight: 600; text-decoration: none; border: 1px solid rgba(99, 102, 241, 0.2); }}
        .paper-link:hover {{ background: rgba(99, 102, 241, 0.2); }}
        .reading-time {{ color: var(--text-secondary); font-size: 0.85rem; }}
        h2, h3 {{ color: var(--text-primary); margin-top: 2rem; margin-bottom: 1rem; }}
        h3 {{ color: var(--accent); font-size: 1.25rem; }}
        p, li {{ color: #d1d1db; margin-bottom: 1rem; }}
        ul, ol {{ padding-left: 1.5rem; margin-bottom: 1.5rem; }}
        .callout {{ background: var(--bg-secondary); border-left: 4px solid var(--accent); padding: 1.5rem; margin: 2rem 0; border-radius: 0 8px 8px 0; }}
        .callout strong {{ color: var(--text-primary); }}
        footer {{ padding: 3rem 2rem; text-align: center; border-top: 1px solid var(--border); color: var(--text-secondary); }}
    </style>
</head>
<body>
    <div class="gradient-bg"></div>
    <nav>
        <a href="https://vouch-protocol.com" class="logo">🔐 Vouch <span>Protocol</span></a>
        <ul class="nav-links">
            <li><a href="https://vouch-protocol.com/blog">Blog</a></li>
            <li><a href="https://github.com/vouch-protocol/vouch">GitHub</a></li>
        </ul>
    </nav>
    <article>
        <div class="post-meta">
            <span>January 10, 2026</span>
            <span class="reading-time">📖 {reading_time}</span>
            <a href="{arxiv_url}" class="paper-link" target="_blank">📄 Read Full Paper</a>
            <a href="https://v.vouch-protocol.com/{tech_id}" class="verify-badge" target="_blank">✓ Verified {tech_id}</a>
        </div>
        <h1>{title}</h1>
        {content}
        <hr style="border: 0; height: 1px; background: var(--border); margin: 3rem 0;">
        <p style="text-align: center;">
            <a href="https://vouch-protocol.com/blog" style="color: var(--accent); text-decoration: none;">← Back to Blog</a>
        </p>
    </article>
    <footer>
        <p>© 2024-2026 Vouch Protocol. Apache 2.0 License.</p>
    </footer>
</body>
</html>"""

def clean_md(text):
    # Basic MD to HTML conversion
    html = text
    # Remove "Based on [PAD-XXX: ...]" lines (we have a dedicated paper link now)
    html = re.sub(r'^\*Based on \[PAD-\d+:.*?\]\*\n?', '', html, flags=re.MULTILINE)
    # Headers
    html = re.sub(r'^### (.*)$', r'<h3>\1</h3>', html, flags=re.MULTILINE)
    # Bold
    html = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', html)
    # Italic
    html = re.sub(r'\*(.*?)\*', r'<em>\1</em>', html)
    # Lists
    html = re.sub(r'^- (.*)$', r'<li>\1</li>', html, flags=re.MULTILINE)
    # Wrap lists (simple heuristic: consecutive li)
    html = re.sub(r'(<li>.*?</li>\n)+', lambda m: f"<ul>{m.group(0)}</ul>", html, flags=re.DOTALL)
    # Links
    html = re.sub(r'\[(.*?)\]\((.*?)\)', r'<a href="\2">\1</a>', html)
    # Paragraphs (lines that don't start with <)
    lines = html.split('\n')
    new_lines = []
    for line in lines:
        if line.strip() and not line.strip().startswith('<'):
            new_lines.append(f"<p>{line.strip()}</p>")
        else:
            new_lines.append(line)
    return "\n".join(new_lines)

def main():
    if not os.path.exists(SOURCE_FILE):
        print("Source file not found")
        return

    with open(SOURCE_FILE, "r") as f:
        content = f.read()

    # Split sections
    sections = re.split(r'^## \d+\. ', content, flags=re.MULTILINE)[1:] # Skip first chunk
    
    generated_pages = []

    for section in sections:
        match = re.search(r'(.*?) \((PAD-\d+)\)\n(.*?)$', section, re.DOTALL)
        if not match:
            # Fallback for updated titles that might be slightly different
            match_fallback = re.search(r'(.*?) \((PAD-\d+)\)\n(.*?)$', section, re.DOTALL)
            if not match_fallback:
                print(f"Skipping section: {section[:50]}...")
                continue
            match = match_fallback

        title = match.group(1).strip()
        pad_id = match.group(2).strip()
        body_md = match.group(3).strip()
        
        # Get metadata for this post
        metadata = POST_METADATA.get(pad_id, {})
        slug = metadata.get("slug", pad_id.lower().replace("-", ""))
        tech_id = metadata.get("tech_id", pad_id.lower().replace("-", ""))
        og_description = metadata.get("og_desc", f"Technical Digest: {title}")
        arxiv_url = metadata.get("arxiv_url", f"https://vouch-protocol.com/docs/disclosures/{pad_id}.md")
        reading_time = metadata.get("reading_time", "3 min read")
        
        # Clean title (remove "The Pain Point" etc if needed, but here we just take the first line)
        body_html = clean_md(body_md)
        filename = f"{slug}.html"  # SEO-friendly slug filename
        
        # Generate HTML
        full_html = HTML_TEMPLATE.format(
            title=title,
            slug=slug,
            tech_id=tech_id,
            og_description=og_description,
            arxiv_url=arxiv_url,
            reading_time=reading_time,
            filename=filename,
            content=body_html
        )
        
        path = os.path.join(OUTPUT_DIR, filename)
        with open(path, "w") as f:
            f.write(full_html)
        
        print(f"Generated {filename} (was {pad_id.lower()}.html)")
        generated_pages.append({"title": title, "filename": filename, "slug": slug, "id": pad_id, "og_desc": og_description})

    # Update Index (Append to top)
    # We will just rewrite the blog index to define these cleanly
    print("Files generated. Manually update index.html to list these.")
    
    # Generate snippets for index.html
    print("\n--- HTML Snippets for index.html ---")
    for page in generated_pages:
        print(f"""
        <article class="post-card">
            <div class="post-date">January 10, 2026 • {page['id']}</div>
            <h2><a href="{page['filename']}">{page['title']}</a></h2>
            <p>Technical Digest: {page['title']}</p>
            <a href="{page['filename']}" class="read-more">Read more →</a>
        </article>""")

if __name__ == "__main__":
    main()
