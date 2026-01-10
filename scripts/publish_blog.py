import re
import os
import datetime

# --- CONFIG ---
SOURCE_FILE = "/home/rampy/.gemini/antigravity/brain/34db09bd-73b1-4423-9d6b-179f6430de81/blog_series_technical_digest.md"
OUTPUT_DIR = "/home/rampy/vouch-protocol/docs/blog"
BLOG_INDEX = "/home/rampy/vouch-protocol/docs/blog/index.html"

# --- TEMPLATES ---
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} - Vouch Protocol</title>
    <meta name="description" content="Vouch Protocol Technical Digest: {title}">
    
    <!-- Open Graph -->
    <meta property="og:title" content="{title}">
    <meta property="og:description" content="Technical Digest: {title}">
    <meta property="og:type" content="article">
    <meta property="og:url" content="https://vouch-protocol.com/blog/{filename}">

    <!-- Favicon -->
    <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>📝</text></svg>">

    <!-- Fonts -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">

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
        .post-meta {{ color: var(--text-secondary); font-size: 0.9rem; margin-bottom: 2rem; display: flex; gap: 1rem; align-items: center; }}
        .verify-badge {{ background: rgba(16, 185, 129, 0.1); color: var(--success); padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.8rem; font-weight: 600; text-decoration: none; border: 1px solid rgba(16, 185, 129, 0.2); }}
        .verify-badge:hover {{ background: rgba(16, 185, 129, 0.2); }}
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
        <a href="https://vouch-protocol.com" class="logo">🔐 Vouch <span>Blog</span></a>
        <ul class="nav-links">
            <li><a href="https://vouch-protocol.com/blog">Back to Blog</a></li>
            <li><a href="https://github.com/vouch-protocol/vouch">GitHub</a></li>
        </ul>
    </nav>
    <article>
        <div class="post-meta">
            <span>January 10, 2026</span>
            <a href="https://v.vouch-protocol.com/p/{pad_id}" class="verify-badge" target="_blank">✓ Verified {pad_id}</a>
        </div>
        <h1>{title}</h1>
        {content}
        <hr style="border: 0; height: 1px; background: var(--border); margin: 3rem 0;">
        <p style="text-align: center;">
            <a href="https://vouch-protocol.com/blog" style="color: var(--accent); text-decoration: none;">← Back to Digest Series</a>
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
        
        # Clean title (remove "The Pain Point" etc if needed, but here we just take the first line)
        body_html = clean_md(body_md)
        filename = f"{pad_id.lower()}.html"
        
        # Generate HTML
        full_html = HTML_TEMPLATE.format(
            title=title,
            pad_id=pad_id,
            filename=filename,
            content=body_html
        )
        
        path = os.path.join(OUTPUT_DIR, filename)
        with open(path, "w") as f:
            f.write(full_html)
        
        print(f"Generated {filename}")
        generated_pages.append({"title": title, "filename": filename, "id": pad_id})

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
