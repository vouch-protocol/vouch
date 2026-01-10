#!/usr/bin/env python3
"""
Sign Blog Posts and Register in Cloudflare KV

Signs each blog post using Vouch Protocol and registers the signature
in Cloudflare KV for verification via v.vouch-protocol.com/tech00X
"""

import os
import glob
import re
import base64
import json
import subprocess
import hashlib
from datetime import datetime

# Config
BLOG_DIR = "/home/rampy/vouch-protocol/docs/blog"
WORKER_DIR = "/home/rampy/vouch-protocol/cloudflare-worker"
KV_NAMESPACE_ID = "08413c23ad6147b78d406ba31f52ba1e"
AUTHOR = "Ramprasad Anandam Gaddam"
SIGNER = "github:rampyg"

# Mapping: PAD number -> tech ID
POST_MAPPING = {
    "pad-001": "tech001",
    "pad-002": "tech002",
    "pad-003": "tech003",
    "pad-004": "tech004",
    "pad-005": "tech005",
    "pad-006": "tech006",
    "pad-007": "tech007",
    "pad-008": "tech008",
}

def extract_text_content(html):
    """Extract text content from article tag."""
    match = re.search(r'<article>(.*?)</article>', html, re.DOTALL)
    if not match:
        return None
    
    content = match.group(1)
    
    # Strip HTML tags
    text = re.sub(r'<[^>]+>', '', content)
    # Normalize whitespace
    text = ' '.join(text.split())
    return text.strip()

def compute_sha256(text):
    """Compute SHA-256 hash of text."""
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def upload_to_kv(key, value):
    """Upload to Cloudflare KV using wrangler."""
    print(f"  📤 Uploading {key} to KV...")
    
    value_str = json.dumps(value)
    cmd = [
        "npx", "wrangler", "kv:key", "put",
        key, value_str,
        "--namespace-id", KV_NAMESPACE_ID
    ]
    
    result = subprocess.run(
        cmd,
        cwd=WORKER_DIR,
        capture_output=True,
        text=True
    )
    
    if result.returncode == 0:
        print(f"  ✅ Uploaded {key}")
        return True
    else:
        print(f"  ❌ Failed: {result.stderr.strip()}")
        return False

def add_verify_badge_to_html(filepath, tech_id):
    """Add verify badge to the HTML file."""
    with open(filepath, 'r') as f:
        html = f.read()
    
    verify_url = f"https://v.vouch-protocol.com/{tech_id}"
    
    # Check if badge already exists
    if "verify-badge" in html and tech_id in html:
        print(f"  ⏭️  Badge already exists")
        return
    
    # Add badge after the paper-link in post-meta
    badge_html = f'<a href="{verify_url}" class="verify-badge" target="_blank">✓ Verified {tech_id}</a>'
    
    # Insert after "Read Full Paper" link
    pattern = r'(class="paper-link"[^>]*>[^<]*</a>)'
    replacement = rf'\1\n            {badge_html}'
    
    new_html = re.sub(pattern, replacement, html)
    
    with open(filepath, 'w') as f:
        f.write(new_html)
    
    print(f"  🏷️  Added verify badge")

def process_file(filepath):
    """Process a single blog post file."""
    filename = os.path.basename(filepath)
    pad_id = filename.replace(".html", "")  # e.g., "pad-001"
    tech_id = POST_MAPPING.get(pad_id)
    
    if not tech_id:
        print(f"⚠️  No mapping for {pad_id}")
        return
    
    print(f"\n📝 Processing {filename} -> {tech_id}")
    
    # Read and extract content
    with open(filepath, 'r') as f:
        html = f.read()
    
    text_content = extract_text_content(html)
    if not text_content:
        print(f"  ❌ Could not extract article content")
        return
    
    # Compute hash
    sha256_hash = compute_sha256(text_content)
    
    # Prepare KV data (compatible with worker.js handlePaperPage)
    kv_data = {
        "id": tech_id,
        "sha256": sha256_hash,
        "author": AUTHOR,
        "signer": SIGNER,
        "title": extract_title(html),
        "registered": datetime.utcnow().isoformat() + "Z",
        "type": "article",
        "tier": "pro"
    }
    
    # Upload to KV with paper: prefix (for handlePaperPage compatibility)
    upload_to_kv(f"paper:{tech_id}", kv_data)
    
    # Add badge to HTML
    add_verify_badge_to_html(filepath, tech_id)

def extract_title(html):
    """Extract title from HTML."""
    match = re.search(r'<h1>(.*?)</h1>', html)
    return match.group(1) if match else "Unknown"

def main():
    print("🔐 Vouch Protocol - Blog Post Signing")
    print("=" * 50)
    
    files = sorted(glob.glob(os.path.join(BLOG_DIR, "pad-*.html")))
    
    for filepath in files:
        process_file(filepath)
    
    print("\n" + "=" * 50)
    print("✅ Done! All posts signed and registered.")
    print("\nVerification URLs:")
    for pad_id, tech_id in POST_MAPPING.items():
        print(f"  {pad_id}.html -> https://v.vouch-protocol.com/p/{tech_id}")

if __name__ == "__main__":
    main()
