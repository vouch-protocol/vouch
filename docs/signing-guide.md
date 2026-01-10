# ✍️ Signing Your Content with Vouch Protocol

A guide for researchers, bloggers, and authors who want to cryptographically sign their content.

---

## Why Sign Your Content?

When you sign your content:
- **Readers can verify** it hasn't been tampered with
- **You prove authorship** with cryptographic certainty
- **AI can't fake it** - only you have your private key

---

## Method 1: Browser Extension (Easiest)

### Step 1: Install the Extension

1. Visit the [Chrome Web Store](https://chrome.google.com/webstore) (or Edge Add-ons)
2. Search for "**Vouch Protocol**"
3. Click "**Add to Chrome**"

### Step 2: Sign Your Content

1. **Write your article** in any editor or directly on your blog
2. **Select the text** you want to sign (highlight it)
3. **Right-click** → Choose "**✍️ Sign with Vouch**"
4. The signed block is now **in your clipboard**

### Step 3: Paste Into Your Article

Add the signed block at the end of your article:

```
[Signed]
Your article content here...

---
By: your.email@example.com 🔗 https://v.vouch-protocol.com/abc123
```

That's it! Readers with the extension will see a ✅ badge. Readers without it can click the link to verify.

---

## Method 2: Command Line (For Developers)

```bash
# Install Vouch
pip install vouch-protocol

# Initialize your identity (one-time)
vouch init --domain example.com

# Sign a file
vouch sign --file article.txt
```

---

## How Verification Works

### For Readers WITH the Extension:
- ✅ Green checkmark appears next to verified content
- ⚠️ Warning if content was modified
- 🔵 Blue badge for new/unknown signers

### For Readers WITHOUT the Extension:
- Click the verification link (e.g., `v.vouch-protocol.com/abc123`)
- See the verification page showing:
  - Signer identity
  - Timestamp
  - Content hash

---

## FAQ

**Q: Do I need to create an account?**
A: No! The extension generates a local keypair. No signup required.

**Q: Is my private key secure?**
A: Yes. It never leaves your device. Only the public key and signatures are shared.

**Q: What if I lose my key?**
A: Generate a new one. Old signatures remain valid (they were signed with the old key).

**Q: Can I sign PDFs?**
A: Currently text only. PDF support is coming soon.

---

## Get Started

1. [Install the Browser Extension](https://chrome.google.com/webstore)
2. [Read the Technical Papers](/docs/disclosures/)
3. [Join the Community](https://github.com/vouch-protocol/vouch)
