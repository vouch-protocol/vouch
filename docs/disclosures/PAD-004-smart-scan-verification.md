# Defensive Disclosure: DOM-Traversing Signature Matching ("Smart Scan")

**Disclosure ID:** PAD-004  
**Publication Date:** January 10, 2026  
**Author:** Ramprasad Anandam Gaddam  
**Status:** Public Domain / Prior Art  

---

## Abstract

This disclosure describes a method for automatically locating and visually highlighting cryptographically signed content within a web page, eliminating the need for manual text selection during verification.

---

## Problem Statement

Verifying cryptographically signed text within a web browser is prone to user error. Cryptographic signatures are sensitive to exact byte-level input:

- A trailing space, newline, or invisible Unicode character (e.g., Zero-Width Space U+200B) changes the hash
- Users cannot reliably select the *exact* text that was originally signed
- This results in "False Negative" verification failures, discouraging adoption

Current solutions require users to manually highlight text, leading to:
- **Whitespace errors**: Extra or missing spaces
- **Encoding mismatches**: Different Unicode normalization forms (NFC vs NFD)
- **Invisible characters**: Platform-specific formatting characters

---

## Disclosed Method

We disclose a client-side verification system (implemented as a Browser Extension) that removes the user from the manual selection process via automated DOM traversal and hash matching.

### Mechanism

```
┌─────────────────────────────────────────────────────────────┐
│                    SMART SCAN FLOW                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. DETECT: Find Vouch signature blocks on page             │
│          ↓                                                  │
│  2. EXTRACT: Decode signature → retrieve target hash        │
│          ↓                                                  │
│  3. TRAVERSE: Walk DOM tree (h1, h2, p, article, section)   │
│          ↓                                                  │
│  4. NORMALIZE: Collapse whitespace, remove zero-width chars │
│          ↓                                                  │
│  5. HASH: Compute SHA-256 for each text block               │
│          ↓                                                  │
│  6. COMPARE: Match computed hashes against signature hash   │
│          ↓                                                  │
│  7. HIGHLIGHT: Apply visual class to matching elements      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Technical Details

**Text Normalization:**
```javascript
function normalizeText(text) {
    return text
        .trim()
        .replace(/\s+/g, ' ')                    // Collapse whitespace
        .replace(/[\u200B-\u200D\uFEFF]/g, '');  // Remove zero-width chars
}
```

**DOM Selectors Scanned:**
- `h1`, `h2`, `h3`, `h4` (Headings)
- `p` (Paragraphs)
- `article`, `section` (Semantic blocks)
- `[data-vouch-content]` (Explicit marking)

**Visual Feedback:**
- Matching elements receive CSS class with green highlight
- Floating label "✅ Verified by Vouch" appears above content
- Pulse animation draws user attention

### Security Considerations

1. **Hash Algorithm**: Uses SHA-256 (or SHA-512) for collision resistance
2. **Client-Side Only**: No data transmitted to servers during scan
3. **False Positive Avoidance**: Exact hash match required; no fuzzy matching
4. **XSS Prevention**: Only reads text content, does not execute scripts

---

## Prior Art Declaration

This disclosure is published to establish prior art and prevent patent monopolization. The described method is hereby released into the public domain under the Creative Commons CC0 1.0 Universal dedication.

Any party implementing similar functionality after January 10, 2026 cannot claim novelty for patent purposes.

---

## Implementation Reference

Reference implementation available in:
- `browser-extension/content.js` - `performSmartScan()` function
- `browser-extension/background.js` - Context menu integration

Repository: https://github.com/vouch-protocol/vouch
