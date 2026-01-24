# Defensive Disclosure: Automated Provenance via Input Telemetry ("Ghost Signature")

**Disclosure ID:** PAD-007  
**Publication Date:** January 10, 2026  
**Author:** Ramprasad Anandam Gaddam  
**Status:** Public Domain / Prior Art  

---

## Abstract

This disclosure describes a system for automatically tracking and attesting the provenance of code based on input telemetry, distinguishing between human-typed and AI-generated content without manual tagging.

---

## Problem Statement

In modern software development, code is frequently co-authored by human developers and AI assistants (GitHub Copilot, Cursor, Claude). Current cryptographic signing methods treat a commit as a monolithic block, attributing 100% of authorship to the human who committed it.

This creates a **"Provenance Gap"**:
- AI-generated code is attributed to humans
- Enterprise compliance audits cannot distinguish code origin
- Liability and IP attribution become unclear
- No audit trail for AI contribution percentage

---

## Disclosed Method

We disclose a system for granular, automated provenance tracking integrated directly into the text editor or IDE.

### Mechanism

```
┌─────────────────────────────────────────────────────────────┐
│                  GHOST SIGNATURE FLOW                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  TELEMETRY ANALYSIS (Real-time):                            │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  User types in editor                                │   │
│  │       │                                              │   │
│  │       ▼                                              │   │
│  │  Monitor: Input Velocity + Modification Patterns     │   │
│  │       │                                              │   │
│  │       ├─ 5-10 chars/sec + backspaces → HUMAN         │   │
│  │       │                                              │   │
│  │       └─ 500+ chars/sec (block insert) → SYNTHETIC   │   │
│  │                                                      │   │
│  └─────────────────────────────────────────────────────┘   │
│                           │                                 │
│                           ▼                                 │
│  CLASSIFICATION:                                            │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  file.py                                             │   │
│  │  ├─ Lines 1-9:   origin: human                       │   │
│  │  ├─ Lines 10-50: origin: synthetic (gpt-4, 800cps)   │   │
│  │  └─ Lines 51-55: origin: human                       │   │
│  └─────────────────────────────────────────────────────┘   │
│                           │                                 │
│                           ▼                                 │
│  GHOST SIGNATURE (On save/commit):                          │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Cryptographic attestation auto-generated            │   │
│  │  Signed by user's local identity agent               │   │
│  │  Attached via git notes / sidecar / commit trailer   │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Telemetry Signatures

| Pattern | Classification | Indicators |
|---------|----------------|------------|
| **Human** | `origin: human` | 5-10 chars/sec, frequent backspaces, cursor jumps |
| **Synthetic** | `origin: synthetic` | 500+ chars/sec, block insertion, API paste events |
| **Mixed** | `origin: mixed` | Human edits to synthetic base |

### Ghost Signature Schema

```json
{
  "version": 1,
  "file": "src/main.py",
  "timestamp": "2026-01-10T15:30:00Z",
  "signer": "did:vouch:ramprasad",
  "regions": [
    {
      "lines": "1-9",
      "origin": "human",
      "velocity": "8cps"
    },
    {
      "lines": "10-50",
      "origin": "synthetic",
      "model": "gpt-4",
      "velocity": "800cps",
      "prompt_hash": "sha256:abc123..."
    },
    {
      "lines": "51-55",
      "origin": "human",
      "velocity": "6cps"
    }
  ],
  "attestation": {
    "algorithm": "Ed25519",
    "signature": "base64:..."
  }
}
```

### Attachment Methods

| Method | Description | Use Case |
|--------|-------------|----------|
| **Git Notes** | `git notes add -m '{ ghost signature }'` | Non-intrusive, separate refs |
| **Sidecar File** | `.vouch/main.py.ghost.json` | Works with any VCS |
| **Commit Trailer** | `Ghost-Signature: base64:...` | Embedded in commit message |

### Benefits

1. **Invisible Non-Repudiation**: No manual tagging required
2. **Enterprise Audit**: Human/AI ratio per file, PR, or codebase
3. **IP Attribution**: Clear provenance for legal/compliance
4. **Model Tracking**: Which AI models contributed to which code

---

## Security Considerations

1. **Telemetry Privacy**: Data processed locally, only attestation shared
2. **Spoofing Prevention**: Velocity analysis resistant to slow-typing bots
3. **Signature Integrity**: Ghost signatures cryptographically bound to content hash
4. **Opt-Out**: User can disable telemetry (attestation shows "origin: unknown")

---

## Prior Art Declaration

This disclosure is published to establish prior art and prevent patent monopolization. The described method is hereby released into the public domain under the Creative Commons CC0 1.0 Universal dedication.

Any party implementing similar functionality after January 10, 2026 cannot claim novelty for patent purposes.

---

## Implementation Reference

Planned implementation in:
- VS Code Extension: `vouch-ghost-signature`
- JetBrains Plugin: `vouch-provenance`
- CLI: `vouch ghost analyze <file>`

Repository: https://github.com/vouch-protocol/vouch
