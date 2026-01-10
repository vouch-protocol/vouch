# Vouch Protocol arXiv Submissions

This directory contains 8 LaTeX papers for submission to arXiv as the **Vouch Protocol Defensive Disclosure Series**.

## Papers

| ID | Title | Category |
|----|-------|----------|
| PAD-001 | Cryptographic Binding of AI Agent Identity | cs.CR |
| PAD-002 | Chain of Custody Delegation in Multi-Agent Systems | cs.CR |
| PAD-003 | Identity Sidecar Pattern for Autonomous Agents | cs.DC |
| PAD-004 | DOM-Traversing Signature Matching ("Smart Scan") | cs.CR |
| PAD-005 | Detached Signature Recovery via Reverse Lookup Registry | cs.CR |
| PAD-006 | URL-Based Credential Chaining for Trust Graphs | cs.CR |
| PAD-007 | Automated Provenance via Input Telemetry ("Ghost Signature") | cs.SE |
| PAD-008 | Hybrid Identity Bootstrapping via SSH Keys | cs.CR |

## Building PDFs

Each paper can be compiled individually:

```bash
cd pad-001
pdflatex main.tex
```

Or build all:

```bash
for dir in pad-*/; do
  cd "$dir"
  pdflatex main.tex
  cd ..
done
```

## Submitting to arXiv

1. Go to https://arxiv.org/submit
2. Upload `main.tex` and `../common/preamble.tex`
3. Select category (cs.CR for most, cs.SE for PAD-007)
4. Enter metadata (title, abstract, etc.)
5. Submit for moderation

## Recommended: Submit All on Same Day

To get sequential arXiv IDs (xxxx.00001, xxxx.00002, etc.), submit all 8 papers on the same day.

## Author Information

**Ramprasad Yoganathan**
Vouch Protocol Project
https://vouch-protocol.com
