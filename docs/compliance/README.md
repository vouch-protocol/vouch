# Vouch Protocol™ — Regulatory compliance mapping

This directory maps Vouch Protocol's mechanisms to specific
requirements of the regulatory frameworks most commonly cited by
deployments using autonomous AI agents.

Each document maps from the regulation's requirements (the **outside-in**
view a compliance officer cares about) to the Vouch Protocol section
or mechanism that satisfies it. The intent is to give an enterprise
adopter a single page they can hand to legal, internal audit, or a
regulator.

These documents are **informative**, not normative. The W3C CCG report
(`docs/specs/w3c-cg-report.md`) is the normative specification. A
conformance claim at the L1/L2/L3 levels (§17 of the spec) does not
imply legal compliance with any specific framework; legal compliance
depends on the full deployment, not just the protocol layer.

## Documents in this directory

| File | Framework | Status |
|---|---|---|
| `gdpr.md` | EU General Data Protection Regulation | Skeleton |
| `eu-ai-act.md` | EU AI Act (Regulation 2024/1689) | Skeleton |
| `nist-800-63.md` | NIST SP 800-63 Digital Identity Guidelines (IAL/AAL/FAL) | Skeleton |
| `hipaa.md` | US HIPAA Privacy and Security Rules | Skeleton |
| `soc-2.md` | AICPA SOC 2 Trust Services Criteria | Planned |
| `iso-27001.md` | ISO/IEC 27001 Information Security Management | Planned |
| `pci-dss.md` | PCI Data Security Standard v4.0 | Planned |
| `dpdpa.md` | India Digital Personal Data Protection Act 2023 | Planned |

## How to use these documents

If you are evaluating Vouch Protocol against a specific compliance
mandate:

1. Find the document for your framework above.
2. Read the **Summary** at the top: what Vouch claims to help with, and
   what it explicitly does not address.
3. Walk the **Requirements mapping** table: each row is a clause or
   requirement from the regulation, with the Vouch mechanism that
   satisfies it (or "out of scope" with a brief reason).
4. Use the **Deployment checklist** to translate mappings into
   configuration decisions for your runtime.
5. The **Open questions** section flags items where the protocol's
   default does not meet the requirement and additional deployment
   work is needed.

## Document structure (each framework follows this template)

```markdown
# Framework name (regulation/standard/standard number)

## Summary
- Where Vouch Protocol helps
- Where Vouch Protocol explicitly does not address
- Minimum conformance level recommended

## Requirements mapping
| Clause | Requirement (paraphrased) | Vouch mechanism | Spec section |
|---|---|---|---|
| ... | ... | ... | ... |

## Deployment checklist
- [ ] Specific configuration items required

## Open questions / gaps
- Things that need legal or deployment-level work beyond the protocol
```

## Contributing

These documents are open for review and contribution. If you are a
practitioner of any of these frameworks and find a mapping incorrect,
incomplete, or misleading, please open a PR against this directory.
The maintainers will incorporate corrections rather than litigate them.
