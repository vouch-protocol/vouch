# Papers

Academic papers describing the Vouch Protocol. These are companion
publications to the open specification and reference implementations.

## Canonical citation

**arXiv is the canonical citation source.** When citing a Vouch paper
in your own work, cite the arXiv ID, not the GitHub URL.

This directory holds the LaTeX source, the BibTeX database, build
scripts, and a Markdown reading-copy for each paper. The source here
is what was used to produce the PDF submitted to arXiv. Treat this
directory as the **archive** and arXiv as the **publication**.

## Why both?

The papers live in this repo because:

- Reviewers and contributors can submit errata as GitHub issues.
- The LaTeX source is part of the protocol's reproducibility story.
- Pull requests can update minor inaccuracies between arXiv revisions.
- The author can update reading copies without re-submitting to arXiv
  every time.
- Forks of this repository include the papers automatically.

arXiv is the publication because:

- arXiv IDs are stable citations that survive repository moves and
  ownership changes.
- The arXiv moderation pass is light editorial QA.
- arXiv is the venue the academic community expects.

## Publication schedule

Four papers cover the body of work. They are sequenced to land
separately so each gets its own attention moment, rather than
batching all four at once.

| # | Title (working) | Status | Target submit | What it covers |
|---|---|---|---|---|
| 1 | **Vouch Protocol: Cryptographic Identity and Continuous State Verifiability for Autonomous AI Agents** | Drafted, LaTeX in progress | **May 2026** | The protocol overview: VC format, DIDs, sidecar, hybrid PQ, delegation, JCS. The umbrella paper. |
| 2 | **The Heartbeat Protocol: Decaying Trust and Behavioral Attestation for Long-Running AI Agents** | Outlined | July 2026 | State Verifiability runtime in depth: trust entropy, behavioral digests, canary commitments, Merkle action roots, validator quorum. Folds in PAD-016, PAD-020, PAD-022, PAD-032. |
| 3 | **Identity Sidecar Architecture: Capability-Bounded LLM Agents via Allow-List-Enforced Signing** | Outlined | September 2026 | The sidecar pattern, the tier hierarchy (Go / Python / TypeScript), the allow-list signing model. Folds in PAD-003 and PAD-056. Pairs naturally with a USENIX Security or CCS submission. |
| 4 | **Hybrid Composite Signatures Bound to Identical Canonical Payload: A Cryptosuite for the Post-Quantum Transition** | Outlined | November 2026 | PAD-040 in depth: the `hybrid-eddsa-mldsa44-jcs-2026` cryptosuite, verifier-mode semantics, migration sequencing. Folds in PAD-039, PAD-041, PAD-046. Timed near NIST PQC update cycles. |

## Directory layout

```
papers/
├── README.md                              (you are here)
├── paper-1-vouch-protocol/
│   ├── paper-1-vouch-protocol.tex         (LaTeX source)
│   ├── paper-1-vouch-protocol.md          (Markdown reading copy)
│   ├── references.bib                     (BibTeX database)
│   ├── Makefile                           (build script)
│   └── README.md                          (per-paper build & submit notes)
└── (papers 2-4 added when drafted)
```

## Building a paper

Each paper directory ships with a `Makefile`. From inside the paper
directory:

```bash
make           # build paper.pdf via pdflatex + bibtex
make clean     # remove intermediate files
make arxiv     # produce a paper.tar.gz suitable for arXiv submission
```

If you do not have a local LaTeX install, the standard alternative is
[Overleaf](https://www.overleaf.com): create a new project, upload
`paper-1-vouch-protocol.tex` and `references.bib`, click Compile.

## Submitting to arXiv

Per-paper notes are in each paper's directory. The general arXiv
workflow:

1. Build the PDF locally to confirm it compiles cleanly without warnings.
2. Run `make arxiv` to produce the source tarball.
3. Upload the tarball at https://arxiv.org/submit.
4. Choose categories (`cs.CR` primary, `cs.AI` cross-list for #1; choose per-paper for #2–#4).
5. Wait through the moderation queue (typically 1–3 business days for first submitters).
6. When announced, update this README's status column with the arXiv ID.

## Errata

If you find errors in a published paper:

1. Open an issue at https://github.com/vouch-protocol/vouch/issues
   tagged `paper-N` where N is the paper number.
2. The errata are corrected in this repo first.
3. A revised arXiv version is submitted when accumulated errata
   warrant a v2 (typically every 4–6 weeks during active iteration).

## License

The paper texts are released under **Creative Commons Attribution
4.0 International (CC BY 4.0)**. The accompanying LaTeX source,
BibTeX, and build scripts are released under **Apache 2.0**.
