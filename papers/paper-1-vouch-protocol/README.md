# Paper 1 — Vouch Protocol (umbrella paper)

**Title:** Vouch Protocol: Cryptographic Identity and Continuous State Verifiability for Autonomous AI Agents

**Status:** Drafted, ready for arXiv submission

**arXiv ID:** *(to be filled once accepted)*

## Files

- `paper-1-vouch-protocol.tex` — LaTeX source (this is what arXiv compiles)
- `paper-1-vouch-protocol.md` — Markdown reading copy (human-friendly, kept in sync)
- `references.bib` — BibTeX database
- `Makefile` — build script
- `README.md` — this file

## Building locally

You need `pdflatex` and `bibtex` (any modern TeX distribution: TeX Live, MikTeX, MacTeX).

```bash
make            # produces paper-1-vouch-protocol.pdf
make arxiv      # produces paper-1-vouch-protocol-arxiv.tar.gz for submission
make clean      # remove intermediate files
make distclean  # also remove the PDF
```

## No local LaTeX?

Upload `paper-1-vouch-protocol.tex` and `references.bib` to
[Overleaf](https://www.overleaf.com), create a new project, and click
Compile. You get the same PDF.

## arXiv submission steps

1. Build clean locally: `make distclean && make`. Confirm zero warnings.
2. Run `make arxiv` to produce the tarball.
3. Open https://arxiv.org/submit.
4. **Primary category:** `cs.CR` (Cryptography and Security).
5. **Cross-list categories:** `cs.AI` (Artificial Intelligence), `cs.DC` (Distributed, Parallel, and Cluster Computing).
6. Upload the tarball.
7. Fill in the metadata:
   - **Title**: copy from the LaTeX title.
   - **Authors**: Ramprasad Anandam Gaddam.
   - **Abstract**: copy from the `\begin{abstract} ... \end{abstract}` block.
   - **Comments**: `25 pages. Companion to W3C CCG draft report.`
   - **License**: choose CC BY 4.0 to match the paper's stated license.
8. Submit. Wait for the moderation queue (typically 1–3 business days for first-time submitters).
9. Once announced, fill in the arXiv ID in `papers/README.md` and at the top of this file.

## Errata

If you find an error after submission, log it as a GitHub issue tagged
`paper-1`. Errata are corrected in this directory first; a v2 arXiv
revision is submitted when accumulated errata warrant it (typically
every 4–6 weeks during active iteration).
