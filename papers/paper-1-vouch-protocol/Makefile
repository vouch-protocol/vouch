PAPER := paper-1-vouch-protocol
TEX   := $(PAPER).tex
BIB   := references.bib
PDF   := $(PAPER).pdf

# Dual-column variant (preview of how the paper looks in a typical conference
# two-column layout; identical content, only the documentclass option changes).
PAPER_2COL := $(PAPER)-2col
TEX_2COL   := $(PAPER_2COL).tex
PDF_2COL   := $(PAPER_2COL).pdf

ARXIV_TARBALL := $(PAPER)-arxiv.tar.gz

LATEX := pdflatex -interaction=nonstopmode -halt-on-error
BIBTEX := bibtex

.PHONY: all clean arxiv two-column distclean

all: $(PDF)

both: $(PDF) $(PDF_2COL)

$(PDF): $(TEX) $(BIB)
	@echo "==> Pass 1"
	$(LATEX) $(PAPER) > /dev/null
	@echo "==> bibtex"
	-$(BIBTEX) $(PAPER)
	@echo "==> Pass 2"
	$(LATEX) $(PAPER) > /dev/null
	@echo "==> Pass 3 (cross-refs)"
	$(LATEX) $(PAPER) > /dev/null
	@echo "==> Done: $(PDF)"

$(PDF_2COL): $(TEX_2COL) $(BIB)
	@echo "==> [2col] Pass 1"
	$(LATEX) $(PAPER_2COL) > /dev/null
	@echo "==> [2col] bibtex"
	-$(BIBTEX) $(PAPER_2COL)
	@echo "==> [2col] Pass 2"
	$(LATEX) $(PAPER_2COL) > /dev/null
	@echo "==> [2col] Pass 3 (cross-refs)"
	$(LATEX) $(PAPER_2COL) > /dev/null
	@echo "==> Done: $(PDF_2COL)"

two-column: $(PDF_2COL)

# arXiv submission tarball — the .tex, the .bib, and the .bbl
arxiv: $(PDF)
	@echo "==> Packaging arXiv tarball"
	tar czf $(ARXIV_TARBALL) $(TEX) $(BIB) $(PAPER).bbl
	@echo "==> Created: $(ARXIV_TARBALL)"
	@echo "    Upload at https://arxiv.org/submit"

clean:
	rm -f $(PAPER).aux $(PAPER).log $(PAPER).out $(PAPER).bbl $(PAPER).blg \
	      $(PAPER).toc $(PAPER).fls $(PAPER).fdb_latexmk $(PAPER).synctex.gz \
	      $(PAPER_2COL).aux $(PAPER_2COL).log $(PAPER_2COL).out $(PAPER_2COL).bbl $(PAPER_2COL).blg \
	      $(PAPER_2COL).toc $(PAPER_2COL).fls $(PAPER_2COL).fdb_latexmk $(PAPER_2COL).synctex.gz \
	      $(ARXIV_TARBALL)

distclean: clean
	rm -f $(PDF) $(PDF_2COL)
