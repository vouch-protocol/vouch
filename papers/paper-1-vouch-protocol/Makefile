PAPER := paper-1-vouch-protocol
TEX   := $(PAPER).tex
BIB   := references.bib
PDF   := $(PAPER).pdf
ARXIV_TARBALL := $(PAPER)-arxiv.tar.gz

LATEX := pdflatex -interaction=nonstopmode -halt-on-error
BIBTEX := bibtex

.PHONY: all clean arxiv

all: $(PDF)

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

# arXiv submission tarball — the .tex, the .bib, and the .bbl
arxiv: $(PDF)
	@echo "==> Packaging arXiv tarball"
	tar czf $(ARXIV_TARBALL) $(TEX) $(BIB) $(PAPER).bbl
	@echo "==> Created: $(ARXIV_TARBALL)"
	@echo "    Upload at https://arxiv.org/submit"

clean:
	rm -f $(PAPER).aux $(PAPER).log $(PAPER).out $(PAPER).bbl $(PAPER).blg \
	      $(PAPER).toc $(PAPER).fls $(PAPER).fdb_latexmk $(PAPER).synctex.gz \
	      $(ARXIV_TARBALL)

distclean: clean
	rm -f $(PDF)
