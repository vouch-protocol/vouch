# Vouch Protocol — Specifications Build
#
# Generates HTML, PDF, and DOCX renderings of the three specification documents.
#
# Requirements (install once):
#   Windows:   choco install pandoc miktex
#   macOS:     brew install pandoc basictex
#   Linux:     apt install pandoc texlive-xetex
#
# Usage:
#   make all          # builds everything
#   make html         # ReSpec HTML for CG Report + plain HTML for the others
#   make pdf          # PDF for all three
#   make docx         # DOCX for all three
#   make w3c          # the W3C-canonical artifact (CG Report ReSpec HTML)
#   make sponsor      # the sponsor distribution bundle (PDFs)
#   make clean

CG_REPORT  := w3c-cg-report.md
EXEC_SUM   := cg-report-executive-summary.md
SPONSOR    := vouch-sponsor-brief.md

OUT        := build
HTML_OUT   := $(OUT)/html
PDF_OUT    := $(OUT)/pdf
DOCX_OUT   := $(OUT)/docx

PANDOC_OPTS := --standalone --toc --toc-depth=3 --metadata=lang:en

PDF_OPTS  := --pdf-engine=xelatex \
             -V geometry:margin=1in \
             -V mainfont="DejaVu Serif" \
             -V monofont="DejaVu Sans Mono" \
             -V colorlinks=true \
             -V linkcolor=blue \
             -V urlcolor=blue

DOCX_OPTS := --reference-doc=corporate-template.docx 2>/dev/null || true

.PHONY: all html pdf docx w3c sponsor clean

all: html pdf docx

# ---------- HTML ----------
html: $(HTML_OUT)/w3c-cg-report.html \
      $(HTML_OUT)/cg-report-executive-summary.html \
      $(HTML_OUT)/vouch-sponsor-brief.html

$(HTML_OUT)/w3c-cg-report.html: $(CG_REPORT) | $(HTML_OUT)
	pandoc $(PANDOC_OPTS) -t html5 \
	  --template=respec-template.html \
	  -o $@ $<
	@echo "Built ReSpec HTML: $@"

$(HTML_OUT)/cg-report-executive-summary.html: $(EXEC_SUM) | $(HTML_OUT)
	pandoc $(PANDOC_OPTS) -t html5 -o $@ $<
	@echo "Built HTML: $@"

$(HTML_OUT)/vouch-sponsor-brief.html: $(SPONSOR) | $(HTML_OUT)
	pandoc $(PANDOC_OPTS) -t html5 -o $@ $<
	@echo "Built HTML: $@"

# ---------- PDF ----------
pdf: $(PDF_OUT)/w3c-cg-report.pdf \
     $(PDF_OUT)/cg-report-executive-summary.pdf \
     $(PDF_OUT)/vouch-sponsor-brief.pdf

$(PDF_OUT)/%.pdf: %.md | $(PDF_OUT)
	pandoc $(PANDOC_OPTS) $(PDF_OPTS) -o $@ $<
	@echo "Built PDF: $@"

# ---------- DOCX ----------
docx: $(DOCX_OUT)/w3c-cg-report.docx \
      $(DOCX_OUT)/cg-report-executive-summary.docx \
      $(DOCX_OUT)/vouch-sponsor-brief.docx

$(DOCX_OUT)/%.docx: %.md | $(DOCX_OUT)
	pandoc $(PANDOC_OPTS) -o $@ $<
	@echo "Built DOCX: $@"

# ---------- Convenience targets ----------
w3c: $(HTML_OUT)/w3c-cg-report.html
	@echo ""
	@echo "W3C-canonical submission artifact built at $<"
	@echo "Submit this HTML to the W3C CCG, not the PDF or DOCX."

sponsor: $(PDF_OUT)/cg-report-executive-summary.pdf $(PDF_OUT)/vouch-sponsor-brief.pdf
	@echo ""
	@echo "Sponsor distribution bundle built:"
	@echo "  $(PDF_OUT)/cg-report-executive-summary.pdf"
	@echo "  $(PDF_OUT)/vouch-sponsor-brief.pdf"

# ---------- Output directories ----------
$(HTML_OUT) $(PDF_OUT) $(DOCX_OUT):
	mkdir -p $@

clean:
	rm -rf $(OUT)
