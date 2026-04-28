#!/usr/bin/env bash
# Vouch Protocol — Specifications Build Script
#
# Generates HTML, PDF, and DOCX renderings of the three specification documents.
# Runs from Git Bash on Windows or any POSIX shell with pandoc installed.
#
# Requirements:
#   - pandoc          (winget install JohnMacFarlane.Pandoc)
#   - Google Chrome   (already installed on most workstations)
#
# Usage:
#   ./build.sh            # builds all three formats for all three docs
#   ./build.sh clean      # remove the build/ directory

set -euo pipefail

# ---- Resolve pandoc on Windows + Git Bash without manual PATH setup ----
if ! command -v pandoc >/dev/null 2>&1; then
  USER_NAME="${USER:-${USERNAME:-${LOGNAME:-rampy}}}"
  for candidate in \
    "/c/Users/$USER_NAME/AppData/Local/Pandoc/pandoc.exe" \
    "/c/Program Files/Pandoc/pandoc.exe" \
    "$HOME/AppData/Local/Pandoc/pandoc.exe"; do
    if [[ -x "$candidate" ]]; then
      export PATH="$(dirname "$candidate"):$PATH"
      break
    fi
  done
fi

if ! command -v pandoc >/dev/null 2>&1; then
  echo "ERROR: pandoc not found. Install with: winget install JohnMacFarlane.Pandoc" >&2
  exit 1
fi

# ---- Paths ----
SPECS_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SPECS_DIR/build"
HTML_DIR="$BUILD_DIR/html"
PDF_DIR="$BUILD_DIR/pdf"
DOCX_DIR="$BUILD_DIR/docx"

DOCS=(w3c-cg-report cg-report-executive-summary vouch-sponsor-brief sponsor-outreach-plan optum-internal-socialization-plan youtube-demo-plan)

if [[ "${1:-}" == "clean" ]]; then
  rm -rf "$BUILD_DIR"
  echo "Cleaned $BUILD_DIR"
  exit 0
fi

mkdir -p "$HTML_DIR" "$PDF_DIR" "$DOCX_DIR"

# ---- Locate Chrome for PDF rendering ----
CHROME=""
for c in \
  "/c/Program Files/Google/Chrome/Application/chrome.exe" \
  "/c/Program Files (x86)/Google/Chrome/Application/chrome.exe" \
  "/c/Program Files/Microsoft/Edge/Application/msedge.exe"; do
  if [[ -x "$c" ]]; then
    CHROME="$c"
    break
  fi
done

# ---- Build HTML and DOCX ----
for name in "${DOCS[@]}"; do
  src="$SPECS_DIR/$name.md"
  if [[ ! -f "$src" ]]; then
    echo "Skipping $name — source not found"
    continue
  fi
  pandoc --standalone --toc --toc-depth=3 --metadata=lang:en \
    -t html5 -o "$HTML_DIR/$name.html" "$src"
  echo "HTML  : $name.html"
  pandoc --standalone --metadata=lang:en \
    -o "$DOCX_DIR/$name.docx" "$src"
  echo "DOCX  : $name.docx"
done

# ---- Build PDF via Chrome headless (pandoc's xelatex path requires LaTeX, not assumed installed) ----
if [[ -z "$CHROME" ]]; then
  echo "WARN: Chrome/Edge not found — skipping PDF build."
  exit 0
fi

# Chrome refuses to write PDFs to UNC paths; stage in local TEMP, then copy.
TEMP_PDF_DIR="$(mktemp -d -t vouch-pdf-XXXXXX)"
trap 'rm -rf "$TEMP_PDF_DIR"' EXIT

for name in "${DOCS[@]}"; do
  html_file="$HTML_DIR/$name.html"
  if [[ ! -f "$html_file" ]]; then continue; fi

  # Convert WSL/UNC path to Windows file URI
  win_html=$(cygpath -w "$html_file" 2>/dev/null || echo "$html_file")
  temp_pdf="$TEMP_PDF_DIR/$name.pdf"

  "$CHROME" --headless=new --disable-gpu --no-pdf-header-footer \
    --print-to-pdf="$temp_pdf" \
    "file:///${win_html//\\//}" 2>/dev/null || true

  if [[ -f "$temp_pdf" ]]; then
    cp "$temp_pdf" "$PDF_DIR/$name.pdf"
    echo "PDF   : $name.pdf"
  else
    echo "FAILED: $name.pdf"
  fi
done

echo ""
echo "Done. Artifacts in $BUILD_DIR/{html,pdf,docx}"
echo ""
echo "  W3C submission           -> build/html/w3c-cg-report.html"
echo "  Sponsor distribution     -> build/pdf/cg-report-executive-summary.pdf"
echo "                              build/pdf/vouch-sponsor-brief.pdf"
echo "  Corporate legal review   -> build/docx/*.docx"
