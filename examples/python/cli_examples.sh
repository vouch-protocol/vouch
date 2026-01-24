#!/bin/bash
# ============================================================================
# Vouch CLI Examples
# ============================================================================
# 
# These examples show how to use the `vouch` command-line tool.
# Install with: pip install vouch-sdk
#
# The daemon must be running: vouch-bridge
# ============================================================================

# ----------------------------------------------------------------------------
# Check Status
# ----------------------------------------------------------------------------

# Check if daemon is running and show identity
vouch status

# ----------------------------------------------------------------------------
# Sign Files
# ----------------------------------------------------------------------------

# Sign a single file (overwrites original)
vouch sign document.pdf

# Sign a file and save to a different location
vouch sign photo.jpg --output photo_signed.jpg

# Sign code files
vouch sign main.py
vouch sign config.yaml

# ----------------------------------------------------------------------------
# Verify Files (works offline!)
# ----------------------------------------------------------------------------

# Verify a file has valid C2PA manifest
vouch verify photo_signed.jpg

# Verbose output shows full manifest details
vouch verify photo_signed.jpg --verbose

# ----------------------------------------------------------------------------
# Show Version
# ----------------------------------------------------------------------------

vouch version

# ----------------------------------------------------------------------------
# Batch Operations (using shell)
# ----------------------------------------------------------------------------

# Sign all Python files
for f in *.py; do
    vouch sign "$f" --output "signed/$f"
done

# Sign all images in a directory
for f in images/*.jpg; do
    vouch sign "$f"
done

# Verify all media files
for f in *.jpg *.png *.mp4 *.pdf; do
    echo "Checking: $f"
    vouch verify "$f" 2>/dev/null || echo "  ⚠️ Unsigned"
done

# ----------------------------------------------------------------------------
# Integration with other tools
# ----------------------------------------------------------------------------

# Sign a file and then upload (e.g., to S3)
vouch sign report.pdf --output report_signed.pdf
aws s3 cp report_signed.pdf s3://my-bucket/reports/

# Sign before committing to git
vouch sign important_code.py
git add important_code.py
git commit -m "Signed code update"

# Verify downloaded files
curl -O https://example.com/software.zip
vouch verify software.zip || echo "Warning: Unsigned download!"
