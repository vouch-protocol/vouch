#!/usr/bin/env bash
# Three-step end-to-end publish of paper-1 with the new personal DID.
# Run from the repo root: bash papers/paper-1-vouch-protocol/run-publish.sh
#
# Each step is gated by `read -r -p` so you can abort between them.

set -e

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

# Pull vouch secrets (CLOUDFLARE_API_TOKEN, etc) from the canonical env file.
# This works under non-interactive bash too, unlike sourcing ~/.bashrc which
# returns early on Ubuntu before the export lines run.
if [ -f "$HOME/.vouch/env" ]; then
  . "$HOME/.vouch/env"
fi

if [ -z "$CLOUDFLARE_API_TOKEN" ]; then
  echo "error: CLOUDFLARE_API_TOKEN not set. Put your token in ~/.vouch/env"
  echo "       (export CLOUDFLARE_API_TOKEN='cfut_...' on a single line)."
  exit 1
fi

echo "Repo:   $REPO_ROOT"
echo "Token:  set, length=${#CLOUDFLARE_API_TOKEN}"
echo

# ---------------------------------------------------------------------------
echo "Step 1/3 — Deploy the worker (new Option B template + bug fix)"
echo "---------------------------------------------------------------------"
read -r -p "Press Enter to deploy, or Ctrl-C to abort: " _
( cd cloudflare-worker && npx wrangler deploy )
echo

# ---------------------------------------------------------------------------
echo "Step 2/3 — Remove the old paper:arxiv-1 record so we can replace it"
echo "---------------------------------------------------------------------"
echo "    (deletes paper:arxiv-1 and the stale paper:arxiv-1<space>)"
read -r -p "Press Enter to delete, or Ctrl-C to abort: " _
( cd cloudflare-worker && \
  npx wrangler kv key delete --namespace-id 08413c23ad6147b78d406ba31f52ba1e "paper:arxiv-1" || true )
( cd cloudflare-worker && \
  npx wrangler kv key delete --namespace-id 08413c23ad6147b78d406ba31f52ba1e "paper:arxiv-1 " || true )
echo

# ---------------------------------------------------------------------------
echo "Step 3/3 — Re-publish paper-1 with did:web:vouch-protocol.com:u:rampy"
echo "---------------------------------------------------------------------"
read -r -p "Press Enter to publish, or Ctrl-C to abort: " _
source ~/venvvouch/bin/activate
python papers/paper-1-vouch-protocol/sign-and-publish.py --publish
echo

echo "Done. Verify: https://vch.sh/arxiv-1  →  https://vouch-protocol.com/v/arxiv-1"
