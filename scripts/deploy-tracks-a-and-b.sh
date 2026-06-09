#!/usr/bin/env bash
# Track A: finish Fly Vouch Assistant deployment
#   - create persistent volume for SQLite interactions log
#   - set admin bearer token for /interactions read endpoint
#   - redeploy so the volume mount + token take effect
#   - smoke test
#
# Track B: deploy the Cloudflare email worker (ask@vouch-protocol.com)
#   - deploy the worker code
#   - prompt for Resend + Gemini API keys + forward inbox
#   - (You'll still need to wire ask@ -> worker in CF dashboard manually,
#      and verify your Resend domain. Script flags these.)
#
# Run from anywhere:  bash ~/vouch-protocol/scripts/deploy-tracks-a-and-b.sh
#
# Idempotent: each step checks current state before acting. Safe to re-run
# after a partial completion.

set -e

REPO="$HOME/vouch-protocol"

if [ -f "$HOME/.vouch/env" ]; then
  . "$HOME/.vouch/env"
fi

if [ -z "$CLOUDFLARE_API_TOKEN" ]; then
  echo "warn: CLOUDFLARE_API_TOKEN not set. Track B will require it for the worker deploy."
fi

echo
echo "==========================================================="
echo " Track A — Vouch Assistant on Fly.io (persistent log + token)"
echo "==========================================================="

cd "$REPO/website-agent/backend"

# 1. Create Fly volume (idempotent: list first, only create if missing)
if flyctl volumes list -a vouch-assistant 2>/dev/null | grep -q vouch_data; then
  echo "[A1/4] volume 'vouch_data' already exists, skipping"
else
  echo "[A1/4] creating volume 'vouch_data' (1 GB, bom)"
  flyctl volumes create vouch_data --region bom --size 1 --yes
fi

# 2. Admin token (idempotent: check existence first)
if flyctl secrets list -a vouch-assistant 2>/dev/null | grep -q VOUCH_ADMIN_TOKEN; then
  echo "[A2/4] secret VOUCH_ADMIN_TOKEN already set, skipping (use 'flyctl secrets unset' to rotate)"
else
  echo "[A2/4] generating + setting VOUCH_ADMIN_TOKEN"
  ADMIN_TOKEN=$(openssl rand -hex 32)
  flyctl secrets set VOUCH_ADMIN_TOKEN="$ADMIN_TOKEN" -a vouch-assistant
  echo
  echo "  >> SAVE THIS ADMIN TOKEN (printed once):"
  echo "  >> $ADMIN_TOKEN"
  echo
  # Append to vouch env file if it exists
  if [ -f "$HOME/.vouch/env" ]; then
    if ! grep -q VOUCH_ADMIN_TOKEN "$HOME/.vouch/env"; then
      echo "" >> "$HOME/.vouch/env"
      echo "# Bearer token for the /interactions admin endpoint on vouch-assistant.fly.dev" >> "$HOME/.vouch/env"
      echo "export VOUCH_ADMIN_TOKEN='$ADMIN_TOKEN'" >> "$HOME/.vouch/env"
      echo "  >> Also appended to ~/.vouch/env"
    fi
  fi
fi

# 3. Redeploy (picks up the new mount + new code in pyproject + secrets)
echo "[A3/4] deploying"
flyctl deploy -a vouch-assistant

# 4. Smoke test
echo "[A4/4] smoke-testing"
sleep 5
HEALTH=$(curl -s https://vouch-assistant.fly.dev/healthz)
echo "  healthz: $HEALTH"
echo
echo "Track A done. Next: try /chat to see end-to-end with persistent logging."

# ===========================================================

echo
echo "==========================================================="
echo " Track B — Cloudflare email worker (ask@vouch-protocol.com)"
echo "==========================================================="

cd "$REPO/cloudflare-email-worker"

# Check Resend setup before deploying — Track B is moot without it.
if [ -z "$RESEND_API_KEY" ]; then
  echo
  echo "  >> RESEND_API_KEY is not in your environment."
  echo "  >> If you haven't set up Resend yet:"
  echo "  >>   1. Sign up at https://resend.com"
  echo "  >>   2. Add domain vouch-protocol.com + verify DNS in Cloudflare"
  echo "  >>   3. Generate an API key with 'Sending Access' scope"
  echo "  >>   4. Save it: export RESEND_API_KEY=re_... and add to ~/.vouch/env"
  echo "  >> Then re-run this script."
  echo
  echo "Skipping Track B."
  exit 0
fi

if [ -z "$GEMINI_API_KEY" ]; then
  echo
  echo "  >> GEMINI_API_KEY not in env."
  echo "  >> Get one at https://aistudio.google.com/app/apikey and add to ~/.vouch/env."
  echo
  echo "Skipping Track B."
  exit 0
fi

# 1. Install deps
echo "[B1/4] installing worker dependencies"
npm install --no-audit --no-fund

# 2. Deploy worker
echo "[B2/4] deploying worker to Cloudflare"
npx wrangler deploy

# 3. Set secrets (idempotent — wrangler secret put overrides)
echo "[B3/4] setting secrets"
echo "$GEMINI_API_KEY" | npx wrangler secret put GEMINI_API_KEY
echo "$RESEND_API_KEY" | npx wrangler secret put RESEND_API_KEY
echo "ram@vouch-protocol.com" | npx wrangler secret put FORWARD_TO

# 4. Reminder for the manual step
echo "[B4/4] worker is deployed"
echo
echo "  >> Manual step (one-time, in CF dashboard):"
echo "  >> 1. Open https://dash.cloudflare.com -> vouch-protocol.com -> Email -> Email Routing -> Routes"
echo "  >> 2. Click 'Create address' under Custom addresses"
echo "  >> 3. Address: ask    Action: Send to a Worker    Destination: vouch-email-assistant"
echo "  >> 4. Save"
echo
echo "  >> Then tail and test:"
echo "  >>   cd ~/vouch-protocol/cloudflare-email-worker && npx wrangler tail vouch-email-assistant"
echo "  >>   (in another terminal/email client) send a test message to ask@vouch-protocol.com"
echo
echo "Track B done."

# ===========================================================

echo
echo "==========================================================="
echo " Both tracks complete (or skipped with reason above)."
echo "==========================================================="
