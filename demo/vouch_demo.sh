#!/bin/bash
# Vouch Protocol Demo Script
# Run this with: bash demo/vouch_demo.sh
# Record with: asciinema rec demo.cast && asciinema upload demo.cast
# Or convert to GIF: agg demo.cast demo.gif

set -e
DEMO_DIR=$(mktemp -d)
cd "$DEMO_DIR"

# Colors
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║          ${GREEN}VOUCH PROTOCOL${CYAN} - AI Agent Identity Demo            ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
sleep 2

# Step 1: Create Identity
echo -e "${YELLOW}━━━ Step 1: Create Agent Identity ━━━${NC}"
echo ""
echo "$ vouch init --domain my-agent.example.com"
sleep 1

vouch init --domain my-agent.example.com --env > identity.env 2>&1
source identity.env

echo -e "${GREEN}✓ Generated DID: $VOUCH_DID${NC}"
echo -e "${GREEN}✓ Ed25519 keypair created${NC}"
echo ""
sleep 2

# Step 2: Sign an Action
echo -e "${YELLOW}━━━ Step 2: Sign an Agent Action ━━━${NC}"
echo ""
ACTION='{"tool": "read_database", "params": {"table": "users"}}'
echo "Agent wants to execute:"
echo -e "${CYAN}$ACTION${NC}"
echo ""
sleep 1
echo "$ vouch sign '\$ACTION' --json"
sleep 1

TOKEN=$(vouch sign "$ACTION" --json --key "$VOUCH_PRIVATE_KEY" --did "$VOUCH_DID")
echo ""
echo -e "${GREEN}✓ Signed JWT Token:${NC}"
echo "${TOKEN:0:80}..."
echo ""
sleep 2

# Step 3: Verify
echo -e "${YELLOW}━━━ Step 3: Verify the Signed Action ━━━${NC}"
echo ""
echo "$ vouch verify '\$TOKEN' --json"
sleep 1
echo ""
vouch verify "$TOKEN" --json
echo ""
sleep 1

echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✓ Cryptographic proof that THIS agent authorized THIS action${NC}"
echo -e "${GREEN}✓ No central authority needed - domain is the root of trust${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "🔗 GitHub: https://github.com/vouch-protocol/vouch"
echo ""

# Cleanup
rm -rf "$DEMO_DIR"
