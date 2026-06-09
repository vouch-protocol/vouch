#!/usr/bin/env bash
# Build the .vsix using Node 20. The vsce CLI's `undici` dependency
# requires Node >= 20 for the global File constructor.
set -euo pipefail
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"
nvm use 20 > /dev/null
echo "node: $(node --version)"
cd "$(dirname "$0")"
npx vsce package
