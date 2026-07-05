#!/usr/bin/env bash
#
# Build the native core needed for FROST threshold signing (the "frost" build
# tag) and place it under lib/, where signer/threshold.go's cgo directive
# looks for it. Everything else in this module is pure Go and does not need
# this script.
#
set -euo pipefail
cd "$(dirname "$0")"
export PATH="$HOME/.cargo/bin:$PATH"

CORE="../core/uniffi"
NAME="vouch_core_uniffi"

echo "==> building the core"
( cd "$CORE" && cargo build --release )

case "$(uname -s)" in
  Linux)  SO="lib${NAME}.so";;
  Darwin) SO="lib${NAME}.dylib";;
  *)      SO="lib${NAME}.so";;
esac

mkdir -p lib
cp "$CORE/target/release/$SO" "lib/$SO"

echo "==> done. Build/test with FROST:  go build -tags frost ./... && go test -tags frost ./..."
echo "    (on Linux, set LD_LIBRARY_PATH=\$(pwd)/lib to run/test)"
