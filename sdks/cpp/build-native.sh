#!/usr/bin/env bash
#
# Refresh the prebuilt C bindings (shared + static library + header) from the
# canonical Rust core. The shared library (.so/.dylib/.dll) is the normal target;
# the static library (.a, around 50 MB) is produced for those who want to link
# statically and is not committed.
#
set -euo pipefail
cd "$(dirname "$0")"
export PATH="$HOME/.cargo/bin:$PATH"

CORE="../../core/uniffi"
NAME="vouch_core_uniffi"

echo "==> building the core"
( cd "$CORE" && cargo build --release )

case "$(uname -s)" in
  Linux)  SO="lib${NAME}.so";;
  Darwin) SO="lib${NAME}.dylib";;
  *)      SO="lib${NAME}.so";;
esac

cp "$CORE/target/release/$SO" "lib/$SO"
[ -f "$CORE/target/release/lib${NAME}.a" ] && cp "$CORE/target/release/lib${NAME}.a" "lib/" || true
cp "$CORE/generated/c/vouch_core.h" include/vouch_core.h

echo "==> done. Build + run the example:  (cd examples && make run)"
