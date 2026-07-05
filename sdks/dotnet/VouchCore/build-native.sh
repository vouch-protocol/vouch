#!/usr/bin/env bash
#
# Build the native core (core/uniffi) for one runtime identifier and place it
# under runtimes/<rid>/native/ so `dotnet pack` bundles it. NuGet then resolves
# the right binary per RID at consume time, and the P/Invoke in Vouch.cs
# (DllImport "vouch_core_uniffi") finds it.
#
# Usage: build-native.sh [rid]
#   With no argument it builds for the host. Pass a RID to cross-compile, e.g.
#   `build-native.sh osx-x64` on an arm64 mac. Supported RIDs: linux-x64,
#   osx-arm64, osx-x64, win-x64.
#
set -euo pipefail
cd "$(dirname "$0")"
export PATH="$HOME/.cargo/bin:$PATH"

CORE="../../../core/uniffi"
NAME="vouch_core_uniffi"
RID="${1:-}"

if [ -z "$RID" ]; then
  case "$(uname -s)-$(uname -m)" in
    Linux-x86_64)                              RID="linux-x64";;
    Darwin-arm64)                              RID="osx-arm64";;
    Darwin-x86_64)                             RID="osx-x64";;
    MINGW*-x86_64|MSYS*-x86_64|CYGWIN*-x86_64) RID="win-x64";;
    *) echo "unsupported host: $(uname -s)-$(uname -m)"; exit 1;;
  esac
fi

case "$RID" in
  linux-x64) TARGET="x86_64-unknown-linux-gnu"; LIB="lib$NAME.so";;
  osx-arm64) TARGET="aarch64-apple-darwin";     LIB="lib$NAME.dylib";;
  osx-x64)   TARGET="x86_64-apple-darwin";       LIB="lib$NAME.dylib";;
  win-x64)   TARGET="x86_64-pc-windows-msvc";    LIB="$NAME.dll";;
  *) echo "unsupported rid: $RID"; exit 1;;
esac

rustup target add "$TARGET" >/dev/null 2>&1 || true

echo "==> building $NAME for $RID ($TARGET)"
( cd "$CORE" && cargo build --release --target "$TARGET" )

mkdir -p "runtimes/$RID/native"
cp "$CORE/target/$TARGET/release/$LIB" "runtimes/$RID/native/$LIB"
echo "==> placed runtimes/$RID/native/$LIB"
