#!/usr/bin/env bash
#
# Build the native core for the .NET SDK and place it under
# VouchCore/runtimes/<rid>/native so NuGet/the loader resolves it. Run once per
# target platform (Linux, macOS, Windows) to populate all RIDs.
#
set -euo pipefail
cd "$(dirname "$0")"
export PATH="$HOME/.cargo/bin:$PATH"

CORE="../../core/uniffi"
NAME="vouch_core_uniffi"

echo "==> building host native lib"
( cd "$CORE" && cargo build --release )

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)  RID="linux-x64";  EXT="so";    PRE="lib";;
  Linux-aarch64) RID="linux-arm64"; EXT="so";   PRE="lib";;
  Darwin-arm64)  RID="osx-arm64";  EXT="dylib"; PRE="lib";;
  Darwin-x86_64) RID="osx-x64";    EXT="dylib"; PRE="lib";;
  *) echo "unknown host; place the native library manually"; exit 0;;
esac

mkdir -p "VouchCore/runtimes/$RID/native"
cp "$CORE/target/release/${PRE}${NAME}.${EXT}" "VouchCore/runtimes/$RID/native/"
echo "==> placed ${PRE}${NAME}.${EXT} in runtimes/$RID/native"
echo "    (on Windows, build vouch_core_uniffi.dll and place it in runtimes/win-x64/native)"
echo "==> build + test:  dotnet test"
