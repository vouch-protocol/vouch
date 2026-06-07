#!/usr/bin/env bash
#
# Build the native core for the JVM SDK: the host platform (desktop JVM) and,
# optionally, Android ABIs via cargo-ndk. The host library is placed both in
# lib/ (for tests) and in src/main/resources/<jna-platform>/ (bundled in the jar
# so JNA finds it on the classpath). Also refreshes the UniFFI Kotlin binding.
#
set -euo pipefail
cd "$(dirname "$0")"
export PATH="$HOME/.cargo/bin:$PATH"

CORE="../../core/uniffi"
NAME="vouch_core_uniffi"

echo "==> building host native lib"
( cd "$CORE" && cargo build --release )

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)  JNA="linux-x86-64";  EXT="so";;
  Linux-aarch64) JNA="linux-aarch64"; EXT="so";;
  Darwin-arm64)  JNA="darwin-aarch64"; EXT="dylib";;
  Darwin-x86_64) JNA="darwin-x86-64";  EXT="dylib";;
  *) echo "unknown host; place the library manually"; JNA="unknown"; EXT="so";;
esac

mkdir -p lib "src/main/resources/$JNA"
cp "$CORE/target/release/lib$NAME.$EXT" "lib/"
cp "$CORE/target/release/lib$NAME.$EXT" "src/main/resources/$JNA/"

echo "==> refreshing UniFFI Kotlin binding"
( cd "$CORE" && cargo run -q --release --bin uniffi-bindgen -- generate src/vouch_core.udl --language kotlin --out-dir generated/kotlin )
cp "$CORE/generated/kotlin/uniffi/vouch_core/vouch_core.kt" src/main/kotlin/vouch_core.kt

cat <<'NOTE'
==> done (host).

For Android, build per-ABI shared libraries with cargo-ndk and place them under
src/main/jniLibs/<abi>/ :

  cargo install cargo-ndk
  rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android
  (cd ../../core/uniffi && cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -t x86 \
       -o ../../sdks/jvm/src/main/jniLibs build --release)

Build + test the JVM SDK with:  gradle test
NOTE
