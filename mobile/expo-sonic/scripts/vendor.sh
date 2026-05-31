#!/usr/bin/env bash
#
# Vendor the derived inputs from ../core into this package so it is
# self-contained for an Android (cargo-ndk) build / npm publish:
#   - UniFFI-generated Kotlin bindings -> android/src/main/java/uniffi/
#   - Rust crate source                -> rust/
#
# These are git-ignored (regenerated, not source-of-truth). Run before
# `expo-module build` / `npm publish`, or from an EAS pre-install hook.
#
set -e
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORE="$(cd "$HERE/../core" && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"

echo "==> regenerating UniFFI Kotlin bindings"
( cd "$CORE" && cargo build --release \
  && cargo run -q --release --bin uniffi-bindgen -- generate \
       src/vouch_sonic_core.udl --language kotlin --out-dir generated/kotlin )

echo "==> vendoring Kotlin bindings"
rm -rf "$HERE/android/src/main/java/uniffi"
mkdir -p "$HERE/android/src/main/java/uniffi"
cp -r "$CORE/generated/kotlin/uniffi/." "$HERE/android/src/main/java/uniffi/"

echo "==> vendoring Rust crate source"
rm -rf "$HERE/rust"
mkdir -p "$HERE/rust/src"
cp "$CORE/Cargo.toml" "$HERE/rust/Cargo.toml"
cp "$CORE/build.rs" "$HERE/rust/build.rs"
cp "$CORE/uniffi-bindgen.rs" "$HERE/rust/uniffi-bindgen.rs"
cp "$CORE/src/lib.rs" "$HERE/rust/src/lib.rs"
cp "$CORE/src/vouch_sonic_core.udl" "$HERE/rust/src/vouch_sonic_core.udl"

echo "==> done"
