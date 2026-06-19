#!/usr/bin/env bash
#
# Build the VouchCore XCFramework from the canonical Rust core. Run on macOS
# (needs Xcode: xcodebuild + lipo) or in CI. Produces
# Frameworks/vouch_coreFFI.xcframework (iOS device + iOS simulator + macOS) and
# refreshes the vendored UniFFI Swift binding.
#
set -euo pipefail
cd "$(dirname "$0")"
export PATH="$HOME/.cargo/bin:$PATH"

CORE="../../core/uniffi"
NAME="vouch_core_uniffi"

echo "==> adding Apple Rust targets"
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios \
                  aarch64-apple-darwin x86_64-apple-darwin >/dev/null 2>&1 || true

echo "==> building static libs"
( cd "$CORE"
  for t in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios aarch64-apple-darwin x86_64-apple-darwin; do
    cargo build --release --target "$t"
  done
  echo "==> regenerating Swift binding"
  cargo run --release --bin uniffi-bindgen -- generate src/vouch_core.udl --language swift --out-dir generated/swift
)

echo "==> refreshing vendored binding + headers"
cp "$CORE/generated/swift/vouch_core.swift" Sources/VouchCore/vouch_core.swift
cp "$CORE/generated/swift/vouch_coreFFI.h" ffi/vouch_coreFFI.h
cp "$CORE/generated/swift/vouch_coreFFI.modulemap" ffi/module.modulemap

echo "==> fat libs for simulator + macOS"
mkdir -p build/ios-sim build/macos build/headers
lipo -create "$CORE/target/aarch64-apple-ios-sim/release/lib$NAME.a" \
             "$CORE/target/x86_64-apple-ios/release/lib$NAME.a" \
     -output build/ios-sim/lib$NAME.a
lipo -create "$CORE/target/aarch64-apple-darwin/release/lib$NAME.a" \
             "$CORE/target/x86_64-apple-darwin/release/lib$NAME.a" \
     -output build/macos/lib$NAME.a

cp ffi/vouch_coreFFI.h build/headers/
cp ffi/module.modulemap build/headers/module.modulemap

echo "==> assembling XCFramework"
rm -rf Frameworks/vouch_coreFFI.xcframework
xcodebuild -create-xcframework \
  -library "$CORE/target/aarch64-apple-ios/release/lib$NAME.a" -headers build/headers \
  -library build/ios-sim/lib$NAME.a -headers build/headers \
  -library build/macos/lib$NAME.a -headers build/headers \
  -output Frameworks/vouch_coreFFI.xcframework

echo "==> done: Frameworks/vouch_coreFFI.xcframework"
echo "    Run tests with:  swift test"
