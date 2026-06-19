require 'json'

package = JSON.parse(File.read(File.join(__dir__, '..', 'package.json')))

Pod::Spec.new do |s|
  s.name           = 'VouchSonicCore'
  s.version        = package['version']
  s.summary        = package['description']
  s.description    = package['description']
  s.license        = 'Apache-2.0'
  s.author         = package['author']
  s.homepage       = 'https://vouch-protocol.com'
  s.platforms      = { :ios => '15.1', :tvos => '15.1' }
  s.swift_version  = '5.9'
  s.source         = { git: 'https://github.com/vouch-protocol/vouch.git' }
  s.static_framework = true

  s.dependency 'ExpoModulesCore'

  # The Expo module + the vendored UniFFI Swift bindings compile together.
  s.source_files   = '*.swift', 'uniffi/*.swift'
  # The C FFI header + modulemap (named `vouch_sonic_coreFFI`) must remain on
  # disk so the Swift bindings can `import vouch_sonic_coreFFI`. The Rust crate
  # source (vendored at ../rust) is built by the script phase below.
  s.preserve_paths = 'uniffi/*.h', 'uniffi/*.modulemap', '../rust/**/*'

  # ---------------------------------------------------------------------------
  # Build the Rust core to a per-config static library and link it.
  #
  # Runs on the build machine (locally or an EAS macOS worker). Requires the
  # Rust toolchain + cargo on PATH (add via an eas-build-pre-install hook in
  # the app, same as Android). Picks the target triple from Xcode's
  # PLATFORM_NAME / ARCHS so device and simulator both work.
  # ---------------------------------------------------------------------------
  s.script_phase = {
    :name => 'Build Vouch Sonic Rust core',
    :execution_position => :before_compile,
    :script => <<-SH
set -e
export PATH="$HOME/.cargo/bin:$PATH"
RUST_DIR="${PODS_TARGET_SRCROOT}/../rust"

if [ "$PLATFORM_NAME" = "iphonesimulator" ]; then
  if [ "$ARCHS" = "x86_64" ]; then TRIPLE="x86_64-apple-ios"; else TRIPLE="aarch64-apple-ios-sim"; fi
else
  TRIPLE="aarch64-apple-ios"
fi

echo "[vouch-sonic] building Rust core for $TRIPLE"
rustup target add "$TRIPLE" || true
( cd "$RUST_DIR" && cargo build --release --target "$TRIPLE" )
mkdir -p "$BUILT_PRODUCTS_DIR"
cp "$RUST_DIR/target/$TRIPLE/release/libvouch_sonic_core.a" "$BUILT_PRODUCTS_DIR/libvouch_sonic_core.a"
SH
  }

  s.pod_target_xcconfig = {
    'SWIFT_INCLUDE_PATHS' => '${PODS_TARGET_SRCROOT}/uniffi',
    'OTHER_LDFLAGS'       => '-L${BUILT_PRODUCTS_DIR} -lvouch_sonic_core',
    # The cdylib/staticlib needs the system libs UniFFI/std rely on.
    'OTHER_LDFLAGS[sdk=iphoneos*]' => '-L${BUILT_PRODUCTS_DIR} -lvouch_sonic_core',
  }
end
