#!/bin/bash
#
# Vouch Sonic Core - Build and Binding Generation Script
#
# This script builds the Rust library for iOS and Android targets
# and generates Swift/Kotlin bindings using UniFFI.
#
# Prerequisites:
#   - Rust toolchain with cross-compilation targets
#   - Android NDK (for Android targets)
#   - Xcode (for iOS targets)
#
# Usage:
#   ./build.sh all          # Build everything
#   ./build.sh ios          # Build for iOS only
#   ./build.sh android      # Build for Android only
#   ./build.sh bindings     # Generate bindings only
#   ./build.sh test         # Run tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_step() {
    echo -e "${BLUE}==>${NC} $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}!${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# =============================================================================
# Configuration
# =============================================================================

# iOS targets
IOS_TARGETS=(
    "aarch64-apple-ios"           # iPhone/iPad (ARM64)
    "aarch64-apple-ios-sim"       # iOS Simulator (ARM64 - M1/M2 Macs)
    "x86_64-apple-ios"            # iOS Simulator (Intel Macs)
)

# Android targets
ANDROID_TARGETS=(
    "aarch64-linux-android"       # ARM64 (most modern phones)
    "armv7-linux-androideabi"     # ARM32 (older phones)
    "x86_64-linux-android"        # x86_64 emulator
    "i686-linux-android"          # x86 emulator
)

# Output directories
OUTPUT_DIR="$SCRIPT_DIR/target"
BINDINGS_DIR="$SCRIPT_DIR/generated"
IOS_OUTPUT="$BINDINGS_DIR/ios"
ANDROID_OUTPUT="$BINDINGS_DIR/android"

# =============================================================================
# Helper Functions
# =============================================================================

ensure_target() {
    local target=$1
    if ! rustup target list --installed | grep -q "$target"; then
        print_step "Installing Rust target: $target"
        rustup target add "$target"
    fi
}

check_android_ndk() {
    if [ -z "$ANDROID_NDK_HOME" ]; then
        print_warning "ANDROID_NDK_HOME not set. Android builds will be skipped."
        return 1
    fi
    return 0
}

# =============================================================================
# Build Commands
# =============================================================================

build_host() {
    print_step "Building for host (debug)"
    cargo build
    print_success "Host build complete"
}

build_host_release() {
    print_step "Building for host (release)"
    cargo build --release
    print_success "Host release build complete"
}

run_tests() {
    print_step "Running tests"
    cargo test -- --nocapture
    print_success "All tests passed"
}

build_ios() {
    print_step "Building for iOS targets"
    
    for target in "${IOS_TARGETS[@]}"; do
        ensure_target "$target"
        print_step "  Building $target"
        cargo build --release --target "$target"
    done
    
    print_success "iOS builds complete"
    
    # Create XCFramework
    create_xcframework
}

build_android() {
    if ! check_android_ndk; then
        return
    fi
    
    print_step "Building for Android targets"
    
    for target in "${ANDROID_TARGETS[@]}"; do
        ensure_target "$target"
        print_step "  Building $target"
        
        # Configure linker for Android
        case "$target" in
            aarch64-linux-android)
                export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android21-clang"
                ;;
            armv7-linux-androideabi)
                export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/armv7a-linux-androideabi21-clang"
                ;;
            x86_64-linux-android)
                export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/x86_64-linux-android21-clang"
                ;;
            i686-linux-android)
                export CARGO_TARGET_I686_LINUX_ANDROID_LINKER="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/i686-linux-android21-clang"
                ;;
        esac
        
        cargo build --release --target "$target"
    done
    
    print_success "Android builds complete"
    
    # Copy to JNI directories
    copy_android_libs
}

create_xcframework() {
    print_step "Creating XCFramework for iOS"
    
    mkdir -p "$IOS_OUTPUT"
    
    # Create fat library for simulators
    print_step "  Creating simulator fat library"
    
    local sim_libs=""
    for target in aarch64-apple-ios-sim x86_64-apple-ios; do
        local lib="$OUTPUT_DIR/$target/release/libvouch_sonic_core.a"
        if [ -f "$lib" ]; then
            sim_libs="$sim_libs $lib"
        fi
    done
    
    if [ -n "$sim_libs" ]; then
        lipo -create $sim_libs -output "$IOS_OUTPUT/libvouch_sonic_core_sim.a" 2>/dev/null || \
            cp "$OUTPUT_DIR/aarch64-apple-ios-sim/release/libvouch_sonic_core.a" "$IOS_OUTPUT/libvouch_sonic_core_sim.a"
    fi
    
    # Copy device library
    local device_lib="$OUTPUT_DIR/aarch64-apple-ios/release/libvouch_sonic_core.a"
    if [ -f "$device_lib" ]; then
        cp "$device_lib" "$IOS_OUTPUT/libvouch_sonic_core_device.a"
    fi
    
    print_success "XCFramework created at $IOS_OUTPUT"
}

copy_android_libs() {
    print_step "Copying Android libraries to JNI directories"
    
    mkdir -p "$ANDROID_OUTPUT/jniLibs/arm64-v8a"
    mkdir -p "$ANDROID_OUTPUT/jniLibs/armeabi-v7a"
    mkdir -p "$ANDROID_OUTPUT/jniLibs/x86_64"
    mkdir -p "$ANDROID_OUTPUT/jniLibs/x86"
    
    local mappings=(
        "aarch64-linux-android:arm64-v8a"
        "armv7-linux-androideabi:armeabi-v7a"
        "x86_64-linux-android:x86_64"
        "i686-linux-android:x86"
    )
    
    for mapping in "${mappings[@]}"; do
        local target="${mapping%%:*}"
        local abi="${mapping##*:}"
        local src="$OUTPUT_DIR/$target/release/libvouch_sonic_core.so"
        
        if [ -f "$src" ]; then
            cp "$src" "$ANDROID_OUTPUT/jniLibs/$abi/"
            print_success "  Copied to jniLibs/$abi"
        fi
    done
}

generate_bindings() {
    print_step "Generating Swift and Kotlin bindings"
    
    # Build for host first to create the library
    build_host_release
    
    mkdir -p "$IOS_OUTPUT/swift"
    mkdir -p "$ANDROID_OUTPUT/kotlin"
    
    # Determine library extension based on OS
    local lib_ext="so"
    if [[ "$OSTYPE" == "darwin"* ]]; then
        lib_ext="dylib"
    fi
    
    local lib_path="$OUTPUT_DIR/release/libvouch_sonic_core.$lib_ext"
    
    # Generate Swift bindings
    print_step "  Generating Swift bindings"
    cargo run --bin uniffi-bindgen -- generate \
        --library "$lib_path" \
        --language swift \
        --out-dir "$IOS_OUTPUT/swift" || {
            print_warning "Swift binding generation failed - trying alternative method"
            cargo run --bin uniffi-bindgen -- generate \
                "src/vouch_sonic_core.udl" \
                --language swift \
                --out-dir "$IOS_OUTPUT/swift"
        }
    
    # Generate Kotlin bindings
    print_step "  Generating Kotlin bindings"
    cargo run --bin uniffi-bindgen -- generate \
        --library "$lib_path" \
        --language kotlin \
        --out-dir "$ANDROID_OUTPUT/kotlin" || {
            print_warning "Kotlin binding generation failed - trying alternative method"
            cargo run --bin uniffi-bindgen -- generate \
                "src/vouch_sonic_core.udl" \
                --language kotlin \
                --out-dir "$ANDROID_OUTPUT/kotlin"
        }
    
    print_success "Bindings generated"
    echo ""
    echo "Swift bindings:  $IOS_OUTPUT/swift/"
    echo "Kotlin bindings: $ANDROID_OUTPUT/kotlin/"
}

clean() {
    print_step "Cleaning build artifacts"
    cargo clean
    rm -rf "$BINDINGS_DIR"
    print_success "Clean complete"
}

# =============================================================================
# Main
# =============================================================================

print_header() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║          Vouch Sonic Core - Build System                     ║"
    echo "║          Audio Watermark Detection for Mobile                ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
}

show_help() {
    echo "Usage: $0 <command>"
    echo ""
    echo "Commands:"
    echo "  all         Build for all targets and generate bindings"
    echo "  ios         Build for iOS targets only"
    echo "  android     Build for Android targets only"
    echo "  bindings    Generate Swift and Kotlin bindings"
    echo "  test        Run tests"
    echo "  clean       Remove build artifacts"
    echo "  help        Show this help message"
    echo ""
}

main() {
    print_header
    
    local command="${1:-help}"
    
    case "$command" in
        all)
            run_tests
            build_ios
            build_android
            generate_bindings
            ;;
        ios)
            build_ios
            generate_bindings
            ;;
        android)
            build_android
            generate_bindings
            ;;
        bindings)
            generate_bindings
            ;;
        test)
            run_tests
            ;;
        clean)
            clean
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            print_error "Unknown command: $command"
            show_help
            exit 1
            ;;
    esac
    
    echo ""
    print_success "Done!"
}

main "$@"
