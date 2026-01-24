//! UniFFI Bindgen CLI binary
//!
//! This is used to generate Swift and Kotlin bindings from the command line.
//! Run: cargo run --bin uniffi-bindgen -- generate --library target/release/libvouch_sonic_core.dylib --language swift --out-dir ./generated/swift

fn main() {
    uniffi::uniffi_bindgen_main()
}
