//! Build script: generate UniFFI scaffolding from the UDL.
fn main() {
    uniffi::generate_scaffolding("src/vouch_core.udl")
        .expect("Failed to generate UniFFI scaffolding");
}
