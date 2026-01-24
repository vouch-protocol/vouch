//! Build script for UniFFI binding generation

fn main() {
    // Generate UniFFI scaffolding from the UDL file
    uniffi::generate_scaffolding("src/vouch_sonic_core.udl")
        .expect("Failed to generate UniFFI scaffolding");
}
