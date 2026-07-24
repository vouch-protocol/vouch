//! Sign the shared interop credential and print the signed JSON, so an external
//! Data Integrity implementation can verify it.
use vouch_core::data_integrity::{sign, BuildProofOptions};

fn main() {
    let vector: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(std::env::args().nth(1).expect("vector path")).unwrap(),
    )
    .unwrap();

    let seed_b64 = vector["ed25519"]["seed_b64"].as_str().unwrap();
    let seed = base64_decode(seed_b64);
    let credential = vector["unsigned_credential"].clone();
    let vm = vector["verificationMethod"].as_str().unwrap();
    let created = vector["created"].as_str().unwrap();

    let signed = sign(&credential, &seed, &BuildProofOptions::new(vm, created)).unwrap();
    println!("{}", serde_json::to_string_pretty(&signed).unwrap());
}

fn base64_decode(s: &str) -> Vec<u8> {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0u32;
    for c in s.bytes() {
        if c == b'=' {
            break;
        }
        let v = match T.iter().position(|&t| t == c) {
            Some(v) => v as u32,
            None => continue,
        };
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    out
}
