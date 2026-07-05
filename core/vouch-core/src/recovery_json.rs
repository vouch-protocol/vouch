//! JSON facade for [`crate::recovery`] (Shamir root-identity recovery).
//!
//! Presents the recovery core as JSON-in / JSON-out with binary fields as
//! standard base64 strings, matching the convention the rest of the
//! FFI-facing core uses (see [`crate::threshold_json`]), so UniFFI, the C
//! ABI, and WASM all share one implementation instead of re-deriving the
//! plumbing per language.

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};

use crate::error::{CoreError, Result};
use crate::recovery as r;

fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

fn unb64(s: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(s)
        .map_err(|e| CoreError::Json(format!("base64: {e}")))
}

fn shares_from_json(shares_json: &str) -> Result<Vec<Vec<u8>>> {
    let v: Value =
        serde_json::from_str(shares_json).map_err(|e| CoreError::Json(format!("json: {e}")))?;
    let arr = v
        .as_array()
        .ok_or_else(|| CoreError::Json("expected a JSON array of base64 shares".into()))?;
    arr.iter()
        .map(|item| {
            item.as_str()
                .ok_or_else(|| CoreError::Json("each share must be a base64 string".into()))
                .and_then(unb64)
        })
        .collect()
}

fn shares_to_json(shares: &[Vec<u8>]) -> String {
    json!(shares.iter().map(|s| b64(s)).collect::<Vec<_>>()).to_string()
}

/// Splits `secret_b64` (a base64-encoded byte string) into `shares` pieces;
/// any `threshold` of them reconstruct it. Returns a JSON array of
/// base64-encoded shares.
pub fn split_secret(secret_b64: &str, threshold: u16, shares: u16) -> Result<String> {
    let secret = unb64(secret_b64)?;
    let out = r::split_secret(&secret, threshold, shares)?;
    Ok(shares_to_json(&out))
}

/// Reconstructs a secret from a JSON array of base64-encoded shares. Returns
/// the base64-encoded secret.
pub fn combine_shares(shares_json: &str) -> Result<String> {
    let shares = shares_from_json(shares_json)?;
    let secret = r::combine_shares(&shares)?;
    Ok(b64(&secret))
}

/// Splits a root identity's base64-encoded Ed25519 seed into recovery shares.
/// Returns a JSON array of base64-encoded shares.
pub fn split_identity(seed_b64: &str, threshold: u16, shares: u16) -> Result<String> {
    let seed = unb64(seed_b64)?;
    let out = r::split_identity(&seed, threshold, shares)?;
    Ok(shares_to_json(&out))
}

/// Recovers a root identity from a JSON array of base64-encoded recovery
/// shares. Pass `did` (or an empty string) to set it on the result; an empty
/// string derives a did:key from the recovered public key instead. Returns
/// JSON `{"did": string, "seed": b64, "public_key": b64}`.
pub fn recover_identity(shares_json: &str, did: &str) -> Result<String> {
    let shares = shares_from_json(shares_json)?;
    let did_opt = if did.is_empty() { None } else { Some(did) };
    let recovered = r::recover_identity(&shares, did_opt)?;
    let out = json!({
        "did": recovered.did,
        "seed": b64(&recovered.seed),
        "public_key": b64(&recovered.public_key),
    });
    Ok(out.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};

    #[test]
    fn split_and_combine_round_trips_through_json() {
        let secret = [5u8; 32];
        let secret_b64 = STANDARD.encode(secret);
        let shares_json = split_secret(&secret_b64, 3, 5).unwrap();
        let shares: Vec<String> = serde_json::from_str(&shares_json).unwrap();
        assert_eq!(shares.len(), 5);

        let subset = json!([shares[0], shares[2], shares[4]]).to_string();
        let combined_b64 = combine_shares(&subset).unwrap();
        assert_eq!(combined_b64, secret_b64);
    }

    #[test]
    fn split_and_recover_identity_round_trips_through_json() {
        let keypair = crate::keys::Ed25519KeyPair::generate().unwrap();
        let seed_b64 = STANDARD.encode(keypair.seed());
        let did = keypair.did_key();

        let shares_json = split_identity(&seed_b64, 2, 3).unwrap();
        let shares: Vec<String> = serde_json::from_str(&shares_json).unwrap();
        let subset = json!([shares[0], shares[1]]).to_string();

        let recovered_json = recover_identity(&subset, &did).unwrap();
        let recovered: Value = serde_json::from_str(&recovered_json).unwrap();
        assert_eq!(recovered["did"], did);
        assert_eq!(recovered["seed"], seed_b64);
    }
}
