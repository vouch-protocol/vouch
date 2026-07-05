//! JSON facade for [`crate::threshold`] (FROST threshold signing).
//!
//! The threshold core works in typed Rust. This facade presents every step as
//! JSON-in / JSON-out with binary fields as standard base64 strings, matching
//! the convention the rest of the FFI-facing core uses (see
//! [`crate::robotics_json`]), so UniFFI, the C ABI, and WASM all share one
//! implementation instead of re-deriving the plumbing per language.

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};

use crate::error::{CoreError, Result};
use crate::threshold as t;

fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

fn unb64(s: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(s)
        .map_err(|e| CoreError::Json(format!("base64: {e}")))
}

fn parse(s: &str) -> Result<Value> {
    serde_json::from_str(s).map_err(|e| CoreError::Json(format!("json: {e}")))
}

fn gs(v: &Value, k: &str) -> Result<String> {
    v.get(k)
        .and_then(|x| x.as_str())
        .map(String::from)
        .ok_or_else(|| CoreError::Json(format!("missing or non-string field: {k}")))
}

fn key_share_to_json(share: &t::KeyShare) -> Value {
    json!({
        "identifier": b64(&share.identifier),
        "key_package": b64(&share.key_package),
    })
}

fn key_share_from_json(v: &Value) -> Result<t::KeyShare> {
    Ok(t::KeyShare {
        identifier: unb64(&gs(v, "identifier")?)?,
        key_package: unb64(&gs(v, "key_package")?)?,
    })
}

fn group_public_key_to_json(gpk: &t::GroupPublicKey) -> Value {
    json!({
        "verifying_key": b64(&gpk.verifying_key),
        "public_key_package": b64(&gpk.public_key_package),
    })
}

fn group_public_key_from_json(v: &Value) -> Result<t::GroupPublicKey> {
    let verifying_key_bytes = unb64(&gs(v, "verifying_key")?)?;
    let verifying_key: [u8; 32] = verifying_key_bytes
        .try_into()
        .map_err(|_| CoreError::Json("verifying_key must be 32 bytes".into()))?;
    Ok(t::GroupPublicKey {
        verifying_key,
        public_key_package: unb64(&gs(v, "public_key_package")?)?,
    })
}

/// A map keyed by base64-encoded participant identifier, valued by
/// base64-encoded bytes (a commitment or a signature share).
fn b64_map_from_json(v: &Value) -> Result<std::collections::BTreeMap<Vec<u8>, Vec<u8>>> {
    let obj = v
        .as_object()
        .ok_or_else(|| CoreError::Json("expected a JSON object".into()))?;
    let mut out = std::collections::BTreeMap::new();
    for (id_b64, val) in obj {
        let val_b64 = val
            .as_str()
            .ok_or_else(|| CoreError::Json(format!("value for {id_b64} must be a string")))?;
        out.insert(unb64(id_b64)?, unb64(val_b64)?);
    }
    Ok(out)
}

/// Mint a fresh threshold-native Ed25519 identity. Returns JSON:
/// `{"shares": [{"identifier": b64, "key_package": b64}, ...],
///   "group_public_key": {"verifying_key": b64, "public_key_package": b64}}`
pub fn generate_key(min_signers: u16, max_signers: u16) -> Result<String> {
    let result = t::generate_key(min_signers, max_signers)?;
    let out = json!({
        "shares": result.shares.iter().map(key_share_to_json).collect::<Vec<_>>(),
        "group_public_key": group_public_key_to_json(&result.group_public_key),
    });
    Ok(out.to_string())
}

/// Round 1 for one signer. `key_share_json` is one entry from `generate_key`'s
/// `shares` array. Returns JSON `{"nonces": b64, "commitments": b64}`. The
/// `nonces` field is SECRET: keep it only on this signer's device, use it for
/// exactly one `sign_share` call, then discard it.
pub fn commit(key_share_json: &str) -> Result<String> {
    let share = key_share_from_json(&parse(key_share_json)?)?;
    let round1 = t::commit(&share)?;
    let out = json!({
        "nonces": b64(&round1.nonces),
        "commitments": b64(&round1.commitments),
    });
    Ok(out.to_string())
}

/// Round 2 for one signer. `commitments_json` is a JSON object mapping each
/// participating signer's base64 identifier to its base64 commitment
/// (including this signer's own). Returns the base64-encoded signature share.
pub fn sign_share(
    message: &[u8],
    key_share_json: &str,
    nonces_b64: &str,
    commitments_json: &str,
) -> Result<String> {
    let share = key_share_from_json(&parse(key_share_json)?)?;
    let nonces = unb64(nonces_b64)?;
    let commitments = b64_map_from_json(&parse(commitments_json)?)?;
    let sig_share = t::sign_share(message, &share, &nonces, &commitments)?;
    Ok(b64(&sig_share))
}

/// Combine signature shares into the final signature. `commitments_json` and
/// `shares_json` are JSON objects mapping each signer's base64 identifier to
/// its base64 commitment / signature share respectively.
/// `group_public_key_json` is the `group_public_key` object from
/// `generate_key`. Returns the raw 64-byte Ed25519 signature, verifiable with
/// the same `verify` used for any other Vouch credential.
pub fn aggregate(
    message: &[u8],
    commitments_json: &str,
    shares_json: &str,
    group_public_key_json: &str,
) -> Result<Vec<u8>> {
    let commitments = b64_map_from_json(&parse(commitments_json)?)?;
    let shares = b64_map_from_json(&parse(shares_json)?)?;
    let group_public_key = group_public_key_from_json(&parse(group_public_key_json)?)?;
    let sig = t::aggregate(message, &commitments, &shares, &group_public_key)?;
    Ok(sig.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_ceremony_round_trips_through_json() {
        let generated_json = generate_key(2, 3).expect("generate_key");
        let generated: Value = serde_json::from_str(&generated_json).unwrap();
        let shares = generated["shares"].as_array().unwrap();
        assert_eq!(shares.len(), 3);

        let message = b"read did:web:files https://files/x";
        let chosen = [&shares[0], &shares[2]];

        let mut nonces_by_id = std::collections::HashMap::new();
        let mut commitments_obj = serde_json::Map::new();
        for share in &chosen {
            let round1_json = commit(&share.to_string()).expect("commit");
            let round1: Value = serde_json::from_str(&round1_json).unwrap();
            let id = share["identifier"].as_str().unwrap().to_string();
            commitments_obj.insert(id.clone(), round1["commitments"].clone());
            nonces_by_id.insert(id, round1["nonces"].as_str().unwrap().to_string());
        }
        let commitments_json = Value::Object(commitments_obj).to_string();

        let mut shares_obj = serde_json::Map::new();
        for share in &chosen {
            let id = share["identifier"].as_str().unwrap().to_string();
            let nonces_b64 = nonces_by_id.get(&id).unwrap();
            let sig_share_b64 =
                sign_share(message, &share.to_string(), nonces_b64, &commitments_json)
                    .expect("sign_share");
            shares_obj.insert(id, Value::String(sig_share_b64));
        }
        let shares_json = Value::Object(shares_obj).to_string();

        let group_public_key_json = generated["group_public_key"].to_string();
        let signature = aggregate(
            message,
            &commitments_json,
            &shares_json,
            &group_public_key_json,
        )
        .expect("aggregate");
        assert_eq!(signature.len(), 64);

        let gpk = group_public_key_from_json(&generated["group_public_key"]).unwrap();
        let ok = crate::keys::verify(&gpk.verifying_key, message, &signature).unwrap();
        assert!(ok);
    }

    #[test]
    fn generate_key_rejects_bad_threshold_through_json() {
        assert!(generate_key(1, 3).is_err());
    }
}
