//! BitstringStatusList revocation/suspension checks.
//!
//! Port of the TypeScript `status-list.ts` (W3C VC-BITSTRING-STATUS-LIST). The
//! bitstring is GZIP-compressed and multibase base64url-no-pad encoded (prefix
//! 'u'). Bit `i` lives at byte `i >> 3`, position `7 - (i % 8)` (MSB first).
//!
//! The core's job is verification: decode a published status list and report
//! whether a credential's bit is set (revoked/suspended). Encoding is provided
//! for issuers; decoding (gunzip) is deterministic regardless of the compressor,
//! so verification interoperates with lists produced by any SDK.

use std::io::{Read, Write};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde_json::Value;

use crate::error::{CoreError, Result};

pub const DEFAULT_BITSTRING_LENGTH: usize = 131_072;
pub const MULTIBASE_BASE64URL_PREFIX: char = 'u';

/// Maximum decompressed bitstring size. The protocol minimum is 16 KiB (131072
/// bits); this 16 MiB ceiling (over 134 million entries) is far above any real
/// list while preventing a gzip-bomb denial of service from an attacker-supplied
/// `encodedList` that expands to gigabytes.
pub const MAX_DECOMPRESSED_BYTES: usize = 16 * 1024 * 1024;

pub const STATUS_PURPOSE_REVOCATION: &str = "revocation";
pub const BITSTRING_STATUS_LIST_CREDENTIAL_TYPE: &str = "BitstringStatusListCredential";
pub const BITSTRING_STATUS_LIST_SUBJECT_TYPE: &str = "BitstringStatusList";
pub const BITSTRING_STATUS_LIST_ENTRY_TYPE: &str = "BitstringStatusListEntry";

/// Decode a multibase-encoded, GZIP-compressed bitstring into raw bytes.
pub fn decode_bitstring(encoded: &str) -> Result<Vec<u8>> {
    let body = encoded
        .strip_prefix(MULTIBASE_BASE64URL_PREFIX)
        .ok_or_else(|| CoreError::Json("encodedList must use multibase prefix 'u'".into()))?;
    let compressed = URL_SAFE_NO_PAD
        .decode(body)
        .map_err(|e| CoreError::Json(format!("bad base64url: {e}")))?;
    let gz = GzDecoder::new(&compressed[..]);
    let mut out = Vec::new();
    // Cap decompression to defend against a gzip bomb. Reading one byte past the
    // ceiling lets us distinguish "exactly at the cap" from "overflowed".
    let mut limited = gz.take(MAX_DECOMPRESSED_BYTES as u64 + 1);
    limited
        .read_to_end(&mut out)
        .map_err(|e| CoreError::Json(format!("gunzip failed: {e}")))?;
    if out.len() > MAX_DECOMPRESSED_BYTES {
        return Err(CoreError::Json(format!(
            "decompressed status list exceeds the {MAX_DECOMPRESSED_BYTES}-byte limit"
        )));
    }
    Ok(out)
}

/// Encode a raw bitstring to the multibase GZIP form (issuer side). The gzip
/// header MTIME is zeroed and OS byte set to 0xff for deterministic output.
///
/// NOTE: the pure-Rust DEFLATE backend does not produce byte-identical
/// compressed output to zlib (Python/Node/Go), so the encoded string may differ
/// from those SDKs even though it decodes to the same bits. Verification is
/// unaffected (gunzip is deterministic). Issuers needing byte-identical output
/// across SDKs should build with a zlib-backed flate2 feature.
pub fn encode_bitstring(bits: &[u8]) -> Result<String> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::new(9));
    encoder
        .write_all(bits)
        .map_err(|e| CoreError::Json(format!("gzip failed: {e}")))?;
    let mut compressed = encoder
        .finish()
        .map_err(|e| CoreError::Json(format!("gzip finish failed: {e}")))?;
    if compressed.len() >= 10 {
        compressed[4] = 0;
        compressed[5] = 0;
        compressed[6] = 0;
        compressed[7] = 0;
        compressed[9] = 0xff;
    }
    Ok(format!(
        "{}{}",
        MULTIBASE_BASE64URL_PREFIX,
        URL_SAFE_NO_PAD.encode(compressed)
    ))
}

/// Read bit `index` from a raw bitstring.
pub fn get_status(bits: &[u8], index: usize) -> Result<bool> {
    let byte = index >> 3;
    if byte >= bits.len() {
        return Err(CoreError::Json(format!(
            "index {index} out of range for {}-bit list",
            bits.len() * 8
        )));
    }
    let pos = 7 - (index % 8);
    Ok(bits[byte] & (1 << pos) != 0)
}

/// Set bit `index` in a raw bitstring (issuer side).
pub fn set_status(bits: &mut [u8], index: usize, value: bool) -> Result<()> {
    let byte = index >> 3;
    if byte >= bits.len() {
        return Err(CoreError::Json(format!("index {index} out of range")));
    }
    let pos = 7 - (index % 8);
    if value {
        bits[byte] |= 1 << pos;
    } else {
        bits[byte] &= !(1 << pos);
    }
    Ok(())
}

/// Verify a credential's status against a fetched BitstringStatusListCredential.
/// Returns Ok(true) if the referenced bit is set (revoked/suspended). The caller
/// MUST verify the Data Integrity proof on `status_list_credential` first.
pub fn verify_status(credential_status: &Value, status_list_credential: &Value) -> Result<bool> {
    let cs = credential_status
        .as_object()
        .ok_or_else(|| CoreError::Json("credentialStatus must be an object".into()))?;
    let sl = status_list_credential
        .as_object()
        .ok_or_else(|| CoreError::Json("statusListCredential must be an object".into()))?;

    if cs.get("type").and_then(|v| v.as_str()) != Some(BITSTRING_STATUS_LIST_ENTRY_TYPE) {
        return Err(CoreError::Json(format!(
            "credentialStatus.type must be {BITSTRING_STATUS_LIST_ENTRY_TYPE}"
        )));
    }
    let referenced = cs
        .get("statusListCredential")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            CoreError::Json("credentialStatus.statusListCredential is required".into())
        })?;
    let actual_id = sl.get("id").and_then(|v| v.as_str()).unwrap_or_default();
    if actual_id != referenced {
        return Err(CoreError::Json(format!(
            "status list id mismatch: references {referenced}, fetched {actual_id}"
        )));
    }
    let has_type = sl
        .get("type")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .any(|t| t.as_str() == Some(BITSTRING_STATUS_LIST_CREDENTIAL_TYPE))
        })
        .unwrap_or(false);
    if !has_type {
        return Err(CoreError::Json(format!(
            "fetched credential is not a {BITSTRING_STATUS_LIST_CREDENTIAL_TYPE}"
        )));
    }
    let subject = sl
        .get("credentialSubject")
        .and_then(|v| v.as_object())
        .ok_or_else(|| CoreError::Json("status list has no credentialSubject".into()))?;
    if subject.get("type").and_then(|v| v.as_str()) != Some(BITSTRING_STATUS_LIST_SUBJECT_TYPE) {
        return Err(CoreError::Json(format!(
            "credentialSubject.type must be {BITSTRING_STATUS_LIST_SUBJECT_TYPE}"
        )));
    }
    if cs.get("statusPurpose").and_then(|v| v.as_str())
        != subject.get("statusPurpose").and_then(|v| v.as_str())
    {
        return Err(CoreError::Json("statusPurpose mismatch".into()));
    }
    let encoded = subject
        .get("encodedList")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CoreError::Json("credentialSubject.encodedList is required".into()))?;

    // statusListIndex may be a string ("100") or a number.
    let index = match cs.get("statusListIndex") {
        Some(Value::String(s)) => s
            .parse::<usize>()
            .map_err(|_| CoreError::Json(format!("bad statusListIndex: {s:?}")))?,
        Some(Value::Number(n)) => n
            .as_u64()
            .ok_or_else(|| CoreError::Json("statusListIndex must be non-negative".into()))?
            as usize,
        _ => {
            return Err(CoreError::Json(
                "credentialStatus.statusListIndex is required".into(),
            ))
        }
    };

    let bits = decode_bitstring(encoded)?;
    get_status(&bits, index)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_encoded_list_errors_gracefully() {
        assert!(decode_bitstring("not-multibase").is_err()); // missing 'u' prefix
        assert!(decode_bitstring("uNotValidGzipData").is_err()); // bad gzip stream
    }

    #[test]
    fn encode_decode_roundtrip_preserves_bits() {
        let mut bits = vec![0u8; DEFAULT_BITSTRING_LENGTH / 8];
        for &i in &[0usize, 1, 7, 8, 15, 100, 1023, 65535, 131070, 131071] {
            set_status(&mut bits, i, true).unwrap();
        }
        let encoded = encode_bitstring(&bits).unwrap();
        let decoded = decode_bitstring(&encoded).unwrap();
        assert_eq!(decoded, bits);
        assert!(get_status(&decoded, 100).unwrap());
        assert!(!get_status(&decoded, 99).unwrap());
    }
}
