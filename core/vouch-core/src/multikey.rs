//! Multikey encoding for verification methods.
//!
//! Byte-exact port of the TypeScript SDK `multikey.ts` and `vouch/multikey.py`.
//! A public key is encoded as `publicKeyMultibase = base58btc(multicodec_prefix
//! || raw_public_key_bytes)`, with a leading 'z' marking base58btc. Cross-
//! implementation interop with the other SDKs is REQUIRED.
//!
//! Supported algorithms:
//!   Ed25519     multicodec prefix 0xed01  (32-byte public key)
//!   ML-DSA-44   multicodec prefix 0x8724  (1312-byte public key, provisional)

use crate::error::{CoreError, Result};

/// Multicodec 2-byte prefixes.
pub const ED25519_PUB_PREFIX: [u8; 2] = [0xed, 0x01];
pub const ED25519_PRIV_PREFIX: [u8; 2] = [0x80, 0x26];
pub const MLDSA44_PUB_PREFIX: [u8; 2] = [0x87, 0x24];
pub const MLDSA44_PRIV_PREFIX: [u8; 2] = [0x88, 0x24];

const ED25519_PUBLIC_LEN: usize = 32;
const MLDSA44_PUBLIC_LEN: usize = 1312;

/// Maximum base58btc input length accepted by [`decode_base58_bounded`]. base58
/// decoding is O(n^2), so an unbounded input is a denial-of-service vector. The
/// largest legitimate value is a hybrid composite proofValue (about 3400 chars);
/// 8192 is a safe ceiling well above every real key, signature, and proofValue.
pub const MAX_BASE58_LEN: usize = 8192;

/// Decode base58btc with a length cap to bound the O(n^2) decode cost. Use this
/// for any externally-supplied base58 (proofValues, multikeys) instead of
/// calling `bs58::decode` directly.
pub fn decode_base58_bounded(s: &str) -> Result<Vec<u8>> {
    if s.len() > MAX_BASE58_LEN {
        return Err(CoreError::InvalidMultikey(format!(
            "base58 input too long: {} > {MAX_BASE58_LEN}",
            s.len()
        )));
    }
    bs58::decode(s)
        .into_vec()
        .map_err(|e| CoreError::InvalidMultikey(format!("bad base58: {e}")))
}

/// A multikey decoded into its algorithm name and raw key bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedKey {
    pub algorithm: String,
    pub raw_key: Vec<u8>,
}

fn encode_with_prefix(prefix: [u8; 2], raw: &[u8]) -> String {
    let mut buf = Vec::with_capacity(2 + raw.len());
    buf.extend_from_slice(&prefix);
    buf.extend_from_slice(raw);
    format!("z{}", bs58::encode(buf).into_string())
}

/// Encode a 32-byte Ed25519 public key as a Multikey string (z-prefixed base58btc).
pub fn encode_ed25519_public(raw: &[u8]) -> Result<String> {
    if raw.len() != ED25519_PUBLIC_LEN {
        return Err(CoreError::InvalidKeyLength {
            expected: ED25519_PUBLIC_LEN,
            got: raw.len(),
        });
    }
    Ok(encode_with_prefix(ED25519_PUB_PREFIX, raw))
}

/// Encode a 1312-byte ML-DSA-44 public key as a Multikey string (hybrid PQ profile).
pub fn encode_mldsa44_public(raw: &[u8]) -> Result<String> {
    if raw.len() != MLDSA44_PUBLIC_LEN {
        return Err(CoreError::InvalidKeyLength {
            expected: MLDSA44_PUBLIC_LEN,
            got: raw.len(),
        });
    }
    Ok(encode_with_prefix(MLDSA44_PUB_PREFIX, raw))
}

/// Decode a Multikey string into algorithm name plus raw key bytes.
pub fn decode(multikey: &str) -> Result<DecodedKey> {
    let body = multikey.strip_prefix('z').ok_or_else(|| {
        CoreError::InvalidMultikey("must use base58btc encoding (z-prefix)".into())
    })?;
    let decoded = decode_base58_bounded(body)?;
    if decoded.len() < 2 {
        return Err(CoreError::InvalidMultikey("too short".into()));
    }
    let prefix = [decoded[0], decoded[1]];
    let algorithm = match prefix {
        ED25519_PUB_PREFIX | ED25519_PRIV_PREFIX => "Ed25519",
        MLDSA44_PUB_PREFIX | MLDSA44_PRIV_PREFIX => "ML-DSA-44",
        _ => {
            return Err(CoreError::UnknownMulticodec(format!(
                "{:02x}{:02x}",
                prefix[0], prefix[1]
            )))
        }
    };
    Ok(DecodedKey {
        algorithm: algorithm.to_string(),
        raw_key: decoded[2..].to_vec(),
    })
}

/// Return the algorithm name encoded in a Multikey without exposing raw bytes.
pub fn algorithm_of(multikey: &str) -> Result<String> {
    Ok(decode(multikey)?.algorithm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_roundtrip() {
        let raw = [7u8; 32];
        let mk = encode_ed25519_public(&raw).unwrap();
        assert!(mk.starts_with('z'));
        let decoded = decode(&mk).unwrap();
        assert_eq!(decoded.algorithm, "Ed25519");
        assert_eq!(decoded.raw_key, raw);
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(encode_ed25519_public(&[0u8; 31]).is_err());
    }

    #[test]
    fn rejects_non_z_prefix() {
        assert!(decode("Qabc").is_err());
    }

    #[test]
    fn rejects_overlong_base58() {
        // Guards the O(n^2) base58 decode DoS.
        let overlong = "1".repeat(MAX_BASE58_LEN + 1);
        assert!(decode_base58_bounded(&overlong).is_err());
        assert!(decode(&format!("z{overlong}")).is_err());
    }
}
