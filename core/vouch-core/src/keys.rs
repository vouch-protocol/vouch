//! Ed25519 key generation, signing, verification, and did:key encoding.
//!
//! Matches the TypeScript reference SDK: the same seed produces the same public
//! key, the same message produces the same 64-byte signature, and did:key uses
//! the Ed25519 multikey (`did:key:z6Mk...`). Interop is asserted against the
//! shared vectors (a seed -> public-key known-answer test).

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::error::{CoreError, Result};
use crate::multikey;

pub const ED25519_SEED_LEN: usize = 32;
pub const ED25519_PUBLIC_LEN: usize = 32;
pub const ED25519_SIGNATURE_LEN: usize = 64;

/// An Ed25519 key pair. The 32-byte seed is the private key (RFC 8032).
pub struct Ed25519KeyPair {
    signing: SigningKey,
}

impl Ed25519KeyPair {
    /// Generate a fresh key pair using the platform CSPRNG (getrandom; on WASM
    /// this is the JS crypto API via the getrandom "js" feature in the wasm
    /// wrapper crate).
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; ED25519_SEED_LEN];
        getrandom::getrandom(&mut seed)
            .map_err(|e| CoreError::Crypto(format!("rng: {e}")))?;
        Ok(Self::from_seed(&seed))
    }

    /// Build a key pair from a 32-byte seed (deterministic; used for KATs and
    /// for importing an existing private key).
    pub fn from_seed(seed: &[u8; ED25519_SEED_LEN]) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed),
        }
    }

    /// Build a key pair from a seed slice, validating its length.
    pub fn from_seed_slice(seed: &[u8]) -> Result<Self> {
        let arr: [u8; ED25519_SEED_LEN] = seed.try_into().map_err(|_| {
            CoreError::InvalidKeyLength {
                expected: ED25519_SEED_LEN,
                got: seed.len(),
            }
        })?;
        Ok(Self::from_seed(&arr))
    }

    /// The 32-byte private seed.
    pub fn seed(&self) -> [u8; ED25519_SEED_LEN] {
        self.signing.to_bytes()
    }

    /// The 32-byte public key.
    pub fn public_key(&self) -> [u8; ED25519_PUBLIC_LEN] {
        self.signing.verifying_key().to_bytes()
    }

    /// Sign a message, returning the 64-byte signature.
    pub fn sign(&self, message: &[u8]) -> [u8; ED25519_SIGNATURE_LEN] {
        self.signing.sign(message).to_bytes()
    }

    /// The public key as a Multikey string (z-prefixed base58btc).
    pub fn public_multikey(&self) -> String {
        multikey::encode_ed25519_public(&self.public_key())
            .expect("public key is always 32 bytes")
    }

    /// The did:key form of the public key.
    pub fn did_key(&self) -> String {
        ed25519_to_did_key(&self.public_key()).expect("public key is always 32 bytes")
    }
}

/// Verify a 64-byte Ed25519 signature over a message against a 32-byte public key.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
    let pk: [u8; ED25519_PUBLIC_LEN] = public_key.try_into().map_err(|_| {
        CoreError::InvalidKeyLength {
            expected: ED25519_PUBLIC_LEN,
            got: public_key.len(),
        }
    })?;
    let sig: [u8; ED25519_SIGNATURE_LEN] = signature.try_into().map_err(|_| {
        CoreError::InvalidSignatureLength {
            expected: ED25519_SIGNATURE_LEN,
            got: signature.len(),
        }
    })?;
    let vk = VerifyingKey::from_bytes(&pk)
        .map_err(|e| CoreError::Crypto(format!("bad public key: {e}")))?;
    // verify_strict (not verify): rejects signatures with a non-canonical or
    // small-order R component and small-order public keys, closing Ed25519
    // malleability / multiple-valid-signature avenues that a permissive verifier
    // would accept. Honest, canonically-encoded signatures are unaffected.
    Ok(vk.verify_strict(message, &Signature::from_bytes(&sig)).is_ok())
}

/// Encode an Ed25519 public key as a did:key DID.
pub fn ed25519_to_did_key(public_key: &[u8]) -> Result<String> {
    Ok(format!("did:key:{}", multikey::encode_ed25519_public(public_key)?))
}

/// Extract the Ed25519 public key bytes from a did:key DID.
pub fn did_key_to_ed25519(did: &str) -> Result<Vec<u8>> {
    let mk = did
        .strip_prefix("did:key:")
        .ok_or_else(|| CoreError::InvalidDid("not a did:key".into()))?;
    let decoded = multikey::decode(mk)?;
    if decoded.algorithm != "Ed25519" {
        return Err(CoreError::InvalidDid(format!(
            "did:key is {} not Ed25519",
            decoded.algorithm
        )));
    }
    Ok(decoded.raw_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let kp = Ed25519KeyPair::generate().unwrap();
        let msg = b"vouch protocol";
        let sig = kp.sign(msg);
        assert!(verify(&kp.public_key(), msg, &sig).unwrap());
        assert!(!verify(&kp.public_key(), b"tampered", &sig).unwrap());
    }

    #[test]
    fn did_key_roundtrip() {
        let kp = Ed25519KeyPair::generate().unwrap();
        let did = kp.did_key();
        assert!(did.starts_with("did:key:z6Mk"));
        assert_eq!(did_key_to_ed25519(&did).unwrap(), kp.public_key().to_vec());
    }

    #[test]
    fn seed_determinism() {
        let seed = [3u8; 32];
        let a = Ed25519KeyPair::from_seed(&seed);
        let b = Ed25519KeyPair::from_seed(&seed);
        assert_eq!(a.public_key(), b.public_key());
    }
}
