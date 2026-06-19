//! Post-quantum ML-DSA-44 (FIPS 204) keygen, sign, and verify.
//!
//! The wire sizes (public 1312, secret 2560, signature 2420 bytes) and the
//! "pure" empty-context signing match `@noble/post-quantum`'s `ml_dsa44`, so a
//! signature produced by the SDK verifies here and vice versa. ML-DSA signing is
//! randomized (hedged), so signatures are not byte-reproducible across runs;
//! interop is asserted by cross-verification, not by signature equality.

use fips204::ml_dsa_44;
use fips204::traits::{SerDes, Signer, Verifier};

use crate::error::{CoreError, Result};

pub const MLDSA44_PUBLIC_LEN: usize = 1312;
pub const MLDSA44_SECRET_LEN: usize = 2560;
pub const MLDSA44_SIG_LEN: usize = 2420;

/// An ML-DSA-44 key pair, stored as raw key bytes so both the secret and public
/// material can be exported (the WASM/FFI wrappers need the secret to sign).
pub struct MlDsa44KeyPair {
    secret_bytes: [u8; MLDSA44_SECRET_LEN],
    public_bytes: [u8; MLDSA44_PUBLIC_LEN],
}

impl MlDsa44KeyPair {
    /// Generate a fresh key pair using the platform CSPRNG.
    pub fn generate() -> Result<Self> {
        let (pk, sk) =
            ml_dsa_44::try_keygen().map_err(|e| CoreError::Crypto(format!("ml-dsa keygen: {e}")))?;
        Ok(Self {
            secret_bytes: sk.into_bytes(),
            public_bytes: pk.into_bytes(),
        })
    }

    /// Import a key pair from raw secret + public key bytes (validated).
    pub fn from_bytes(secret: &[u8], public: &[u8]) -> Result<Self> {
        let sk_arr: [u8; MLDSA44_SECRET_LEN] =
            secret.try_into().map_err(|_| CoreError::InvalidKeyLength {
                expected: MLDSA44_SECRET_LEN,
                got: secret.len(),
            })?;
        let pk_arr: [u8; MLDSA44_PUBLIC_LEN] =
            public.try_into().map_err(|_| CoreError::InvalidKeyLength {
                expected: MLDSA44_PUBLIC_LEN,
                got: public.len(),
            })?;
        ml_dsa_44::PrivateKey::try_from_bytes(sk_arr)
            .map_err(|e| CoreError::Crypto(format!("bad ml-dsa secret key: {e}")))?;
        ml_dsa_44::PublicKey::try_from_bytes(pk_arr)
            .map_err(|e| CoreError::Crypto(format!("bad ml-dsa public key: {e}")))?;
        Ok(Self {
            secret_bytes: sk_arr,
            public_bytes: pk_arr,
        })
    }

    /// The 1312-byte public key.
    pub fn public_key(&self) -> [u8; MLDSA44_PUBLIC_LEN] {
        self.public_bytes
    }

    /// The 2560-byte secret key.
    pub fn secret_key(&self) -> [u8; MLDSA44_SECRET_LEN] {
        self.secret_bytes
    }

    /// Sign a message (pure ML-DSA, empty context), returning the 2420-byte
    /// signature.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let sk = ml_dsa_44::PrivateKey::try_from_bytes(self.secret_bytes)
            .map_err(|e| CoreError::Crypto(format!("bad ml-dsa secret key: {e}")))?;
        let sig = sk
            .try_sign(message, &[])
            .map_err(|e| CoreError::Crypto(format!("ml-dsa sign: {e}")))?;
        Ok(sig.to_vec())
    }
}

/// Verify a 2420-byte ML-DSA-44 signature over a message against a 1312-byte
/// public key (pure ML-DSA, empty context).
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
    let pk_arr: [u8; MLDSA44_PUBLIC_LEN] =
        public_key.try_into().map_err(|_| CoreError::InvalidKeyLength {
            expected: MLDSA44_PUBLIC_LEN,
            got: public_key.len(),
        })?;
    let sig_arr: [u8; MLDSA44_SIG_LEN] =
        signature.try_into().map_err(|_| CoreError::InvalidSignatureLength {
            expected: MLDSA44_SIG_LEN,
            got: signature.len(),
        })?;
    let pk = ml_dsa_44::PublicKey::try_from_bytes(pk_arr)
        .map_err(|e| CoreError::Crypto(format!("bad ml-dsa public key: {e}")))?;
    Ok(pk.verify(message, &sig_arr, &[]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_sign_verify_roundtrip() {
        let kp = MlDsa44KeyPair::generate().unwrap();
        let msg = b"vouch pq";
        let sig = kp.sign(msg).unwrap();
        assert_eq!(sig.len(), MLDSA44_SIG_LEN);
        assert!(verify(&kp.public_key(), msg, &sig).unwrap());
        assert!(!verify(&kp.public_key(), b"other", &sig).unwrap());
    }
}
