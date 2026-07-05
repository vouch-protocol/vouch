//! Root-identity recovery by Shamir secret sharing.
//!
//! Splits a root identity's Ed25519 seed into `shares` pieces so that any
//! `threshold` of them reconstruct it, and fewer reveal nothing. Distribute
//! shares to separate guardians or locations; gather `threshold` only during
//! a deliberate recovery.
//!
//! This is the recovery / escrow primitive, distinct from [`crate::threshold`]
//! (FROST), where the key is never reassembled: here the seed IS reconstructed
//! at recovery time, so do it on a trusted device and re-seal afterwards. Use
//! it for cold recovery of a root, not for hot signing.
//!
//! The arithmetic is textbook Shamir over GF(2^8) (the AES field, reducing
//! polynomial 0x11B). Shares carry no integrity tag, so a corrupted share
//! yields a wrong secret rather than an error; pair with your own checksum if
//! you need to detect a bad share.

use crate::error::{CoreError, Result};
use crate::keys::{ed25519_to_did_key, Ed25519KeyPair, ED25519_SEED_LEN};

fn recovery_err(msg: impl Into<String>) -> CoreError {
    CoreError::Crypto(msg.into())
}

// ---------------------------------------------------------------------------
// GF(2^8) arithmetic (AES field, reducing polynomial 0x11B)
// ---------------------------------------------------------------------------

struct GfTables {
    exp: [u8; 512],
    log: [u8; 256],
}

fn gf_tables() -> &'static GfTables {
    use std::sync::OnceLock;
    static TABLES: OnceLock<GfTables> = OnceLock::new();
    TABLES.get_or_init(|| {
        // 3 (not 2) is a primitive element of GF(2^8) under 0x11B, so powers of
        // 3 cycle through all 255 non-zero elements. Multiply by 3 = (x*2) XOR x.
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        #[allow(clippy::needless_range_loop)] // log is indexed by x, not by i
        for i in 0..255usize {
            exp[i] = x as u8;
            log[x as usize] = i as u8;
            let mut x2 = x << 1;
            if x2 & 0x100 != 0 {
                x2 ^= 0x11B;
            }
            x ^= x2;
        }
        // exp[255..512) mirrors exp[0..257) (period 255); each entry depends on
        // one already computed earlier in this same range, so this must stay a
        // sequential loop rather than a single bulk copy.
        #[allow(clippy::needless_range_loop)]
        for i in 255..512 {
            exp[i] = exp[i - 255];
        }
        GfTables { exp, log }
    })
}

fn gf_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let t = gf_tables();
    t.exp[t.log[a as usize] as usize + t.log[b as usize] as usize]
}

fn gf_inv(a: u8) -> Result<u8> {
    if a == 0 {
        return Err(recovery_err("no inverse for 0 in GF(2^8)"));
    }
    let t = gf_tables();
    Ok(t.exp[255 - t.log[a as usize] as usize])
}

/// Evaluates a polynomial (coefficients low-order first) at `x` in GF(2^8).
fn eval_poly(coeffs: &[u8], x: u8) -> u8 {
    let mut result = 0u8;
    for &c in coeffs.iter().rev() {
        result = gf_mul(result, x) ^ c;
    }
    result
}

/// Lagrange-interpolates the points and returns the value at x = 0.
fn interpolate_at_zero(xs: &[u8], ys: &[u8]) -> Result<u8> {
    let mut result = 0u8;
    for i in 0..xs.len() {
        let mut num = 1u8;
        let mut den = 1u8;
        for j in 0..xs.len() {
            if i == j {
                continue;
            }
            num = gf_mul(num, xs[j]); // (0 - xj) == xj in GF(2^8)
            den = gf_mul(den, xs[i] ^ xs[j]); // (xi - xj) == xi ^ xj
        }
        let inv = gf_inv(den)?;
        result ^= gf_mul(ys[i], gf_mul(num, inv));
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// Byte-level split / combine
// ---------------------------------------------------------------------------

/// Splits `secret` into `shares` pieces; any `threshold` of them reconstruct
/// it. Each returned share is a leading index byte (1..=shares) followed by
/// the share body, the same length as `secret`.
pub fn split_secret(secret: &[u8], threshold: u16, shares: u16) -> Result<Vec<Vec<u8>>> {
    if secret.is_empty() {
        return Err(recovery_err("secret must be non-empty bytes"));
    }
    if threshold < 2 || threshold > shares || shares > 255 {
        return Err(recovery_err("require 2 <= threshold <= shares <= 255"));
    }

    let mut out: Vec<Vec<u8>> = (1..=shares).map(|i| vec![i as u8]).collect();

    for &b in secret {
        let mut coeffs = vec![0u8; threshold as usize];
        coeffs[0] = b;
        if threshold > 1 {
            getrandom::getrandom(&mut coeffs[1..])
                .map_err(|e| recovery_err(format!("rng: {e}")))?;
        }
        for (i, out_share) in out.iter_mut().enumerate() {
            out_share.push(eval_poly(&coeffs, (i + 1) as u8));
        }
    }
    Ok(out)
}

/// Reconstructs a secret from `threshold` (or more) shares. Supplying fewer
/// than the original threshold returns a wrong value, not an error.
pub fn combine_shares(shares: &[Vec<u8>]) -> Result<Vec<u8>> {
    if shares.len() < 2 {
        return Err(recovery_err("need at least 2 shares"));
    }
    let mut xs = Vec::with_capacity(shares.len());
    let mut bodies = Vec::with_capacity(shares.len());
    let mut seen = std::collections::HashSet::new();
    for s in shares {
        if s.len() < 2 {
            return Err(recovery_err("malformed share"));
        }
        if !seen.insert(s[0]) {
            return Err(recovery_err("shares must have distinct indices"));
        }
        xs.push(s[0]);
        bodies.push(&s[1..]);
    }
    let length = bodies[0].len();
    if bodies.iter().any(|b| b.len() != length) {
        return Err(recovery_err("shares have inconsistent length"));
    }

    let mut secret = vec![0u8; length];
    for j in 0..length {
        let ys: Vec<u8> = bodies.iter().map(|b| b[j]).collect();
        secret[j] = interpolate_at_zero(&xs, &ys)?;
    }
    Ok(secret)
}

// ---------------------------------------------------------------------------
// Vouch identity recovery
// ---------------------------------------------------------------------------

/// Splits a root identity's Ed25519 seed into recovery shares. Any threshold
/// of them recover the identity via [`recover_identity`]. Distribute them to
/// separate guardians or locations.
pub fn split_identity(seed: &[u8], threshold: u16, shares: u16) -> Result<Vec<Vec<u8>>> {
    if seed.len() != ED25519_SEED_LEN {
        return Err(CoreError::InvalidKeyLength {
            expected: ED25519_SEED_LEN,
            got: seed.len(),
        });
    }
    split_secret(seed, threshold, shares)
}

/// A root identity rebuilt from recovery shares.
pub struct RecoveredIdentity {
    pub did: String,
    pub seed: [u8; ED25519_SEED_LEN],
    pub public_key: [u8; 32],
}

/// Recovers a root identity from threshold recovery shares. The recovered
/// seed is deterministic, so the rebuilt key is identical to the original.
/// Pass `did` to set it on the result (for example the DID the shares were
/// split under); pass `None` to derive a did:key from the recovered public
/// key instead.
pub fn recover_identity(shares: &[Vec<u8>], did: Option<&str>) -> Result<RecoveredIdentity> {
    let seed_vec = combine_shares(shares)?;
    if seed_vec.len() != ED25519_SEED_LEN {
        return Err(recovery_err(format!(
            "recovered seed is not {ED25519_SEED_LEN} bytes; wrong or too few shares"
        )));
    }
    let seed: [u8; ED25519_SEED_LEN] = seed_vec
        .try_into()
        .map_err(|_| recovery_err("recovered seed had unexpected length"))?;

    let keypair = Ed25519KeyPair::from_seed(&seed);
    let public_key = keypair.public_key();

    let did = match did {
        Some(d) if !d.is_empty() => d.to_string(),
        _ => ed25519_to_did_key(&public_key)?,
    };

    Ok(RecoveredIdentity {
        did,
        seed,
        public_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_and_combine_roundtrips() {
        let secret = [7u8; 32];
        let shares = split_secret(&secret, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);

        let combined = combine_shares(&shares[0..3].to_vec()).unwrap();
        assert_eq!(combined, secret.to_vec());

        let alt = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
        let combined2 = combine_shares(&alt).unwrap();
        assert_eq!(combined2, secret.to_vec());
    }

    #[test]
    fn below_threshold_does_not_reveal_secret() {
        let secret = [9u8; 16];
        let shares = split_secret(&secret, 3, 5).unwrap();
        let combined = combine_shares(&shares[0..2].to_vec()).unwrap();
        assert_ne!(combined, secret.to_vec());
    }

    #[test]
    fn split_secret_rejects_bad_parameters() {
        assert!(split_secret(&[], 2, 3).is_err());
        assert!(split_secret(&[1], 1, 3).is_err());
        assert!(split_secret(&[1], 4, 3).is_err());
    }

    #[test]
    fn combine_shares_rejects_inconsistent_input() {
        let secret = [1u8; 16];
        let shares = split_secret(&secret, 2, 3).unwrap();
        let dup = vec![shares[0].clone(), shares[0].clone()];
        assert!(combine_shares(&dup).is_err());

        let mut short = shares[1].clone();
        short.truncate(6);
        let mismatched = vec![shares[0].clone(), short];
        assert!(combine_shares(&mismatched).is_err());
    }

    #[test]
    fn split_and_recover_identity_signs_identically() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let seed = keypair.seed();
        let did = ed25519_to_did_key(&keypair.public_key()).unwrap();

        let shares = split_identity(&seed, 2, 3).unwrap();
        assert_eq!(shares.len(), 3);

        let recovered = recover_identity(&shares[0..2].to_vec(), Some(&did)).unwrap();
        assert_eq!(recovered.did, did);
        assert_eq!(recovered.public_key, keypair.public_key());

        let message = b"charge api.bank invoices/42";
        let sig = Ed25519KeyPair::from_seed(&recovered.seed).sign(message);
        assert!(crate::keys::verify(&keypair.public_key(), message, &sig).unwrap());
    }

    #[test]
    fn recover_identity_without_explicit_did() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let seed = keypair.seed();
        let did = ed25519_to_did_key(&keypair.public_key()).unwrap();

        let shares = split_identity(&seed, 2, 3).unwrap();
        let recovered = recover_identity(&shares[1..3].to_vec(), None).unwrap();
        assert_eq!(recovered.did, did);
    }

    #[test]
    fn too_few_shares_gives_wrong_did_not_an_error() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let seed = keypair.seed();
        let did = ed25519_to_did_key(&keypair.public_key()).unwrap();

        let shares = split_identity(&seed, 3, 5).unwrap();
        // Two shares when three are required: recover_identity still returns
        // structurally, but the seed (and therefore the DID) will not match
        // the original, since interpolation with too few points gives the
        // wrong value.
        let recovered = recover_identity(&shares[0..2].to_vec(), None).unwrap();
        assert_ne!(recovered.did, did);
    }
}
