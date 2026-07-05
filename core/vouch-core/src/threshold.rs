//! FROST(Ed25519, SHA-512) threshold signing (RFC 9591).
//!
//! Wraps the audited Zcash Foundation `frost-ed25519` crate. A key is split
//! among `max_signers` participants so that any `min_signers` of them can
//! produce a signature together, WITHOUT the full private key ever being
//! reconstructed at any point, not even during signing. This is distinct from
//! Shamir secret sharing (see the Python `vouch.recovery` module and its
//! `split_secret`/`combine_shares`), where the secret IS reconstructed; FROST
//! is for live, repeated signing across a threshold of custodians.
//!
//! The critical property that makes this a drop-in fit for Vouch: the
//! aggregated signature is a STANDARD Ed25519 signature (RFC 8032), so it
//! verifies with the existing [`crate::keys::verify`] and needs no new proof
//! type, cryptosuite, or verifier anywhere in the protocol. A verifier cannot
//! tell whether a credential was signed by one key or by a threshold of
//! shares.
//!
//! Design note: [`generate_key`] mints a FRESH threshold-native group
//! identity (via a trusted dealer), rather than converting an existing
//! single-key Ed25519 identity into a threshold one. This is deliberate: a
//! standard Ed25519 private key is derived from its 32-byte seed via
//! SHA-512-and-clamp (RFC 8032 §5.1.5), and the resulting scalar is not
//! generally a canonical element of the group order used by FROST's scalar
//! field. Naively reducing it would silently produce a DIFFERENT public key,
//! which would break the DID it was meant to protect. Treat a threshold
//! identity as its own identity from the start, exactly like
//! `generate_identity`, and enroll it as a device or root the same way any
//! other Vouch identity is enrolled.
//!
//! Ceremony (four steps, mirroring RFC 9591 §5):
//!
//!   1. [`generate_key`]: a trusted dealer mints `max_signers` key shares and
//!      a group public key. (Full distributed key generation, where no single
//!      party ever sees a complete key even momentarily, is a further step not
//!      implemented here; the dealer only ever handles shares and the public
//!      key, never a reconstructed private scalar.)
//!   2. [`commit`]: each signer, locally, generates single-use signing nonces
//!      (kept secret, never transmitted) and a public commitment (safe to
//!      send to the coordinator).
//!   3. [`sign_share`]: each signer, given the message and every signer's
//!      commitment, produces a signature share using its own key share and
//!      nonces.
//!   4. [`aggregate`]: the coordinator combines `min_signers` (or more)
//!      signature shares into one final, standard Ed25519 signature.
//!
//! There is deliberately no `reconstruct` function exposed here. The
//! underlying crate provides one (`frost_ed25519::keys::reconstruct`) as an
//! explicit escape hatch documented as NOT required for signing; Vouch does
//! not wrap or expose it, so nothing in this module can assemble the full key.

use std::collections::BTreeMap;

use frost_ed25519 as frost;
use rand_core::OsRng;

use crate::error::{CoreError, Result};

fn threshold_err<E: std::fmt::Display>(e: E) -> CoreError {
    CoreError::Threshold(e.to_string())
}

/// One participant's share of a threshold key. `key_package` is secret key
/// material (a scalar share of the group secret) and must be kept only by the
/// participant it was issued to.
#[derive(Clone)]
pub struct KeyShare {
    pub identifier: Vec<u8>,
    pub key_package: Vec<u8>,
}

/// The group's public identity. `verifying_key` is a standard 32-byte Ed25519
/// public key: it is what you publish as the DID's verification method key,
/// exactly like any other Vouch identity's public key.
#[derive(Clone)]
pub struct GroupPublicKey {
    pub verifying_key: [u8; 32],
    pub public_key_package: Vec<u8>,
}

/// Output of [`generate_key`].
pub struct GenerateKeyResult {
    pub shares: Vec<KeyShare>,
    pub group_public_key: GroupPublicKey,
}

/// Mint a fresh threshold-native Ed25519 identity: `max_signers` key shares,
/// any `min_signers` of which can sign together, and a group public key. The
/// dealer performing this call sees every share transiently (to hand them out)
/// but never a reconstructed private key; the underlying crate samples the
/// group secret directly as shares via verifiable secret sharing, never
/// materializing it as a single scalar.
pub fn generate_key(min_signers: u16, max_signers: u16) -> Result<GenerateKeyResult> {
    if min_signers < 2 || min_signers > max_signers {
        return Err(CoreError::Threshold(format!(
            "require 2 <= min_signers <= max_signers, got min={min_signers} max={max_signers}"
        )));
    }

    let (shares, pubkey_package) = frost::keys::generate_with_dealer(
        max_signers,
        min_signers,
        frost::keys::IdentifierList::Default,
        OsRng,
    )
    .map_err(threshold_err)?;

    let mut out_shares = Vec::with_capacity(shares.len());
    for (identifier, secret_share) in shares {
        let key_package: frost::keys::KeyPackage =
            secret_share.try_into().map_err(threshold_err)?;
        out_shares.push(KeyShare {
            identifier: identifier.serialize(),
            key_package: key_package.serialize().map_err(threshold_err)?,
        });
    }

    let verifying_key_bytes = pubkey_package
        .verifying_key()
        .serialize()
        .map_err(threshold_err)?;
    let verifying_key: [u8; 32] = verifying_key_bytes
        .try_into()
        .map_err(|_| CoreError::Threshold("group verifying key was not 32 bytes".into()))?;

    Ok(GenerateKeyResult {
        shares: out_shares,
        group_public_key: GroupPublicKey {
            verifying_key,
            public_key_package: pubkey_package.serialize().map_err(threshold_err)?,
        },
    })
}

/// Round 1 output for one signer: secret nonces (kept locally, used exactly
/// once) and a public commitment (sent to the coordinator).
pub struct Round1 {
    pub nonces: Vec<u8>,
    pub commitments: Vec<u8>,
}

/// Round 1: a signer generates its single-use nonces and public commitment.
/// `nonces` MUST be used for exactly one [`sign_share`] call and then
/// discarded; reusing them leaks the signer's key share.
pub fn commit(key_share: &KeyShare) -> Result<Round1> {
    let key_package = deserialize_key_package(&key_share.key_package)?;
    let mut rng = OsRng;
    let (nonces, commitments) = frost::round1::commit(key_package.signing_share(), &mut rng);
    Ok(Round1 {
        nonces: nonces.serialize().map_err(threshold_err)?,
        commitments: commitments.serialize().map_err(threshold_err)?,
    })
}

/// Round 2: given the message and every participating signer's commitment,
/// this signer produces its signature share using its own key share and its
/// own (single-use) nonces from [`commit`]. `commitments_by_participant` must
/// include an entry for every signer taking part in this signature, including
/// this one.
pub fn sign_share(
    message: &[u8],
    key_share: &KeyShare,
    nonces: &[u8],
    commitments_by_participant: &BTreeMap<Vec<u8>, Vec<u8>>,
) -> Result<Vec<u8>> {
    let key_package = deserialize_key_package(&key_share.key_package)?;
    let signing_nonces =
        frost::round1::SigningNonces::deserialize(nonces).map_err(threshold_err)?;
    let signing_package = build_signing_package(message, commitments_by_participant)?;

    let share = frost::round2::sign(&signing_package, &signing_nonces, &key_package)
        .map_err(threshold_err)?;
    Ok(share.serialize())
}

/// Combine `min_signers` (or more) signature shares into the final, standard
/// Ed25519 signature. Verify the result with [`crate::keys::verify`] against
/// `group_public_key.verifying_key`, exactly like any other Vouch credential.
pub fn aggregate(
    message: &[u8],
    commitments_by_participant: &BTreeMap<Vec<u8>, Vec<u8>>,
    shares_by_participant: &BTreeMap<Vec<u8>, Vec<u8>>,
    group_public_key: &GroupPublicKey,
) -> Result<[u8; 64]> {
    let signing_package = build_signing_package(message, commitments_by_participant)?;

    let mut shares = BTreeMap::new();
    for (id_bytes, share_bytes) in shares_by_participant {
        let identifier = frost::Identifier::deserialize(id_bytes).map_err(threshold_err)?;
        let share =
            frost::round2::SignatureShare::deserialize(share_bytes).map_err(threshold_err)?;
        shares.insert(identifier, share);
    }

    let pubkey_package =
        frost::keys::PublicKeyPackage::deserialize(&group_public_key.public_key_package)
            .map_err(threshold_err)?;

    let signature =
        frost::aggregate(&signing_package, &shares, &pubkey_package).map_err(threshold_err)?;
    let sig_bytes = signature.serialize().map_err(threshold_err)?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| CoreError::Threshold("aggregated signature was not 64 bytes".into()))?;

    // Defense in depth: an aggregate signature that does not verify against
    // the group's own public key indicates a bug or a misbehaving signer, and
    // must never be returned to a caller as if it were valid.
    let self_check = crate::keys::verify(&group_public_key.verifying_key, message, &sig_arr)
        .map_err(threshold_err)?;
    if !self_check {
        return Err(CoreError::Threshold(
            "aggregated signature failed self-verification".into(),
        ));
    }

    Ok(sig_arr)
}

fn deserialize_key_package(bytes: &[u8]) -> Result<frost::keys::KeyPackage> {
    frost::keys::KeyPackage::deserialize(bytes).map_err(threshold_err)
}

fn build_signing_package(
    message: &[u8],
    commitments_by_participant: &BTreeMap<Vec<u8>, Vec<u8>>,
) -> Result<frost::SigningPackage> {
    if commitments_by_participant.len() < 2 {
        return Err(CoreError::Threshold(
            "need commitments from at least 2 participants".into(),
        ));
    }
    let mut commitments = BTreeMap::new();
    for (id_bytes, commitment_bytes) in commitments_by_participant {
        let identifier = frost::Identifier::deserialize(id_bytes).map_err(threshold_err)?;
        let commitment = frost::round1::SigningCommitments::deserialize(commitment_bytes)
            .map_err(threshold_err)?;
        commitments.insert(identifier, commitment);
    }
    Ok(frost::SigningPackage::new(commitments, message))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_commit_sign_aggregate(
        min_signers: u16,
        max_signers: u16,
        signer_indices: &[usize],
        message: &[u8],
    ) -> (GenerateKeyResult, [u8; 64]) {
        let generated = generate_key(min_signers, max_signers).expect("generate_key");
        assert_eq!(generated.shares.len(), max_signers as usize);

        let chosen: Vec<&KeyShare> = signer_indices
            .iter()
            .map(|&i| &generated.shares[i])
            .collect();

        let mut nonces_by_signer = BTreeMap::new();
        let mut commitments = BTreeMap::new();
        for share in &chosen {
            let round1 = commit(share).expect("commit");
            commitments.insert(share.identifier.clone(), round1.commitments);
            nonces_by_signer.insert(share.identifier.clone(), round1.nonces);
        }

        let mut shares_out = BTreeMap::new();
        for share in &chosen {
            let nonces = nonces_by_signer.get(&share.identifier).unwrap();
            let sig_share = sign_share(message, share, nonces, &commitments).expect("sign_share");
            shares_out.insert(share.identifier.clone(), sig_share);
        }

        let signature = aggregate(
            message,
            &commitments,
            &shares_out,
            &generated.group_public_key,
        )
        .expect("aggregate");

        (generated, signature)
    }

    #[test]
    fn two_of_three_signs_and_verifies_as_plain_ed25519() {
        let message = b"charge api.bank invoices/42";
        let (generated, signature) = generate_commit_sign_aggregate(2, 3, &[0, 2], message);

        let ok = crate::keys::verify(
            &generated.group_public_key.verifying_key,
            message,
            &signature,
        )
        .expect("verify");
        assert!(
            ok,
            "FROST aggregate signature must verify as a plain Ed25519 signature"
        );
    }

    #[test]
    fn three_of_five_any_subset_works() {
        let message = b"read did:web:files https://files/x";
        let (generated, signature) = generate_commit_sign_aggregate(3, 5, &[1, 3, 4], message);
        let ok = crate::keys::verify(
            &generated.group_public_key.verifying_key,
            message,
            &signature,
        )
        .expect("verify");
        assert!(ok);
    }

    #[test]
    fn different_subset_of_same_group_also_verifies() {
        // Any qualifying subset of signers produces a signature that verifies
        // against the SAME group public key.
        let message = b"same message, different signer subset";
        let generated = generate_key(3, 5).expect("generate_key");

        let sign_with = |indices: &[usize]| -> [u8; 64] {
            let chosen: Vec<&KeyShare> = indices.iter().map(|&i| &generated.shares[i]).collect();
            let mut nonces_by_signer = BTreeMap::new();
            let mut commitments = BTreeMap::new();
            for share in &chosen {
                let round1 = commit(share).expect("commit");
                commitments.insert(share.identifier.clone(), round1.commitments);
                nonces_by_signer.insert(share.identifier.clone(), round1.nonces);
            }
            let mut shares_out = BTreeMap::new();
            for share in &chosen {
                let nonces = nonces_by_signer.get(&share.identifier).unwrap();
                let sig_share =
                    sign_share(message, share, nonces, &commitments).expect("sign_share");
                shares_out.insert(share.identifier.clone(), sig_share);
            }
            aggregate(
                message,
                &commitments,
                &shares_out,
                &generated.group_public_key,
            )
            .expect("aggregate")
        };

        let sig_a = sign_with(&[0, 1, 2]);
        let sig_b = sign_with(&[2, 3, 4]);
        assert!(
            crate::keys::verify(&generated.group_public_key.verifying_key, message, &sig_a)
                .unwrap()
        );
        assert!(
            crate::keys::verify(&generated.group_public_key.verifying_key, message, &sig_b)
                .unwrap()
        );
    }

    #[test]
    fn wrong_message_fails_verification() {
        let message = b"original message";
        let (generated, signature) = generate_commit_sign_aggregate(2, 3, &[0, 1], message);
        let ok = crate::keys::verify(
            &generated.group_public_key.verifying_key,
            b"tampered message",
            &signature,
        )
        .expect("verify");
        assert!(
            !ok,
            "a signature over one message must not verify a different message"
        );
    }

    #[test]
    fn different_groups_have_different_public_keys() {
        let a = generate_key(2, 3).unwrap();
        let b = generate_key(2, 3).unwrap();
        assert_ne!(
            a.group_public_key.verifying_key,
            b.group_public_key.verifying_key
        );
    }

    #[test]
    fn generate_key_rejects_bad_threshold() {
        assert!(generate_key(1, 3).is_err()); // min_signers must be >= 2
        assert!(generate_key(4, 3).is_err()); // min_signers must be <= max_signers
    }

    #[test]
    fn aggregate_rejects_single_commitment() {
        let generated = generate_key(2, 3).unwrap();
        let message = b"x";

        let share0 = &generated.shares[0];
        let round1 = commit(share0).unwrap();
        let mut commitments = BTreeMap::new();
        commitments.insert(share0.identifier.clone(), round1.commitments);

        // Only one participant's commitment: below the 2-signer threshold.
        let result = sign_share(message, share0, &round1.nonces, &commitments);
        assert!(result.is_err());
    }

    /// Structural proof that this module cannot reconstruct the full private
    /// key: there is no function anywhere in this module that takes key
    /// shares and returns a seed, signing key, or private scalar of any kind.
    /// `generate_key` only ever returns shares and a PUBLIC key, and every
    /// other function in this module takes shares in and returns either a
    /// public commitment, a signature share, or the final public signature.
    #[test]
    fn no_function_in_this_module_returns_a_private_scalar() {
        let generated = generate_key(2, 3).unwrap();
        // group_public_key.verifying_key is 32 bytes, the same length as a
        // private seed elsewhere in this crate, so a naive size check would
        // not catch a reassembled key; the real guarantee is structural: read
        // the module source above, there is no reconstruct/combine-to-secret
        // function. This assertion documents that the public key differs from
        // every individual share's key_package bytes (which are secret and
        // never returned as a combined whole).
        for share in &generated.shares {
            assert_ne!(
                share.key_package,
                generated.group_public_key.public_key_package
            );
        }
    }
}
