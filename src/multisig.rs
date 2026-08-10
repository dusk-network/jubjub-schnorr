// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg(feature = "alloc")]

//! # Multisignature Module
//!
//! Implementation of a MuSig-style Schnorr-based multisignature scheme
//! with delinearized key aggregation. It allows several signers to
//! create a signature that proves a message to be signed by them all,
//! given their public keys.
//!
//! Delinearization prevents rogue-key attacks by weighting each public
//! key with a coefficient derived from hashing the full key set:
//!
//! ```text
//! d_i = H(pk_i, pk_1, pk_2, ..., pk_n)
//! pk_agg = d_1 * pk_1 + d_2 * pk_2 + ... + d_n * pk_n
//! ```
//!
//! reference: https://eprint.iacr.org/2021/1375.pdf - pag. 19
//!
//! ## Feature
//!
//! Only available with the "alloc" feature enabled.
//!
//! ## Example
//!
//! Generate and verify a multisignature:
//! ```rust
//! use dusk_bls12_381::BlsScalar;
//! use ff::Field;
//! use jubjub_schnorr::multisig;
//! use jubjub_schnorr::{PublicKey, SecretKey};
//! use rand::{rngs::StdRng, SeedableRng};
//!
//! let mut rng = StdRng::seed_from_u64(2321u64);
//!
//! // signer 1
//! let sk_1 = SecretKey::random(&mut rng);
//! let pk_1 = PublicKey::from(&sk_1);
//!
//! // signer 2
//! let sk_2 = SecretKey::random(&mut rng);
//! let pk_2 = PublicKey::from(&sk_2);
//!
//! let message = BlsScalar::random(&mut rng);
//!
//! let pk_vec = vec![pk_1, pk_2];
//!
//! // First round: all signers compute the following elements
//! let (nonce_1, R_1, S_1) = multisig::sign_round_1(&mut rng);
//! let (nonce_2, R_2, S_2) = multisig::sign_round_1(&mut rng);
//!
//! // All signers share `R_vec` and `S_vec` with all the other signers
//! let R_vec = vec![R_1, R_2];
//! let S_vec = vec![S_1, S_2];
//!
//! // Second round: all the signers compute their share `z`
//! let z_1 = multisig::sign_round_2(
//!     &sk_1,
//!     nonce_1,
//!     &pk_vec.clone(),
//!     &R_vec.clone(),
//!     &S_vec.clone(),
//!     &message,
//! )
//! .expect("Multisig Round 2 shouldn't fail");
//! let z_2 = multisig::sign_round_2(
//!     &sk_2,
//!     nonce_2,
//!     &pk_vec.clone(),
//!     &R_vec.clone(),
//!     &S_vec.clone(),
//!     &message,
//! )
//! .expect("Multisig Round 2 shouldn't fail");
//!
//! // All signers share their share `z` with a signer wishing to combine them
//! // all
//! let z_vec = vec![z_1, z_2];
//!
//! // A signer combines all the shares into a signature `sig`
//! let sig = multisig::combine(&z_vec, &pk_vec, &R_vec, &S_vec, &message)
//!     .expect("Multisig combination shouldn't fail");
//!
//! // Anyone can verify using the delinearized aggregate public key
//! let pk = multisig::aggregate_pk(&pk_vec);
//! assert!(pk.verify(&sig, message).is_ok());
//! ```

extern crate alloc;
use alloc::vec;

use dusk_bls12_381::BlsScalar;
use dusk_jubjub::{GENERATOR_EXTENDED, JubJubExtended, JubJubScalar};
use ff::Field;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::{Error, PublicKey, SecretKey, Signature};

/// Secret nonce state produced by [`sign_round_1`] and consumed by
/// [`sign_round_2`].
///
/// The state deliberately implements neither [`Clone`] nor [`Copy`]. Its
/// scalar fields owned by this state are zeroized whenever it is consumed or
/// dropped. This does not guarantee clearing transient copies created during
/// scalar arithmetic.
///
/// A nonce cannot be submitted to round two twice:
///
/// ```compile_fail,E0382
/// use dusk_bls12_381::BlsScalar;
/// use jubjub_schnorr::{PublicKey, SecretKey, multisig};
/// use rand::{SeedableRng, rngs::StdRng};
///
/// let mut rng = StdRng::seed_from_u64(7);
/// let sk = SecretKey::random(&mut rng);
/// let pk = PublicKey::from(&sk);
/// let message = BlsScalar::from(11u64);
/// let (nonce, r, s) = multisig::sign_round_1(&mut rng);
///
/// let _ = multisig::sign_round_2(&sk, nonce, &[pk], &[r], &[s], &message);
/// let _ = multisig::sign_round_2(&sk, nonce, &[pk], &[r], &[s], &message);
/// ```
#[derive(Zeroize)]
pub struct MultisigNonce {
    r: JubJubScalar,
    s: JubJubScalar,
}

impl Drop for MultisigNonce {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Computes the delinearized aggregate public key for a set of signers.
///
/// Each public key is weighted by a coefficient derived from hashing the
/// full key set, preventing rogue-key attacks:
///
/// ```text
/// d_i = H(pk_i, pk_1, pk_2, ..., pk_n)
/// pk_agg = d_1 * pk_1 + d_2 * pk_2 + ... + d_n * pk_n
/// ```
///
/// Use this to compute the verification key for a multisignature.
pub fn aggregate_pk(pk_vec: &[PublicKey]) -> PublicKey {
    let mut pk_agg = JubJubExtended::default();
    for pk in pk_vec {
        let d = delinearization_coeff(pk, pk_vec);
        pk_agg += pk.as_ref() * d;
    }
    PublicKey::from(pk_agg)
}

/// Performs the first round to sign a message using the
/// multisignature scheme
///
/// ## Parameters
///
/// - `rng`: Reference to the random number generator.
///
/// ## Returns
///
/// Returns an opaque one-shot [`MultisigNonce`] and the public commitment
/// points `(R, S)`.
pub fn sign_round_1<R>(
    mut rng: &mut R,
) -> (MultisigNonce, JubJubExtended, JubJubExtended)
where
    R: RngCore + CryptoRng,
{
    // Sample two random values (r, s)
    let r = JubJubScalar::random(&mut rng);
    let s = JubJubScalar::random(&mut rng);

    // Compute R = r * G, S = s * G
    let R = GENERATOR_EXTENDED * r;
    let S = GENERATOR_EXTENDED * s;

    (MultisigNonce { r, s }, R, S)
}

/// Performs the second round to sign a message using the
/// multisignature scheme
///
/// ## Parameters
///
/// - `sk`: Reference to the secret key.
/// - `nonce`: One-shot secret nonce state returned by [`sign_round_1`].
/// - `pk_vec`: Ordered vector of public keys; the signer's key must occur
///   exactly once.
/// - `R_vec`: Vector of R values, index-aligned with `pk_vec`.
/// - `S_vec`: Vector of S values, index-aligned with `pk_vec`.
/// - `msg`: Message to sign.
///
/// ## Returns
///
/// Returns a [`JubJubScalar`] being the signature share 'z'
///
/// ## Errors
///
/// Returns [`Error::InvalidMultisigTranscript`] if the participant vectors do
/// not have equal lengths, the signer key does not occur exactly once in the
/// key list, or this state does not match the signer's commitment slot. Returns
/// [`Error::DuplicatedNonce`] if any two participants supplied the same `R` or
/// `S` commitment.
pub fn sign_round_2(
    sk: &SecretKey,
    nonce: MultisigNonce,
    pk_vec: &[PublicKey],
    R_vec: &[JubJubExtended],
    S_vec: &[JubJubExtended],
    msg: &BlsScalar,
) -> Result<JubJubScalar, Error> {
    if pk_vec.len() != R_vec.len() || R_vec.len() != S_vec.len() {
        return Err(Error::InvalidMultisigTranscript);
    }

    let signer_pk = PublicKey::from(&*sk);
    let mut signer_indices = pk_vec
        .iter()
        .enumerate()
        .filter(|(_, pk)| **pk == signer_pk)
        .map(|(index, _)| index);
    let signer_index = signer_indices
        .next()
        .ok_or(Error::InvalidMultisigTranscript)?;
    if signer_indices.next().is_some()
        || R_vec[signer_index] != GENERATOR_EXTENDED * nonce.r
        || S_vec[signer_index] != GENERATOR_EXTENDED * nonce.s
    {
        return Err(Error::InvalidMultisigTranscript);
    }

    // Check if (R_i == R_j) || (S_i == S_j) for any i != j
    // and return error if so
    for i in 0..R_vec.len() {
        for j in (i + 1)..R_vec.len() {
            if R_vec[i] == R_vec[j] || S_vec[i] == S_vec[j] {
                return Err(Error::DuplicatedNonce);
            }
        }
    }

    let d_i = delinearization_coeff(&signer_pk, pk_vec);
    let (a, c, _RSa) = multisig_common(pk_vec, R_vec, S_vec, msg);

    // Compute the share z = r + s * a - c * d_i * sk
    Ok(nonce.r + (nonce.s * a) - (c * d_i * sk.as_ref()))
}

/// Combines all the multisignature shares `z_vec`.
///
/// ## Parameters
///
/// - `z_vec`: Vector of shares.
/// - `pk_vec`: Vector of public keys.
/// - `R_vec`: Vector of R values.
/// - `S_vec`: Vector of S values.
/// - `msg`: Message to sign.
///
/// ## Returns
///
/// Returns a new [`Signature`] wrapped in [`Ok`] on success.
///
/// ## Errors
///
/// Returns [`Error::InvalidMultisigTranscript`] if the participant vectors are
/// empty or do not have equal lengths.
pub fn combine(
    z_vec: &[JubJubScalar],
    pk_vec: &[PublicKey],
    R_vec: &[JubJubExtended],
    S_vec: &[JubJubExtended],
    msg: &BlsScalar,
) -> Result<Signature, Error> {
    if z_vec.is_empty()
        || z_vec.len() != pk_vec.len()
        || pk_vec.len() != R_vec.len()
        || R_vec.len() != S_vec.len()
    {
        return Err(Error::InvalidMultisigTranscript);
    }

    let (_a, _c, RSa) = multisig_common(pk_vec, R_vec, S_vec, msg);

    // Sum all the shares u = z_1 + z_2 + ... + z_n for `n` signers
    let u = z_vec.iter().sum();

    Ok(Signature::new(u, RSa))
}

/// Computes the delinearization coefficient for a signer's public key
/// given the full set of public keys.
///
/// d_i = H(pk_i, pk_1, pk_2, ..., pk_n)
fn delinearization_coeff(
    pk_i: &PublicKey,
    pk_vec: &[PublicKey],
) -> JubJubScalar {
    use dusk_poseidon::{Domain, Hash};

    let mut preimage = vec![];
    let pk_i_coords = pk_i.as_ref().to_hash_inputs();
    preimage.push(pk_i_coords[0]);
    preimage.push(pk_i_coords[1]);
    for pk in pk_vec {
        let coords = pk.as_ref().to_hash_inputs();
        preimage.push(coords[0]);
        preimage.push(coords[1]);
    }
    Hash::digest_truncated(Domain::Other, &preimage)[0]
}

/// Performs some common operations required in different parts
/// of the multisignature scheme
fn multisig_common(
    pk_vec: &[PublicKey],
    R_vec: &[JubJubExtended],
    S_vec: &[JubJubExtended],
    msg: &BlsScalar,
) -> (JubJubScalar, JubJubScalar, JubJubExtended) {
    use dusk_poseidon::{Domain, Hash};

    // Compute the delinearized aggregate key
    // pk = d_1 * pk_1 + d_2 * pk_2 + ... + d_n * pk_n
    let mut pk = JubJubExtended::default();
    for pk_it in pk_vec {
        let d = delinearization_coeff(pk_it, pk_vec);
        pk += pk_it.as_ref() * d;
    }

    // Compute the hash
    // a = H(pk || m || R_1 || S_1 || R_2 || S_2 || ... || R_n || S_n)
    // for `n` signers
    let mut preimage = vec![];
    let pk_coordinates = pk.to_hash_inputs();

    preimage.push(pk_coordinates[0]);
    preimage.push(pk_coordinates[1]);
    preimage.push(*msg);

    for it in 0..R_vec.len() {
        let R_coordinates = R_vec[it].to_hash_inputs();
        let S_coordinates = S_vec[it].to_hash_inputs();

        preimage.push(R_coordinates[0]);
        preimage.push(R_coordinates[1]);
        preimage.push(S_coordinates[0]);
        preimage.push(S_coordinates[1]);
    }

    let a = Hash::digest_truncated(Domain::Other, &preimage)[0];

    // Compute RSa = R_1 + (S_1 * a) + R_2 + (S_2 * a) + ... + R_n + (S_n *
    // a) for `n` signers
    let mut RSa = JubJubExtended::default();
    for it in 0..R_vec.len() {
        RSa = RSa + R_vec[it] + (S_vec[it] * a);
    }

    // Compute challenge c = H(RSa || pk || m);
    let RSa_coordinates = RSa.to_hash_inputs();
    let c = Hash::digest_truncated(
        Domain::Other,
        &[
            RSa_coordinates[0],
            RSa_coordinates[1],
            pk_coordinates[0],
            pk_coordinates[1],
            *msg,
        ],
    )[0];

    (a, c, RSa)
}

#[cfg(test)]
mod tests {
    use dusk_jubjub::JubJubScalar;
    use zeroize::Zeroize;

    use super::MultisigNonce;

    #[test]
    fn nonce_state_zeroizes_both_scalars() {
        let mut nonce = MultisigNonce {
            r: JubJubScalar::from(41u64),
            s: JubJubScalar::from(43u64),
        };

        nonce.zeroize();

        assert_eq!(nonce.r, JubJubScalar::zero());
        assert_eq!(nonce.s, JubJubScalar::zero());
    }
}
