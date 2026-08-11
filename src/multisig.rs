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
use alloc::vec::Vec;

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
    PublicKey::from(aggregate_key(pk_vec).point)
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

    let signer_pk = PublicKey::from(sk);
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

    let coefficients = multisig_common(pk_vec, R_vec, S_vec, msg);
    let d_i = coefficients.aggregate_key.delinearization[signer_index];

    // Compute the share z = r + s * a - c * d_i * sk
    Ok(nonce.r + (nonce.s * coefficients.a)
        - (coefficients.c * d_i * sk.as_ref()))
}

/// Verifies one multisignature share against its participant slot.
///
/// The verification derives the transcript coefficients from the full,
/// ordered public-key and nonce-commitment vectors, then checks:
///
/// ```text
/// z_i * G + c * d_i * pk_i == R_i + a * S_i
/// ```
///
/// Here `a` binds all participant commitments, `c` is the aggregate Schnorr
/// challenge, and `d_i` delinearizes the participant public key.
///
/// ## Parameters
///
/// - `share`: Signature share to verify.
/// - `participant_index`: Slot corresponding to the share in every transcript
///   vector.
/// - `pk_vec`: Ordered vector of participant public keys.
/// - `R_vec`: Vector of R commitments, index-aligned with `pk_vec`.
/// - `S_vec`: Vector of S commitments, index-aligned with `pk_vec`.
/// - `msg`: Signed message.
///
/// ## Errors
///
/// Returns [`Error::InvalidMultisigTranscript`] if the participant vectors are
/// empty, have unequal lengths, or do not contain `participant_index`. Returns
/// [`Error::InvalidMultisigShare`] with `participant_index` if the share does
/// not satisfy its verification equation.
pub fn verify_share(
    share: &JubJubScalar,
    participant_index: usize,
    pk_vec: &[PublicKey],
    R_vec: &[JubJubExtended],
    S_vec: &[JubJubExtended],
    msg: &BlsScalar,
) -> Result<(), Error> {
    if pk_vec.is_empty()
        || pk_vec.len() != R_vec.len()
        || R_vec.len() != S_vec.len()
        || participant_index >= pk_vec.len()
    {
        return Err(Error::InvalidMultisigTranscript);
    }

    let coefficients = multisig_common(pk_vec, R_vec, S_vec, msg);
    verify_share_with_coefficients(
        share,
        participant_index,
        pk_vec,
        R_vec,
        S_vec,
        &coefficients,
    )
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
/// empty or do not have equal lengths. Returns
/// [`Error::InvalidMultisigShare`] with the participant slot of the first share
/// that fails verification. No aggregate signature is returned when a share is
/// invalid.
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

    let coefficients = multisig_common(pk_vec, R_vec, S_vec, msg);

    for (participant_index, share) in z_vec.iter().enumerate() {
        verify_share_with_coefficients(
            share,
            participant_index,
            pk_vec,
            R_vec,
            S_vec,
            &coefficients,
        )?;
    }

    // Sum all the shares u = z_1 + z_2 + ... + z_n for `n` signers
    let u = z_vec.iter().sum();

    Ok(Signature::new(u, coefficients.aggregate_commitment))
}

fn verify_share_with_coefficients(
    share: &JubJubScalar,
    participant_index: usize,
    pk_vec: &[PublicKey],
    r_vec: &[JubJubExtended],
    s_vec: &[JubJubExtended],
    coefficients: &MultisigCoefficients,
) -> Result<(), Error> {
    let pk_i = &pk_vec[participant_index];
    let r_i = &r_vec[participant_index];
    let s_i = &s_vec[participant_index];
    let d_i = coefficients.aggregate_key.delinearization[participant_index];
    let response =
        (GENERATOR_EXTENDED * share) + (pk_i.as_ref() * (coefficients.c * d_i));
    let commitment = *r_i + (*s_i * coefficients.a);

    if response != commitment {
        return Err(Error::InvalidMultisigShare(participant_index));
    }

    Ok(())
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

struct AggregateKey {
    delinearization: Vec<JubJubScalar>,
    point: JubJubExtended,
}

fn aggregate_key(pk_vec: &[PublicKey]) -> AggregateKey {
    let mut delinearization = Vec::with_capacity(pk_vec.len());
    let mut point = JubJubExtended::default();
    for pk in pk_vec {
        let d = delinearization_coeff(pk, pk_vec);
        delinearization.push(d);
        point += pk.as_ref() * d;
    }

    AggregateKey {
        delinearization,
        point,
    }
}

struct MultisigCoefficients {
    aggregate_key: AggregateKey,
    a: JubJubScalar,
    c: JubJubScalar,
    aggregate_commitment: JubJubExtended,
}

/// Performs some common operations required in different parts
/// of the multisignature scheme
fn multisig_common(
    pk_vec: &[PublicKey],
    R_vec: &[JubJubExtended],
    S_vec: &[JubJubExtended],
    msg: &BlsScalar,
) -> MultisigCoefficients {
    use dusk_poseidon::{Domain, Hash};

    // Compute the delinearized aggregate key
    // pk = d_1 * pk_1 + d_2 * pk_2 + ... + d_n * pk_n
    let aggregate_key = aggregate_key(pk_vec);

    // Compute the hash
    // a = H(pk || m || R_1 || S_1 || R_2 || S_2 || ... || R_n || S_n)
    // for `n` signers
    let mut preimage = vec![];
    let pk_coordinates = aggregate_key.point.to_hash_inputs();

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

    MultisigCoefficients {
        aggregate_key,
        a,
        c,
        aggregate_commitment: RSa,
    }
}

#[cfg(test)]
mod tests {
    use dusk_bls12_381::BlsScalar;
    use dusk_jubjub::{GENERATOR_EXTENDED, JubJubScalar};
    use zeroize::Zeroize;

    use super::{
        MultisigNonce, aggregate_pk, delinearization_coeff, multisig_common,
    };
    use crate::PublicKey;

    #[test]
    fn public_aggregate_key_matches_internal_transcript_key() {
        let point =
            |scalar: u64| GENERATOR_EXTENDED * JubJubScalar::from(scalar);
        let pk_vec = [3, 5, 7].map(|scalar| PublicKey::from(point(scalar)));
        let r_vec = [11, 13, 17].map(point);
        let s_vec = [19, 23, 29].map(point);
        let message = BlsScalar::from(31u64);

        let transcript = multisig_common(&pk_vec, &r_vec, &s_vec, &message);

        assert_eq!(
            aggregate_pk(&pk_vec).as_ref(),
            &transcript.aggregate_key.point
        );
        assert_eq!(
            transcript.aggregate_key.delinearization.len(),
            pk_vec.len()
        );
        for (pk_i, d_i) in
            pk_vec.iter().zip(&transcript.aggregate_key.delinearization)
        {
            assert_eq!(*d_i, delinearization_coeff(pk_i, &pk_vec));
        }
    }

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
