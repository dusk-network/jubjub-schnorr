// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! # Multisignature Module
//!
//! Implementation of the `SpeedyMuSig` Schnorr-based
//! multisignature scheme. It allows several signers to
//! create a signature that proves a message to be signed by
//! them all, given their public keys. The signature can be
//! verified using the same function used for the standard
//! Schnorr signature, using the sum of all the signers' public keys.
//!
//! reference: https://eprint.iacr.org/2021/1375.pdf - pag. 19
//!
//! ## Feature
//!
//! Only available with the "multisig" feature enabled.
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
//! // Key verification: all signers send their public key to
//! // all the other signers, along with a Schnorr signature
//! // that proves knowledge of the corresponding secret key
//! let pk_vec = vec![pk_1, pk_2];
//!
//! // First round: all signers compute the following elements
//! let (r_1, s_1, R_1, S_1) = multisig::sign_round_1(&mut rng);
//! let (r_2, s_2, R_2, S_2) = multisig::sign_round_1(&mut rng);
//!
//! // All signers share `R_vec` and `S_vec` with all the other signers
//! let R_vec = vec![R_1, R_2];
//! let S_vec = vec![S_1, S_2];
//!
//! // Second round: all the signers compute their share `z`
//! let z_1 = multisig::sign_round_2(
//!     &sk_1,
//!     &r_1,
//!     &s_1,
//!     &pk_vec.clone(),
//!     &R_vec.clone(),
//!     &S_vec.clone(),
//!     &message,
//! )
//! .expect("Multisig Round 2 shouldn't fail");
//! let z_2 = multisig::sign_round_2(
//!     &sk_2,
//!     &r_2,
//!     &s_2,
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
//! let sig = multisig::combine(&z_vec, &pk_vec, &R_vec, &S_vec, &message);
//!
//! // Anyone can verify using the sum of all the signers' public keys
//! let pk = PublicKey::from(pk_1.as_ref() + pk_2.as_ref());
//! assert!(pk.verify(&sig, message));
//! ```

extern crate alloc;
use alloc::vec;

use ff::Field;

use dusk_jubjub::{JubJubExtended, GENERATOR_EXTENDED};
use dusk_plonk::prelude::*;
use rand_core::{CryptoRng, RngCore};

use crate::{PublicKey, SecretKey, Signature};

/// Performs the first round to sign a message using the
/// multisignature scheme
///
/// ## Parameters
///
/// - `rng`: Reference to the random number generator.
///
/// ## Returns
///
/// Returns two [`JubJubScalar`] being the scalars (r, s), and
/// two [`JubJubExtended`] being the points (R, S)
pub fn sign_round_1<R>(
    mut rng: &mut R,
) -> (JubJubScalar, JubJubScalar, JubJubExtended, JubJubExtended)
where
    R: RngCore + CryptoRng,
{
    // Sample two random values (r, s)
    let r = JubJubScalar::random(&mut rng);
    let s = JubJubScalar::random(&mut rng);

    // Compute R = r * G, S = s * G
    let R = GENERATOR_EXTENDED * r;
    let S = GENERATOR_EXTENDED * s;

    (r, s, R, S)
}

/// Performs the second round to sign a message using the
/// multisignature scheme
///
/// ## Parameters
///
/// - `sk`: Reference to the random number generator.
/// - `r`: Random value.
/// - `s`: Random value.
/// - `pk_vec`: Vector of public keys.
/// - `R_vec`: Vector of R values.
/// - `S_vec`: Vector of S values.
/// - `msg`: Message to sign.
///
/// ## Returns
///
/// Returns a [`JubJubScalar`] being the signature share 'z'
pub fn sign_round_2(
    sk: &SecretKey,
    r: &JubJubScalar,
    s: &JubJubScalar,
    pk_vec: &[PublicKey],
    R_vec: &[JubJubExtended],
    S_vec: &[JubJubExtended],
    msg: &BlsScalar,
) -> Result<JubJubScalar, MultisigError> {
    // Check if (R_i == R_j) || (S_i == S_j) for any i != j
    // and return error if so
    for i in 0..R_vec.len() {
        for j in (i + 1)..R_vec.len() {
            if R_vec[i] == R_vec[j] || S_vec[i] == S_vec[j] {
                return Err(MultisigError::DuplicatedNonce);
            }
        }
    }

    let (a, c, _RSa) = multisig_common(pk_vec, R_vec, S_vec, msg);

    // Compute the share z = r + s * a - c * sk,
    Ok(r + (s * a) - (c * sk.as_ref()))
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
/// Returns a new signature [`JubJubScalar`]
pub fn combine(
    z_vec: &[JubJubScalar],
    pk_vec: &[PublicKey],
    R_vec: &[JubJubExtended],
    S_vec: &[JubJubExtended],
    msg: &BlsScalar,
) -> Signature {
    let (_a, _c, RSa) = multisig_common(pk_vec, R_vec, S_vec, msg);

    // Sum all the shares u = z_1 + z_2 + ... + z_n for `n` signers
    let u = z_vec.iter().sum();

    Signature::new(u, RSa)
}

/// Performs some common operations required in different parts
/// of the multisignature scheme
fn multisig_common(
    pk_vec: &[PublicKey],
    R_vec: &[JubJubExtended],
    S_vec: &[JubJubExtended],
    msg: &BlsScalar,
) -> (JubJubScalar, JubJubScalar, JubJubExtended) {
    use dusk_poseidon::sponge::truncated::hash;

    // Sum all the public keys pk = pk_1 + pk_2 + ... + pk_n for `n` signers
    let mut pk = JubJubExtended::default();
    for pk_it in pk_vec {
        pk += pk_it.as_ref();
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

    let a = hash(&preimage);

    // Compute RSa = R_1 + (S_1 * a) + R_2 + (S_2 * a) + ... + R_n + (S_n *
    // a) for `n` signers
    let mut RSa = JubJubExtended::default();
    for it in 0..R_vec.len() {
        RSa = RSa + R_vec[it] + (S_vec[it] * a);
    }

    // Compute challenge c = H(RSa || pk || m);
    let RSa_coordinates = RSa.to_hash_inputs();
    let c = hash(&[
        RSa_coordinates[0],
        RSa_coordinates[1],
        pk_coordinates[0],
        pk_coordinates[1],
        *msg,
    ]);

    (a, c, RSa)
}

/// Error variants for the multisignature scheme
#[derive(Debug)]
pub enum MultisigError {
    DuplicatedNonce,
}
