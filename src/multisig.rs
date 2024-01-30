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
//! # Feature
//!
//! Only available with the "multisig" feature enabled.

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
/// ## Returns
///
/// Returns two [`JubJubScalar`] being the scalars (r, s), and
/// two [`JubJubExtended`] being the points (R, S)
pub fn multisig_sign_round_1<R>(
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
/// ## Returns
///
/// Returns a [`JubJubScalar`] being the signature share 'z'
pub fn multisig_sign_round_2(
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

/// Combines all the multisignature shares `z_vec` and returns
/// a new signature [`JubJubScalar`]
pub fn multisig_combine(
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
