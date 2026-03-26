// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Hedged nonce generation for Schnorr signing.
//!
//! Produces a nonce by hashing RNG output together with the secret key
//! and message. This ensures that nonce reuse requires *both* a
//! repeated RNG output *and* an identical (sk, message) pair —
//! defending against weak or broken RNGs.

use dusk_bls12_381::BlsScalar;
use dusk_jubjub::{JubJubExtended, JubJubScalar};
use dusk_poseidon::{Domain, Hash};
use ff::Field;
use rand_core::{CryptoRng, RngCore};

/// Domain separator tags for variant-specific nonce derivation.
///
/// These prevent cross-variant nonce reuse: without them, `sign` and
/// `sign_double` would produce the same nonce for the same (sk, msg)
/// under a broken RNG, enabling key recovery via the differing
/// challenge hashes.
const TAG_STANDARD: BlsScalar = BlsScalar::from_raw([1, 0, 0, 0]);
const TAG_DOUBLE: BlsScalar = BlsScalar::from_raw([2, 0, 0, 0]);

/// Generate a hedged nonce for the standard Schnorr signature.
///
/// `nonce = H(random || sk || tag_standard || msg)`
pub(crate) fn hedged_nonce<R>(
    rng: &mut R,
    sk: &JubJubScalar,
    msg: BlsScalar,
) -> JubJubScalar
where
    R: RngCore + CryptoRng,
{
    let (rng_bls, sk_bls) = prepare_inputs(rng, sk);
    // H(rng || sk || tag || msg) -> JubJubScalar
    Hash::digest_truncated(Domain::Other, &[rng_bls, sk_bls, TAG_STANDARD, msg])
        [0]
}

/// Generate a hedged nonce for the double Schnorr signature.
///
/// `nonce = H(random || sk || tag_double || msg)`
pub(crate) fn hedged_nonce_double<R>(
    rng: &mut R,
    sk: &JubJubScalar,
    msg: BlsScalar,
) -> JubJubScalar
where
    R: RngCore + CryptoRng,
{
    let (rng_bls, sk_bls) = prepare_inputs(rng, sk);
    // H(rng || sk || tag || msg) -> JubJubScalar
    Hash::digest_truncated(Domain::Other, &[rng_bls, sk_bls, TAG_DOUBLE, msg])
        [0]
}

/// Generate a hedged nonce for the variable-generator variant.
///
/// The generator coordinates serve as an implicit domain separator,
/// so no additional tag is needed.
///
/// `nonce = H(random || sk || gen_x || gen_y || msg)`
pub(crate) fn hedged_nonce_var_gen<R>(
    rng: &mut R,
    sk: &JubJubScalar,
    msg: BlsScalar,
    generator: &JubJubExtended,
) -> JubJubScalar
where
    R: RngCore + CryptoRng,
{
    let (rng_bls, sk_bls) = prepare_inputs(rng, sk);
    let gen_coords = generator.to_hash_inputs();
    // H(rng || sk || gen_x || gen_y || msg) -> JubJubScalar
    Hash::digest_truncated(
        Domain::Other,
        &[rng_bls, sk_bls, gen_coords[0], gen_coords[1], msg],
    )[0]
}

/// Draw randomness and convert inputs to BlsScalar for Poseidon.
fn prepare_inputs<R>(rng: &mut R, sk: &JubJubScalar) -> (BlsScalar, BlsScalar)
where
    R: RngCore + CryptoRng,
{
    let rng_scalar = JubJubScalar::random(rng);

    // Both JubJubScalar and BlsScalar are 32-byte little-endian field
    // elements. The JubJub scalar field is smaller than the BLS scalar
    // field, so every JubJubScalar byte representation is a valid
    // BlsScalar.
    let rng_bls = BlsScalar::from_bytes_wide(&widen(rng_scalar.to_bytes()));
    let sk_bls = BlsScalar::from_bytes_wide(&widen(sk.to_bytes()));
    (rng_bls, sk_bls)
}

/// Zero-extend a 32-byte array to 64 bytes for `from_bytes_wide`.
fn widen(bytes: [u8; 32]) -> [u8; 64] {
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&bytes);
    wide
}
