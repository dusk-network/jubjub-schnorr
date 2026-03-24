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

/// Generate a hedged nonce by mixing RNG output with deterministic
/// data derived from the secret key and message.
///
/// `nonce = H(random || sk || msg)` where H is the Poseidon hash
/// truncated to the JubJub scalar field.
pub(crate) fn hedged_nonce<R>(
    rng: &mut R,
    sk: &JubJubScalar,
    msg: BlsScalar,
) -> JubJubScalar
where
    R: RngCore + CryptoRng,
{
    hedged_nonce_with_generator(rng, sk, msg, None)
}

/// Generate a hedged nonce, optionally including a generator point.
///
/// For the variable-generator variant, the generator is included in the
/// hash to prevent cross-generator nonce reuse when the same key signs
/// the same message under different generators with a broken RNG.
pub(crate) fn hedged_nonce_with_generator<R>(
    rng: &mut R,
    sk: &JubJubScalar,
    msg: BlsScalar,
    generator: Option<&JubJubExtended>,
) -> JubJubScalar
where
    R: RngCore + CryptoRng,
{
    // Draw randomness from the RNG
    let rng_scalar = JubJubScalar::random(rng);

    // Convert the secret key and RNG scalar to BlsScalar for Poseidon.
    // Both JubJubScalar and BlsScalar are 32-byte little-endian field
    // elements. The JubJub scalar field is smaller than the BLS scalar
    // field, so every JubJubScalar byte representation is a valid
    // BlsScalar.
    let rng_bls = BlsScalar::from_bytes_wide(&widen(rng_scalar.to_bytes()));
    let sk_bls = BlsScalar::from_bytes_wide(&widen(sk.to_bytes()));

    match generator {
        Some(g) => {
            let gen_coords = g.to_hash_inputs();
            // H(rng || sk || gen_x || gen_y || msg) -> JubJubScalar
            Hash::digest_truncated(
                Domain::Other,
                &[rng_bls, sk_bls, gen_coords[0], gen_coords[1], msg],
            )[0]
        }
        // H(rng || sk || msg) -> JubJubScalar
        None => {
            Hash::digest_truncated(Domain::Other, &[rng_bls, sk_bls, msg])[0]
        }
    }
}

/// Zero-extend a 32-byte array to 64 bytes for `from_bytes_wide`.
fn widen(bytes: [u8; 32]) -> [u8; 64] {
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&bytes);
    wide
}
