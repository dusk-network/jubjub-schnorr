// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Hedged nonce generation for Schnorr signing.
//!
//! Hashes RNG output together with the secret key and the message for
//! single-party signing, or a caller-guaranteed unique session ID for
//! multisignatures. Repeated randomness alone must not repeat nonces
//! across distinct transcripts.

extern crate alloc;
use alloc::vec::Vec;

use dusk_bls12_381::BlsScalar;
use dusk_jubjub::{JubJubExtended, JubJubScalar};
use dusk_poseidon::{Domain, Hash};
use ff::Field;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

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
    truncate_nonce(Hash::digest(
        Domain::Other,
        &[rng_bls, sk_bls, TAG_STANDARD, msg],
    ))
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
    truncate_nonce(Hash::digest(
        Domain::Other,
        &[rng_bls, sk_bls, TAG_DOUBLE, msg],
    ))
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
    truncate_nonce(Hash::digest(
        Domain::Other,
        &[rng_bls, sk_bls, gen_coords[0], gen_coords[1], msg],
    ))
}

/// Separate multisig roles and bind a caller-guaranteed unique session.
/// Six field elements also separate this transcript from the existing
/// standard/double (four) and variable-generator (five) nonce transcripts.
#[cfg(feature = "alloc")]
pub(crate) fn hedged_multisig_nonces<R>(
    rng: &mut R,
    sk: &JubJubScalar,
    session_id: &[u8; 32],
) -> [JubJubScalar; 2]
where
    R: RngCore + CryptoRng,
{
    let (random, secret) = prepare_inputs(rng, sk);
    let mut inputs = Zeroizing::new([
        random,
        secret,
        BlsScalar::from(3u64),
        BlsScalar::zero(),
        BlsScalar::zero(),
        BlsScalar::zero(),
    ]);
    // Encode all 256 session bits injectively, rather than reducing modulo q.
    for (field, chunk) in
        inputs[4..].iter_mut().zip(session_id.as_chunks::<16>().0)
    {
        let mut wide = [0u8; 64];
        wide[..16].copy_from_slice(chunk);
        *field = BlsScalar::from_bytes_wide(&wide);
    }
    let r = truncate_nonce(Hash::digest(Domain::Other, inputs.as_ref()));
    inputs[3] = BlsScalar::one();
    let s = truncate_nonce(Hash::digest(Domain::Other, inputs.as_ref()));
    [r, s]
}

/// Preserve Poseidon's 250-bit truncation, but wipe its owned digest before
/// deallocation. `digest_truncated` leaves both its intermediate BLS vector
/// and its returned Jubjub vector unwiped; avoid the latter allocation.
fn truncate_nonce(output: Vec<BlsScalar>) -> JubJubScalar {
    const TRUNCATION_MASK: BlsScalar = BlsScalar::from_raw([
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
        0x03ff_ffff_ffff_ffff,
    ]);
    let output = Zeroizing::new(output);
    JubJubScalar::from_raw((output[0] & TRUNCATION_MASK).reduce().0)
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

#[cfg(test)]
mod tests {
    extern crate std;
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;

    use rand::SeedableRng;
    use rand::rngs::StdRng;

    use super::*;

    std::thread_local! {
        // Watch only this test thread's exact, initialized digest buffer.
        static WATCH: Cell<(*mut u8, usize, bool)> =
            const { Cell::new((core::ptr::null_mut(), 0, false)) };
    }

    struct InspectDigest;
    #[global_allocator]
    static ALLOCATOR: InspectDigest = InspectDigest;

    // SAFETY: allocation and deallocation are forwarded unchanged to System.
    // The observer neither allocates nor panics, and reads only the registered
    // buffer's initialized scalar bytes, BEFORE System deallocates them.
    unsafe impl GlobalAlloc for InspectDigest {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            // TLS may already be destroyed during thread teardown.
            let _ = WATCH.try_with(|watch| {
                let (target, len, _) = watch.get();
                if ptr == target {
                    let erased = (0..len)
                        .all(|i| unsafe { ptr.add(i).read_volatile() == 0 });
                    watch.set((core::ptr::null_mut(), 0, erased));
                }
            });
            unsafe { System.dealloc(ptr, layout) }
        }
    }

    #[test]
    fn nonce_digest_is_compatible_and_erased() {
        let mut rng = StdRng::seed_from_u64(16);
        for len in [4, 5, 6] {
            for _ in 0..8 {
                let input =
                    [BlsScalar::zero(); 6].map(|_| BlsScalar::random(&mut rng));
                let input = &input[..len];
                let expected = Hash::digest_truncated(Domain::Other, input)[0];
                let output = Hash::digest(Domain::Other, input);
                let ptr = output.as_ptr().cast::<u8>().cast_mut();
                let bytes = core::mem::size_of_val(output.as_slice());
                WATCH.with(|watch| watch.set((ptr, bytes, false)));
                assert_eq!(truncate_nonce(output), expected);
                WATCH.with(|watch| assert!(watch.get().2, "digest not erased"));
            }
        }
    }
}
