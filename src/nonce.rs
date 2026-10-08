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
//!
//! The hash input and the Poseidon digest hold the secret key and the
//! nonce, so both are wiped once the nonce is derived. Copies the compiler
//! keeps in registers or on the stack are not.

extern crate alloc;
use alloc::vec::Vec;

use dusk_bls12_381::BlsScalar;
use dusk_jubjub::{JubJubExtended, JubJubScalar};
use dusk_poseidon::{Domain, Hash};
use ff::Field;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

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
    let input = Zeroizing::new([rng_bls, sk_bls, TAG_STANDARD, msg]);
    let [nonce] = nonces(Hash::digest(Domain::Other, input.as_ref()));
    nonce
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
    let input = Zeroizing::new([rng_bls, sk_bls, TAG_DOUBLE, msg]);
    let [nonce] = nonces(Hash::digest(Domain::Other, input.as_ref()));
    nonce
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
    let input =
        Zeroizing::new([rng_bls, sk_bls, gen_coords[0], gen_coords[1], msg]);
    let [nonce] = nonces(Hash::digest(Domain::Other, input.as_ref()));
    nonce
}

/// Reduce each digest element modulo the JubJub scalar order and wipe the
/// digest.
///
/// The BLS12-381 scalar modulus exceeds eight times the JubJub order by less
/// than 2^126, so a uniform digest reduces to a nonce within 2^-129 of
/// uniform.
/// Truncating the digest to 250 bits, as `Hash::digest_truncated` does,
/// would only reach the nonces below 2^250, about 28% of the scalars.
fn nonces<const N: usize>(digest: Vec<BlsScalar>) -> [JubJubScalar; N] {
    let digest = Zeroizing::new(digest);
    core::array::from_fn(|i| {
        JubJubScalar::from_bytes_wide(&widen(digest[i].to_bytes()))
    })
}

/// Draw randomness and convert inputs to BlsScalar for Poseidon.
fn prepare_inputs<R>(rng: &mut R, sk: &JubJubScalar) -> (BlsScalar, BlsScalar)
where
    R: RngCore + CryptoRng,
{
    let mut rng_scalar = JubJubScalar::random(rng);

    // Both JubJubScalar and BlsScalar are 32-byte little-endian field
    // elements. The JubJub scalar field is smaller than the BLS scalar
    // field, so every JubJubScalar byte representation is a valid
    // BlsScalar.
    let rng_bls = BlsScalar::from_bytes_wide(&widen(rng_scalar.to_bytes()));
    let sk_bls = BlsScalar::from_bytes_wide(&widen(sk.to_bytes()));
    rng_scalar.zeroize();
    (rng_bls, sk_bls)
}

/// Zero-extend a 32-byte array to 64 bytes for `from_bytes_wide`. Both
/// arrays are wiped once used.
fn widen(mut bytes: [u8; 32]) -> Zeroizing<[u8; 64]> {
    let mut wide = Zeroizing::new([0u8; 64]);
    wide[..32].copy_from_slice(&bytes);
    bytes.zeroize();
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
    fn nonce_digest_is_reduced_and_erased() {
        let mut rng = StdRng::seed_from_u64(16);
        for len in [4, 5] {
            for _ in 0..8 {
                let input =
                    [BlsScalar::zero(); 5].map(|_| BlsScalar::random(&mut rng));
                let input = &input[..len];
                let mut wide = [0u8; 64];
                wide[..32].copy_from_slice(
                    &Hash::digest(Domain::Other, input)[0].to_bytes(),
                );
                let expected = JubJubScalar::from_bytes_wide(&wide);
                let digest = Hash::digest(Domain::Other, input);
                let ptr = digest.as_ptr().cast::<u8>().cast_mut();
                let bytes = core::mem::size_of_val(digest.as_slice());
                WATCH.with(|watch| watch.set((ptr, bytes, false)));
                assert_eq!(nonces(digest), [expected]);
                WATCH.with(|watch| assert!(watch.get().2, "digest not erased"));
            }
        }
    }
}
