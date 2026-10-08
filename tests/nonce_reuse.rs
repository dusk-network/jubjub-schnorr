// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Regression tests for hedged nonce generation.
//!
//! A weak or broken RNG that repeats output must not cause nonce reuse
//! across different (sk, message) pairs. These tests construct a
//! constant-output RNG and verify that the hedged nonce derivation
//! produces distinct nonces — making the classical nonce-reuse key
//! recovery attack impossible.

use dusk_bls12_381::BlsScalar;
use dusk_jubjub::{
    GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED, JubJubAffine, JubJubExtended,
    JubJubScalar,
};
use ff::Field;
use jubjub_schnorr::{PublicKey, PublicKeyDouble, PublicKeyVarGen, SecretKey};
use rand::SeedableRng;
use rand::rngs::StdRng;
use rand_core::{CryptoRng, RngCore};

/// An RNG that always fills buffers with the same fixed byte.
/// This simulates the worst-case scenario of a completely broken RNG.
struct ConstRng(u8);

impl RngCore for ConstRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill(self.0);
    }

    fn try_fill_bytes(
        &mut self,
        dest: &mut [u8],
    ) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for ConstRng {}

/// Recompute a single-signer challenge, `H(prefix || points || msg)`
/// truncated to a JubJub scalar.
fn challenge(
    prefix: &[BlsScalar],
    points: &[&JubJubExtended],
    msg: BlsScalar,
) -> JubJubScalar {
    let mut preimage = prefix.to_vec();
    for point in points {
        preimage.extend(point.to_hash_inputs());
    }
    preimage.push(msg);
    dusk_poseidon::Hash::digest_truncated(
        dusk_poseidon::Domain::Other,
        &preimage,
    )[0]
}

/// Hedged nonces must be uniform over the JubJub scalars, which go up to
/// about 2^251.86. A nonce truncated to 250 bits always lies below 2^250,
/// which a uniform nonce does with probability about 0.28.
#[test]
fn hedged_nonces_cover_the_scalar_field() {
    // 2^250 is the smallest scalar whose top byte is at least 4.
    let above_2_250 = |nonce: JubJubScalar| nonce.to_bytes()[31] >= 4;
    let mut rng = StdRng::seed_from_u64(0xfa);
    let sk = SecretKey::random(&mut rng);
    let pk = PublicKey::from(&sk);
    let pk_double = PublicKeyDouble::from(&sk);
    let sk_var_gen = sk
        .clone()
        .with_variable_generator(GENERATOR_EXTENDED * JubJubScalar::from(3u64));
    let pk_var_gen = PublicKeyVarGen::from(&sk_var_gen);
    let double_tag = BlsScalar::from(u64::from_be_bytes(*b"JJSCHDBL"));

    let mut above = [0; 3];
    for msg in (0..64u64).map(BlsScalar::from) {
        let sig = sk.sign(&mut rng, msg);
        let c = challenge(&[], &[sig.R(), pk.as_ref()], msg);
        let nonce = sig.u() + c * sk.as_ref();
        assert_eq!(GENERATOR_EXTENDED * nonce, *sig.R());
        above[0] += usize::from(above_2_250(nonce));

        let sig = sk.sign_double(&mut rng, msg);
        let points =
            [sig.R(), sig.R_prime(), pk_double.pk(), pk_double.pk_prime()];
        let c = challenge(&[double_tag], &points, msg);
        let nonce = sig.u() + c * sk.as_ref();
        assert_eq!(GENERATOR_NUMS_EXTENDED * nonce, *sig.R_prime());
        above[1] += usize::from(above_2_250(nonce));

        let sig = sk_var_gen.sign(&mut rng, msg);
        let points = [sig.R(), pk_var_gen.public_key(), pk_var_gen.generator()];
        let c = challenge(&[], &points, msg);
        let nonce = sig.u() + c * sk.as_ref();
        assert_eq!(pk_var_gen.generator() * nonce, *sig.R());
        above[2] += usize::from(above_2_250(nonce));
    }

    assert!(above.iter().all(|&count| count > 0), "{above:?}");
}

/// Known answers for the single-signer hedged nonces, with `sk = 42`,
/// `msg = 7`, every RNG byte `0x42`, and `G = 3 * GENERATOR_EXTENDED` for
/// the variable generator.
///
/// They were derived without this crate. `random` is the 64 RNG bytes
/// reduced modulo the JubJub order. The nonce is the Poseidon
/// `Domain::Other` digest of `random, sk, 1, msg` (standard), `random, sk,
/// 2, msg` (double) or `random, sk, G.u, G.v, msg` (variable generator),
/// reduced modulo the JubJub order. Points use the compressed affine
/// encoding.
#[test]
fn hedged_nonce_known_answers() {
    const STANDARD_R: [u8; 32] = [
        0xac, 0xbc, 0xd1, 0xd0, 0x3a, 0xd7, 0x0f, 0xbe, 0xd5, 0x82, 0xbf, 0xef,
        0xcd, 0x1e, 0x82, 0x1e, 0x0a, 0x76, 0x88, 0x11, 0xf5, 0xc5, 0xa4, 0x25,
        0x9f, 0x49, 0xda, 0x58, 0xea, 0x6d, 0x94, 0x93,
    ];
    const DOUBLE_R: [u8; 32] = [
        0xd1, 0xc7, 0x11, 0x23, 0x9d, 0x0d, 0x98, 0x18, 0x9a, 0xae, 0x87, 0xce,
        0xc9, 0xb1, 0x2e, 0x65, 0x66, 0x49, 0xeb, 0x59, 0x47, 0xdd, 0x97, 0x3c,
        0x74, 0x13, 0xee, 0xd0, 0xcd, 0x6b, 0x1f, 0xf1,
    ];
    const DOUBLE_R_PRIME: [u8; 32] = [
        0x8e, 0x1c, 0x62, 0x77, 0xfc, 0xa9, 0xf8, 0x77, 0x64, 0x66, 0xaa, 0x09,
        0x6b, 0x2c, 0xb7, 0x5e, 0x71, 0xc1, 0x03, 0x8b, 0xd2, 0x72, 0xd5, 0x34,
        0x7e, 0x22, 0x58, 0x1e, 0x00, 0x64, 0x0b, 0xed,
    ];
    const VAR_GEN_R: [u8; 32] = [
        0x29, 0xf4, 0xee, 0x93, 0x90, 0x3d, 0xd6, 0x46, 0x4b, 0x94, 0x7c, 0xc3,
        0x2f, 0x18, 0xe7, 0xc7, 0x50, 0x92, 0xb6, 0x6a, 0xf9, 0xeb, 0xa7, 0x39,
        0x7f, 0x9e, 0x90, 0x36, 0x20, 0x71, 0x68, 0xd9,
    ];

    let point = |point: &JubJubExtended| JubJubAffine::from(point).to_bytes();
    let sk = SecretKey::from(JubJubScalar::from(42u64));
    let msg = BlsScalar::from(7u64);

    let sig = sk.sign(&mut ConstRng(0x42), msg);
    assert_eq!(point(sig.R()), STANDARD_R);

    let sig = sk.sign_double(&mut ConstRng(0x42), msg);
    assert_eq!(point(sig.R()), DOUBLE_R);
    assert_eq!(point(sig.R_prime()), DOUBLE_R_PRIME);

    let sig = sk
        .with_variable_generator(GENERATOR_EXTENDED * JubJubScalar::from(3u64))
        .sign(&mut ConstRng(0x42), msg);
    assert_eq!(point(sig.R()), VAR_GEN_R);
}

/// With a broken RNG, signing two different messages must produce
/// different nonces (different R values). If R values were the same,
/// an attacker could recover the secret key.
#[test]
fn nonce_reuse_standard_sign() {
    let mut rng = StdRng::seed_from_u64(0xdead);
    let sk = SecretKey::random(&mut rng);
    let pk = PublicKey::from(&sk);

    let msg1 = BlsScalar::from(1u64);
    let msg2 = BlsScalar::from(2u64);

    let sig1 = sk.sign(&mut ConstRng(0x42), msg1);
    let sig2 = sk.sign(&mut ConstRng(0x42), msg2);

    // Both signatures must be valid
    assert!(pk.verify(&sig1, msg1).is_ok());
    assert!(pk.verify(&sig2, msg2).is_ok());

    // The nonces must differ despite the identical RNG output,
    // because the hedged derivation mixes in the message.
    assert_ne!(
        sig1.R(),
        sig2.R(),
        "nonce reuse detected: identical R with broken RNG"
    );
}

/// Same test for the double signature variant.
#[test]
fn nonce_reuse_double_sign() {
    let mut rng = StdRng::seed_from_u64(0xdead);
    let sk = SecretKey::random(&mut rng);

    let msg1 = BlsScalar::from(1u64);
    let msg2 = BlsScalar::from(2u64);

    let sig1 = sk.sign_double(&mut ConstRng(0x42), msg1);
    let sig2 = sk.sign_double(&mut ConstRng(0x42), msg2);

    assert_ne!(
        sig1.R(),
        sig2.R(),
        "nonce reuse detected: identical R with broken RNG (double)"
    );
}

/// Same test for the variable-generator variant.
#[test]
fn nonce_reuse_var_gen_sign() {
    let mut rng = StdRng::seed_from_u64(0xdead);
    let sk_base = SecretKey::random(&mut rng);
    let generator = GENERATOR_EXTENDED * JubJubScalar::random(&mut rng);
    let sk = sk_base.with_variable_generator(generator);
    let pk = PublicKeyVarGen::from(&sk);

    let msg1 = BlsScalar::from(1u64);
    let msg2 = BlsScalar::from(2u64);

    let sig1 = sk.sign(&mut ConstRng(0x42), msg1);
    let sig2 = sk.sign(&mut ConstRng(0x42), msg2);

    assert!(pk.verify(&sig1, msg1).is_ok());
    assert!(pk.verify(&sig2, msg2).is_ok());

    assert_ne!(
        sig1.R(),
        sig2.R(),
        "nonce reuse detected: identical R with broken RNG (var_gen)"
    );
}

/// With the same key and message but different generators and a broken
/// RNG, a shared nonce scalar `r` would allow key recovery via
/// `sk = (u1 - u2) / (c2 - c1)` (the challenges differ because the
/// generator is part of the VarGen challenge hash). The hedged nonce
/// mixes in the generator, so the scalar `r` itself differs and the
/// attack produces a wrong key.
#[test]
fn key_recovery_cross_generator_fails() {
    let mut rng = StdRng::seed_from_u64(0xface);
    let sk_base = SecretKey::random(&mut rng);
    let msg = BlsScalar::from(42u64);

    let g1 = GENERATOR_EXTENDED * JubJubScalar::random(&mut rng);
    let g2 = GENERATOR_EXTENDED * JubJubScalar::random(&mut rng);

    let sk1 = sk_base.clone().with_variable_generator(g1);
    let sk2 = sk_base.clone().with_variable_generator(g2);
    // sk_base is used below for the recovery check

    let pk1 = PublicKeyVarGen::from(&sk1);
    let pk2 = PublicKeyVarGen::from(&sk2);

    let sig1 = sk1.sign(&mut ConstRng(0x42), msg);
    let sig2 = sk2.sign(&mut ConstRng(0x42), msg);

    assert!(pk1.verify(&sig1, msg).is_ok());
    assert!(pk2.verify(&sig2, msg).is_ok());

    // Attempt the cross-generator key recovery attack.
    // If the nonce scalar r is shared, u1 - u2 = (c2 - c1) * sk.
    let u1 = sig1.u();
    let u2 = sig2.u();

    let hash_challenge = |r: &dusk_jubjub::JubJubExtended,
                          pk: PublicKeyVarGen,
                          m: BlsScalar|
     -> JubJubScalar {
        let r_coords = r.to_hash_inputs();
        let pk_coords = pk.public_key().to_hash_inputs();
        let gen_coords = pk.generator().to_hash_inputs();
        dusk_poseidon::Hash::digest_truncated(
            dusk_poseidon::Domain::Other,
            &[
                r_coords[0],
                r_coords[1],
                pk_coords[0],
                pk_coords[1],
                gen_coords[0],
                gen_coords[1],
                m,
            ],
        )[0]
    };

    let c1 = hash_challenge(sig1.R(), pk1, msg);
    let c2 = hash_challenge(sig2.R(), pk2, msg);

    let delta_u = u1 - u2;
    let delta_c = c2 - c1;

    if let Some(delta_c_inv) = Option::<JubJubScalar>::from(delta_c.invert()) {
        let recovered_sk = SecretKey::from(delta_u * delta_c_inv);

        assert_ne!(
            recovered_sk, sk_base,
            "cross-generator key recovery succeeded — generator not \
             mixed into nonce derivation"
        );
    }
}

/// The nonce binds the generator's affine coordinates, so extended
/// representations sharing them must sign identically. Otherwise a repeated
/// nonce under differing challenges reveals the secret key.
#[test]
fn affine_alias_generators_sign_identically() {
    let g = GENERATOR_EXTENDED;
    // Same affine coordinates as `g`, but an inconsistent `T1 * T2`.
    let alias = JubJubExtended::from_raw_unchecked(
        g.get_u(),
        g.get_v(),
        g.get_z(),
        -g.get_t1(),
        g.get_t2(),
    );
    let sk = SecretKey::from(JubJubScalar::from(42u64));
    let msg = BlsScalar::from(42u64);

    let sig = sk
        .clone()
        .with_variable_generator(g)
        .sign(&mut ConstRng(0x42), msg);
    let sig_alias = sk
        .with_variable_generator(alias)
        .sign(&mut ConstRng(0x42), msg);

    assert_eq!(sig, sig_alias);
}

/// Verify that the classical nonce-reuse key recovery attack fails
/// when hedged nonces are used.
///
/// Attack: given two signatures (u1, R) and (u2, R) with the same R,
///   sk = (u1 - u2) / (c2 - c1)
/// With hedged nonces, R1 != R2 even under a broken RNG, so the
/// "recovered" key will be wrong.
#[test]
fn key_recovery_attack_fails() {
    let mut rng = StdRng::seed_from_u64(0xbeef);
    let sk = SecretKey::random(&mut rng);
    let pk = PublicKey::from(&sk);

    let msg1 = BlsScalar::from(100u64);
    let msg2 = BlsScalar::from(200u64);

    let sig1 = sk.sign(&mut ConstRng(0xAA), msg1);
    let sig2 = sk.sign(&mut ConstRng(0xAA), msg2);

    assert!(pk.verify(&sig1, msg1).is_ok());
    assert!(pk.verify(&sig2, msg2).is_ok());

    // Attempt the key recovery attack assuming same nonce
    let u1 = sig1.u();
    let u2 = sig2.u();

    // If R1 == R2 (nonce reuse), then u1 - u2 = (c2 - c1) * sk.
    // But with hedged nonces R1 != R2, so the formula yields garbage.
    // We verify the "recovered" key does NOT match the real public key.
    // Recompute challenge hashes the same way the signature scheme does
    let hash_challenge = |r: &dusk_jubjub::JubJubExtended,
                          pk: &PublicKey,
                          m: BlsScalar|
     -> JubJubScalar {
        let r_coords = r.to_hash_inputs();
        let pk_coords = pk.as_ref().to_hash_inputs();
        dusk_poseidon::Hash::digest_truncated(
            dusk_poseidon::Domain::Other,
            &[r_coords[0], r_coords[1], pk_coords[0], pk_coords[1], m],
        )[0]
    };

    let c1 = hash_challenge(sig1.R(), &pk, msg1);
    let c2 = hash_challenge(sig2.R(), &pk, msg2);

    let delta_u = u1 - u2;
    let delta_c = c2 - c1;

    // If delta_c is zero, the attack is inapplicable regardless
    if let Some(delta_c_inv) = Option::<JubJubScalar>::from(delta_c.invert()) {
        let recovered_sk = SecretKey::from(delta_u * delta_c_inv);

        assert_ne!(
            recovered_sk, sk,
            "key recovery attack succeeded — nonce hedging is broken"
        );
    }
}

/// With the same key and message under a broken RNG, `sign` and
/// `sign_double` currently call `hedged_nonce` with identical inputs,
/// producing the same nonce `r`. Since the challenge hashes differ
/// between variants, an attacker with both signatures can recover the
/// secret key: `sk = (u1 - u2) / (c2 - c1)`.
///
/// This test demonstrates that cross-variant nonce reuse is prevented
/// by variant-specific domain separation in the nonce derivation.
#[test]
fn key_recovery_cross_variant_fails() {
    let mut rng = StdRng::seed_from_u64(0xcafe);
    let sk = SecretKey::random(&mut rng);
    let pk = PublicKey::from(&sk);
    let msg = BlsScalar::from(77u64);

    // Sign the same message with the same key using both variants
    // under a broken RNG that always produces the same output.
    let sig_std = sk.sign(&mut ConstRng(0x42), msg);
    let sig_dbl = sk.sign_double(&mut ConstRng(0x42), msg);

    // Both signatures must be independently valid
    assert!(pk.verify(&sig_std, msg).is_ok());

    let pk_dbl = jubjub_schnorr::PublicKeyDouble::from(&sk);
    assert!(pk_dbl.verify(&sig_dbl, msg).is_ok());

    // Attempt the cross-variant key recovery attack.
    // Standard challenge: H(R_x, R_y, pk_x, pk_y, msg)
    let r_std = sig_std.R();
    let r_std_coords = r_std.to_hash_inputs();
    let pk_coords = pk.as_ref().to_hash_inputs();
    let c_std: JubJubScalar = dusk_poseidon::Hash::digest_truncated(
        dusk_poseidon::Domain::Other,
        &[
            r_std_coords[0],
            r_std_coords[1],
            pk_coords[0],
            pk_coords[1],
            msg,
        ],
    )[0];

    // Double challenge:
    // H(tag, R_x, R_y, R'_x, R'_y, pk_x, pk_y, pk'_x, pk'_y, msg)
    let r_dbl = sig_dbl.R();
    let r_dbl_coords = r_dbl.to_hash_inputs();
    let r_prime = sig_dbl.R_prime();
    let r_prime_coords = r_prime.to_hash_inputs();
    let pk_prime_coords = pk_dbl.pk_prime().to_hash_inputs();
    let c_dbl: JubJubScalar = dusk_poseidon::Hash::digest_truncated(
        dusk_poseidon::Domain::Other,
        &[
            BlsScalar::from(u64::from_be_bytes(*b"JJSCHDBL")),
            r_dbl_coords[0],
            r_dbl_coords[1],
            r_prime_coords[0],
            r_prime_coords[1],
            pk_coords[0],
            pk_coords[1],
            pk_prime_coords[0],
            pk_prime_coords[1],
            msg,
        ],
    )[0];

    // Pin the reconstructed challenges to every verification equation so this
    // regression fails if either hand-written transcript drifts.
    assert_eq!(
        GENERATOR_EXTENDED * sig_std.u() + pk.as_ref() * c_std,
        *sig_std.R()
    );
    assert_eq!(
        GENERATOR_EXTENDED * sig_dbl.u() + pk_dbl.pk() * c_dbl,
        *sig_dbl.R()
    );
    assert_eq!(
        GENERATOR_NUMS_EXTENDED * sig_dbl.u() + pk_dbl.pk_prime() * c_dbl,
        *sig_dbl.R_prime()
    );

    // If nonce r is shared: u_std - u_dbl = (c_dbl - c_std) * sk
    let delta_u = sig_std.u() - sig_dbl.u();
    let delta_c = c_dbl - c_std;

    if let Some(delta_c_inv) = Option::<JubJubScalar>::from(delta_c.invert()) {
        let recovered_sk = SecretKey::from(delta_u * delta_c_inv);

        assert_ne!(
            recovered_sk, sk,
            "cross-variant key recovery succeeded — sign and \
             sign_double share nonces without domain separation"
        );
    }
}
