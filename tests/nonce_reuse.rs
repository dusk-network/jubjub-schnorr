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
use dusk_jubjub::{GENERATOR_EXTENDED, JubJubScalar};
use ff::Field;
use jubjub_schnorr::{PublicKey, PublicKeyVarGen, SecretKey};
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
