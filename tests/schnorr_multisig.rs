// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg(feature = "alloc")]

use dusk_bls12_381::BlsScalar;
use dusk_bytes::Serializable;
use dusk_jubjub::GENERATOR_EXTENDED;
use ff::Field;
use jubjub_schnorr::{Error, PublicKey, SecretKey, Signature, multisig};
use rand::SeedableRng;
use rand::rngs::StdRng;

#[test]
#[allow(non_snake_case)]
fn sign_verify() {
    let mut rng = StdRng::seed_from_u64(2321u64);

    // signer 1
    let sk_1 = SecretKey::random(&mut rng);
    let pk_1 = PublicKey::from(&sk_1);

    // signer 2
    let sk_2 = SecretKey::random(&mut rng);
    let pk_2 = PublicKey::from(&sk_2);

    let message = BlsScalar::random(&mut rng);

    // Key verification: all signers send their public key to
    // all the other signers, along with a Schnorr signature
    // that proves knowledge of the corresponding secret key
    let pk_vec = vec![pk_1, pk_2];

    // First round: all signers compute the following elements
    let (r_1, s_1, R_1, S_1) = multisig::sign_round_1(&mut rng);
    let (r_2, s_2, R_2, S_2) = multisig::sign_round_1(&mut rng);

    // All signers share `R_vec` and `S_vec` with all the other signers
    let R_vec = vec![R_1, R_2];
    let S_vec = vec![S_1, S_2];

    // Second round: all the signers compute their share `z`
    let z_1 = multisig::sign_round_2(
        &sk_1,
        &r_1,
        &s_1,
        &pk_vec.clone(),
        &R_vec.clone(),
        &S_vec.clone(),
        &message,
    )
    .expect("Multisig Round 2 shouldn't fail");
    let z_2 = multisig::sign_round_2(
        &sk_2,
        &r_2,
        &s_2,
        &pk_vec.clone(),
        &R_vec.clone(),
        &S_vec.clone(),
        &message,
    )
    .expect("Multisig Round 2 shouldn't fail");

    // All signers share their share `z` with a signer wishing to combine them
    // all
    let z_vec = vec![z_1, z_2];

    // A signer combines all the shares into a signature `sig`
    let sig = multisig::combine(&z_vec, &pk_vec, &R_vec, &S_vec, &message);

    // Anyone can verify using the sum of all the signers' public keys
    let pk = PublicKey::from(pk_1.as_ref() + pk_2.as_ref());
    assert!(pk.verify(&sig, message).is_ok());

    // We test using a wrong public key
    let pk_wrong = PublicKey::from(pk_1.as_ref() + pk_1.as_ref());
    assert_eq!(
        Error::InvalidSignature,
        pk_wrong.verify(&sig, message).unwrap_err()
    );

    // We test `to_from_bytes``
    assert_eq!(sig, Signature::from_bytes(&sig.to_bytes()).unwrap());
}

/// Regression test for the rogue-key attack on multisig.
///
/// A malicious signer crafts their public key to cancel an honest
/// signer's key, gaining sole control of the aggregate key. The protocol
/// must reject any signer whose secret key does not correspond to a
/// registered public key — this prevents the attacker from computing a
/// valid share for the rogue key.
#[test]
#[allow(non_snake_case)]
fn rogue_key_attack() {
    let mut rng = StdRng::seed_from_u64(0xdeadbeef);

    // Honest Alice generates her keypair
    let sk_alice = SecretKey::random(&mut rng);
    let pk_alice = PublicKey::from(&sk_alice);

    // Mallory picks her own secret key
    let sk_mallory = SecretKey::random(&mut rng);

    // Mallory crafts a rogue public key: pk_m = G * sk_m - pk_alice
    // This makes the aggregate key pk_alice + pk_m = G * sk_m
    let pk_mallory_rogue = PublicKey::from(
        GENERATOR_EXTENDED * sk_mallory.as_ref() - pk_alice.as_ref(),
    );

    // Confirm the aggregate key is controlled by Mallory
    let pk_agg = PublicKey::from(pk_alice.as_ref() + pk_mallory_rogue.as_ref());
    assert_eq!(
        pk_agg,
        PublicKey::from(&sk_mallory),
        "aggregate key should equal Mallory's real public key"
    );

    let message = BlsScalar::random(&mut rng);

    // Both signers participate in round 1
    let (_r_1, _s_1, R_1, S_1) = multisig::sign_round_1(&mut rng);
    let (r_2, s_2, R_2, S_2) = multisig::sign_round_1(&mut rng);

    let pk_vec = vec![pk_alice, pk_mallory_rogue];
    let R_vec = vec![R_1, R_2];
    let S_vec = vec![S_1, S_2];

    // Mallory calls sign_round_2 with her real secret key sk_m, which
    // does NOT correspond to her rogue public key pk_mallory_rogue in
    // pk_vec. The protocol must reject this.
    let result = multisig::sign_round_2(
        &sk_mallory,
        &r_2,
        &s_2,
        &pk_vec,
        &R_vec,
        &S_vec,
        &message,
    );
    assert!(
        result.is_err(),
        "sign_round_2 must reject a signer whose secret key does not \
         match any registered public key"
    );
}

#[test]
#[should_panic]
#[allow(non_snake_case)]
fn duplicated_nonce() {
    let mut rng = StdRng::seed_from_u64(2321u64);

    let sk = SecretKey::random(&mut rng);
    let pk_vec = vec![];

    let message = BlsScalar::random(&mut rng);

    let (r, s, R, S) = multisig::sign_round_1(&mut rng);

    let R_vec = vec![R, R]; // duplicated nonce
    let S_vec = vec![S, S]; // duplicated nonce

    let _z = multisig::sign_round_2(
        &sk,
        &r,
        &s,
        &pk_vec.clone(),
        &R_vec.clone(),
        &S_vec.clone(),
        &message,
    )
    .expect("Multisig Round 2 should fail");
}
