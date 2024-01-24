// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bls12_381::BlsScalar;
use dusk_bytes::Serializable;
use ff::Field;
use jubjub_schnorr::{PublicKey, SecretKey, SecretKeyMultisig, Signature};
use rand::rngs::StdRng;
use rand::SeedableRng;

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
    let (r_1, s_1, R_1, S_1) = SecretKey::multisig_sign_round_1(&mut rng);
    let (r_2, s_2, R_2, S_2) = SecretKey::multisig_sign_round_1(&mut rng);

    // All signers share `R_vec` and `S_vec` with all the other signers
    let R_vec = vec![R_1, R_2];
    let S_vec = vec![S_1, S_2];

    // Second round: all the signers compute their share `z`
    let z_1 = sk_1
        .multisig_sign_round_2(
            r_1,
            s_1,
            pk_vec.clone(),
            R_vec.clone(),
            S_vec.clone(),
            message,
        )
        .expect("Multisig Round 2 failed");
    let z_2 = sk_2
        .multisig_sign_round_2(
            r_2,
            s_2,
            pk_vec.clone(),
            R_vec.clone(),
            S_vec.clone(),
            message,
        )
        .expect("Multisig Round 2 failed");

    // All signers share their share `z` with a signer wishing to combine them
    // all
    let z_vec = vec![z_1, z_2];

    // A signer combines all the shares into a signature `sig`
    let sig = SecretKey::multisig_combine(z_vec, pk_vec, R_vec, S_vec, message);

    // Anyone can verify using the sum of all the signers' public keys
    let pk = PublicKey::from(pk_1.as_ref() + pk_2.as_ref());
    assert!(pk.verify(&sig, message));

    // We test using a wrong public key
    let pk_wrong = PublicKey::from(pk_1.as_ref() + pk_1.as_ref());
    assert!(!pk_wrong.verify(&sig, message));

    // We test `to_from_bytes``
    assert_eq!(sig, Signature::from_bytes(&sig.to_bytes()).unwrap());
}

#[test]
#[should_panic]
#[allow(non_snake_case)]
fn duplicated_nonce() {
    let mut rng = StdRng::seed_from_u64(2321u64);

    let sk = SecretKey::random(&mut rng);
    let pk_vec = vec![];

    let message = BlsScalar::random(&mut rng);

    let (r, s, R, S) = SecretKey::multisig_sign_round_1(&mut rng);

    let R_vec = vec![R, R]; // duplicated nonce
    let S_vec = vec![S, S]; // duplicated nonce

    let _z = sk
        .multisig_sign_round_2(
            r,
            s,
            pk_vec.clone(),
            R_vec.clone(),
            S_vec.clone(),
            message,
        )
        .expect("Multisig Round 2 failed");
}
