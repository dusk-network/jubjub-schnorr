// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bls12_381::BlsScalar;
use dusk_bytes::Serializable;
use dusk_jubjub::{
    GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED, JubJubAffine, JubJubScalar,
};
use dusk_poseidon::{Domain, Hash};
use ff::Field;
use jubjub_schnorr::{Error, PublicKeyDouble, SecretKey, SignatureDouble};
use rand::SeedableRng;
use rand::rngs::StdRng;

#[test]
fn sign_verify() {
    let mut rng = StdRng::seed_from_u64(2321u64);

    let sk = SecretKey::random(&mut rng);
    let message = BlsScalar::random(&mut rng);
    let pk_double = PublicKeyDouble::from(&sk);

    let sig = sk.sign_double(&mut rng, message);

    assert!(pk_double.verify(&sig, message).is_ok());
}

#[test]
fn test_wrong_keys() {
    let mut rng = StdRng::seed_from_u64(2321u64);

    let sk = SecretKey::random(&mut rng);
    let message = BlsScalar::random(&mut rng);

    let sig = sk.sign_double(&mut rng, message);

    // Derive random public key
    let wrong_sk = SecretKey::random(&mut rng);
    let pk_double = PublicKeyDouble::from(&wrong_sk);

    assert_eq!(
        Error::InvalidSignature,
        pk_double.verify(&sig, message).unwrap_err()
    );
}

#[test]
fn to_from_bytes() {
    let mut rng = StdRng::seed_from_u64(2321u64);

    let sk = SecretKey::random(&mut rng);
    let message = BlsScalar::random(&mut rng);

    let sig = sk.sign_double(&mut rng, message);
    assert_eq!(sig, SignatureDouble::from_bytes(&sig.to_bytes()).unwrap());
}

#[test]
fn sign_verify_identity_fails() {
    let mut rng = StdRng::seed_from_u64(0xbeef);
    let msg = BlsScalar::random(&mut rng);
    let sk = SecretKey::from(JubJubScalar::zero());
    let pk = PublicKeyDouble::from(&sk);
    let sig = sk.sign_double(&mut rng, msg);

    assert_eq!(pk.verify(&sig, msg).unwrap_err(), Error::InvalidPoint);
}

#[test]
fn adaptive_secondary_key_is_rejected() {
    let sk = SecretKey::from(JubJubScalar::from(17u64));
    let pk = PublicKeyDouble::from(&sk);
    let msg = BlsScalar::from(23u64);
    let nonce = JubJubScalar::from(31u64);
    let r = GENERATOR_EXTENDED * nonce;
    let r_prime = GENERATOR_NUMS_EXTENDED * JubJubScalar::from(37u64);

    // Recreate the legacy challenge, which omitted PK'. Knowing the primary
    // scalar then lets an attacker solve the second equation for PK'.
    let r_coordinates = r.to_hash_inputs();
    let r_p_coordinates = r_prime.to_hash_inputs();
    let pk_coordinates = pk.pk().to_hash_inputs();
    let legacy_challenge: JubJubScalar = Hash::digest_truncated(
        Domain::Other,
        &[
            r_coordinates[0],
            r_coordinates[1],
            r_p_coordinates[0],
            r_p_coordinates[1],
            pk_coordinates[0],
            pk_coordinates[1],
            msg,
        ],
    )[0];
    let inverse_challenge = legacy_challenge
        .invert()
        .expect("the deterministic legacy challenge is nonzero");
    let u = nonce - legacy_challenge * sk.as_ref();
    let pk_prime = (r_prime - GENERATOR_NUMS_EXTENDED * u) * inverse_challenge;

    let forged_pk = PublicKeyDouble::from_raw_unchecked(*pk.pk(), pk_prime);
    let mut signature_bytes = [0u8; 96];
    signature_bytes[..32].copy_from_slice(&u.to_bytes());
    signature_bytes[32..64].copy_from_slice(&JubJubAffine::from(r).to_bytes());
    signature_bytes[64..]
        .copy_from_slice(&JubJubAffine::from(r_prime).to_bytes());
    let signature = SignatureDouble::from_bytes(&signature_bytes)
        .expect("the attack fixture uses valid subgroup points");

    assert!(forged_pk.is_valid());
    assert_eq!(
        forged_pk.verify(&signature, msg),
        Err(Error::InvalidSignature)
    );
}
