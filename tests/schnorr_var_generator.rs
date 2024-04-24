// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bls12_381::BlsScalar;
use dusk_bytes::Serializable;
use dusk_jubjub::{JubJubScalar, GENERATOR_EXTENDED};
use ff::Field;
use jubjub_schnorr::{
    Error, PublicKeyVarGen, SecretKeyVarGen, SignatureVarGen,
};
use rand::rngs::StdRng;
use rand::SeedableRng;

#[test]
fn sign_verify() {
    let mut rng = StdRng::seed_from_u64(2321u64);

    let sk = SecretKeyVarGen::random(&mut rng);
    let message = BlsScalar::random(&mut rng);
    let pk = PublicKeyVarGen::from(&sk);

    let sig = sk.sign(&mut rng, message);

    assert!(pk.verify(&sig, message).is_ok());
}

#[test]
fn test_wrong_keys() {
    let mut rng = StdRng::seed_from_u64(2321u64);

    let sk = SecretKeyVarGen::random(&mut rng);
    let message = BlsScalar::random(&mut rng);

    let sig = sk.sign(&mut rng, message);

    // Derive random public key
    let pk = PublicKeyVarGen::from(&SecretKeyVarGen::random(&mut rng));

    assert_eq!(
        Error::InvalidSignature,
        pk.verify(&sig, message).unwrap_err()
    );
}

#[test]
fn to_from_bytes() {
    let mut rng = StdRng::seed_from_u64(2321u64);

    let sk = SecretKeyVarGen::random(&mut rng);
    let message = BlsScalar::random(&mut rng);

    let sig = sk.sign(&mut rng, message);
    assert_eq!(sig, SignatureVarGen::from_bytes(&sig.to_bytes()).unwrap());
}

#[test]
fn sign_verify_identity_fails() {
    let mut rng = StdRng::seed_from_u64(0xbeef);
    let msg = BlsScalar::random(&mut rng);
    let sk =
        SecretKeyVarGen::new(JubJubScalar::zero().into(), GENERATOR_EXTENDED);
    let pk = PublicKeyVarGen::from(&sk);
    let sig = sk.sign(&mut rng, msg);

    assert_eq!(pk.verify(&sig, msg).unwrap_err(), Error::InvalidPoint);
}
