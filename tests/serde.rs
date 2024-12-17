// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg(feature = "serde")]

use dusk_bls12_381::BlsScalar;
use ff::Field;
use jubjub_schnorr::{
    PublicKey, PublicKeyDouble, PublicKeyVarGen, SecretKey, SecretKeyVarGen,
    Signature, SignatureDouble, SignatureVarGen,
};
use rand::rngs::StdRng;
use rand::SeedableRng;

#[test]
fn public_key() {
    let mut rng = StdRng::seed_from_u64(2321u64);
    let pk = PublicKey::from(&SecretKey::random(&mut rng));
    let ser = serde_json::to_string(&pk).unwrap();
    let deser = serde_json::from_str(&ser).unwrap();
    assert_eq!(pk, deser);
}

#[test]
fn secret_key() {
    let mut rng = StdRng::seed_from_u64(2321u64);
    let sk = SecretKey::random(&mut rng);
    let ser = serde_json::to_string(&sk).unwrap();
    let deser = serde_json::from_str(&ser).unwrap();
    assert_eq!(sk, deser);
}

#[test]
fn signature() {
    let mut rng = StdRng::seed_from_u64(2321u64);
    let sk = SecretKey::random(&mut rng);
    let msg = BlsScalar::random(&mut rng);
    let sig = sk.sign(&mut rng, msg);
    let ser = serde_json::to_string(&sig).unwrap();
    let deser = serde_json::from_str(&ser).unwrap();
    assert_eq!(sig, deser);
}

#[test]
fn public_key_double() {
    let mut rng = StdRng::seed_from_u64(2321u64);
    let sk = SecretKey::random(&mut rng);
    let pk = PublicKeyDouble::from(&sk);
    let ser = serde_json::to_string(&pk).unwrap();
    let deser = serde_json::from_str(&ser).unwrap();
    assert_eq!(pk, deser);
}

#[test]
fn signature_double() {
    let mut rng = StdRng::seed_from_u64(2321u64);
    let sk = SecretKey::random(&mut rng);
    let msg = BlsScalar::random(&mut rng);
    let sig = sk.sign_double(&mut rng, msg);
    let ser = serde_json::to_string(&sig).unwrap();
    let deser = serde_json::from_str(&ser).unwrap();
    assert_eq!(sig, deser);
}

#[test]
fn public_key_var_gen() {
    let mut rng = StdRng::seed_from_u64(2321u64);
    let pk = PublicKeyVarGen::from(&SecretKeyVarGen::random(&mut rng));
    let ser = serde_json::to_string(&pk).unwrap();
    let deser = serde_json::from_str(&ser).unwrap();
    assert_eq!(pk, deser);
}

#[test]
fn secret_key_var_gen() {
    let mut rng = StdRng::seed_from_u64(2321u64);
    let sk = SecretKeyVarGen::random(&mut rng);
    let ser = serde_json::to_string(&sk).unwrap();
    let deser = serde_json::from_str(&ser).unwrap();
    assert_eq!(sk, deser);
}

#[test]
fn signature_var_gen() {
    let mut rng = StdRng::seed_from_u64(2321u64);
    let sk = SecretKeyVarGen::random(&mut rng);
    let msg = BlsScalar::random(&mut rng);
    let sig = sk.sign(&mut rng, msg);
    let ser = serde_json::to_string(&sig).unwrap();
    let deser = serde_json::from_str(&ser).unwrap();
    assert_eq!(sig, deser);
}

#[test]
fn wrong_encoded() {
    let wrong_encoded = "wrong-encoded";
    let public_key: Result<PublicKey, _> = serde_json::from_str(&wrong_encoded);
    assert!(public_key.is_err());

    let secret_key: Result<SecretKey, _> = serde_json::from_str(&wrong_encoded);
    assert!(secret_key.is_err());

    let signature: Result<Signature, _> = serde_json::from_str(&wrong_encoded);
    assert!(signature.is_err());

    let public_key_double: Result<PublicKeyDouble, _> =
        serde_json::from_str(&wrong_encoded);
    assert!(public_key_double.is_err());

    let signature_double: Result<SignatureDouble, _> =
        serde_json::from_str(&wrong_encoded);
    assert!(signature_double.is_err());

    let public_key_var_gen: Result<PublicKeyVarGen, _> =
        serde_json::from_str(&wrong_encoded);
    assert!(public_key_var_gen.is_err());

    let secret_key_var_gen: Result<SecretKeyVarGen, _> =
        serde_json::from_str(&wrong_encoded);
    assert!(secret_key_var_gen.is_err());

    let signature_var_gen: Result<SignatureVarGen, _> =
        serde_json::from_str(&wrong_encoded);
    assert!(signature_var_gen.is_err());
}

#[test]
fn too_long_encoded() {
    let length_33_enc = "\"yaujE5CNg7SRYuf3Vw7G8QQdM7267QxJtfqGUEjLbxyCC\"";
    let length_65_enc = "\"Hovyh2MvKLSnTfv2aKMMD1s7MgzWVCdzKJbbLwzU3kgVmo2JugxpGPASJWVQVXcxUqxtxVrQ63myzLRr1ko6oJvyv\"";
    let length_97_enc = "\"7a5RpCdtr1aaXvaR3AofnEnVRh7kpzyqE8eYJpCBVLKLLpXVeN9UrXGRTZyq2upTVaJT5QnPQwZCGXW1oxrEAzrPvQ4vbWFwiHMJijZMzrPsTjQJFju1H4shrajuqUG4fYFpC\"";

    let public_key: Result<PublicKey, _> = serde_json::from_str(&length_33_enc);
    assert!(public_key.is_err());

    let secret_key: Result<SecretKey, _> = serde_json::from_str(&length_33_enc);
    assert!(secret_key.is_err());

    let signature: Result<Signature, _> = serde_json::from_str(&length_65_enc);
    assert!(signature.is_err());

    let public_key_double: Result<PublicKeyDouble, _> =
        serde_json::from_str(&length_65_enc);
    assert!(public_key_double.is_err());

    let signature_double: Result<SignatureDouble, _> =
        serde_json::from_str(&length_97_enc);
    assert!(signature_double.is_err());

    let public_key_var_gen: Result<PublicKeyVarGen, _> =
        serde_json::from_str(&length_65_enc);
    assert!(public_key_var_gen.is_err());

    let secret_key_var_gen: Result<SecretKeyVarGen, _> =
        serde_json::from_str(&length_65_enc);
    assert!(secret_key_var_gen.is_err());

    let signature_var_gen: Result<SignatureVarGen, _> =
        serde_json::from_str(&length_65_enc);
    assert!(signature_var_gen.is_err());
}

#[test]
fn too_short_encoded() {
    let length_31_enc = "\"3uTp29S3e2HQBekFYvVwsmoeEzk4uVWwQUjvJPwWKwU\"";
    let length_63_enc = "\"YrHj6pQ3kRkpELFJK8a8ESdYyXaH9fQeb4pXRNEb8mSxDCrin1bF4uHz9BN13kN15mmH5fxXXSAusfLLGLrjCF\"";
    let length_95_enc = "\"LZXkPWnz5xKxYnyDRZyJvL9vF44oQynzozqRBcpgWA3yZicbaxNeKKJrAMv3eXBbyEvk24mgz9Kg9tck5yEW6k16chN4hDWYUr5gDb9PJJ3YmUqcjG8yPaAuz3cNCE8dHv\"";

    let public_key: Result<PublicKey, _> = serde_json::from_str(&length_31_enc);
    assert!(public_key.is_err());

    let secret_key: Result<SecretKey, _> = serde_json::from_str(&length_31_enc);
    assert!(secret_key.is_err());

    let signature: Result<Signature, _> = serde_json::from_str(&length_63_enc);
    assert!(signature.is_err());

    let public_key_double: Result<PublicKeyDouble, _> =
        serde_json::from_str(&length_63_enc);
    assert!(public_key_double.is_err());

    let signature_double: Result<SignatureDouble, _> =
        serde_json::from_str(&length_95_enc);
    assert!(signature_double.is_err());

    let public_key_var_gen: Result<PublicKeyVarGen, _> =
        serde_json::from_str(&length_63_enc);
    assert!(public_key_var_gen.is_err());

    let secret_key_var_gen: Result<SecretKeyVarGen, _> =
        serde_json::from_str(&length_63_enc);
    assert!(secret_key_var_gen.is_err());

    let signature_var_gen: Result<SignatureVarGen, _> =
        serde_json::from_str(&length_63_enc);
    assert!(signature_var_gen.is_err());
}
