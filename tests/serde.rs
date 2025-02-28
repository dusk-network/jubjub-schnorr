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
use serde::Serialize;

fn assert_canonical_json<T>(
    input: &T,
    expected: &str,
) -> Result<String, Box<dyn std::error::Error>>
where
    T: ?Sized + Serialize,
{
    let serialized = serde_json::to_string(input)?;
    let input_canonical: serde_json::Value = serialized.parse()?;
    let expected_canonical: serde_json::Value = expected.parse()?;
    assert_eq!(input_canonical, expected_canonical);
    Ok(serialized)
}

#[test]
fn serde_public_key() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = StdRng::seed_from_u64(2321u64);
    let pk = PublicKey::from(&SecretKey::random(&mut rng));
    let ser = assert_canonical_json(
        &pk,
        "\"DpZLY4DYeQfPL1buDu8mD6ksNms6Egs98dSSFnFaSbRy\"",
    )?;
    let deser = serde_json::from_str(&ser)?;
    assert_eq!(pk, deser);
    Ok(())
}

#[test]
fn serde_secret_key() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = StdRng::seed_from_u64(2321u64);
    let sk = SecretKey::random(&mut rng);
    let ser = assert_canonical_json(
        &sk,
        "\"kTCLvwPCUa18aowCBXYNLuPVjHoonZYzyJGaSn6xsrP\"",
    )?;
    let deser = serde_json::from_str(&ser)?;
    assert_eq!(sk, deser);
    Ok(())
}

#[test]
fn serde_signature() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = StdRng::seed_from_u64(2321u64);
    let sk = SecretKey::random(&mut rng);
    let msg = BlsScalar::random(&mut rng);
    let sig = sk.sign(&mut rng, msg);
    let ser = assert_canonical_json(
        &sig,
        "\"3RaYppgCj8gGPTqx7R2RCvL8L8VwtHEXNuMrmGYiyfHBYgsLTPfc96DoyD6jhD8PhN4aRycx5jL6kNcCL2ieVEct\""
    )?;
    let deser = serde_json::from_str(&ser)?;
    assert_eq!(sig, deser);
    Ok(())
}

#[test]
fn serde_public_key_double() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = StdRng::seed_from_u64(2321u64);
    let sk = SecretKey::random(&mut rng);
    let pk = PublicKeyDouble::from(&sk);
    let ser = assert_canonical_json(
        &pk,
        "\"4otCV6kFoJ6PXxwcFM1z9AFyiqwGHp3VPj3rUBCD25TcyNJWtMqSfNndztYMjG6RodvSpTvnZQjpMEvD1dCodKZd\""
    )?;
    let deser = serde_json::from_str(&ser)?;
    assert_eq!(pk, deser);
    Ok(())
}

#[test]
fn serde_signature_double() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = StdRng::seed_from_u64(2321u64);
    let sk = SecretKey::random(&mut rng);
    let msg = BlsScalar::random(&mut rng);
    let sig = sk.sign_double(&mut rng, msg);
    let ser = assert_canonical_json(
        &sig,
        "\"2VLaiWNVxxsCgBKu7qSXY6PYN12Xmrqg2ASGhjs7TMgx8fQg7esQXhqomzKK8gcDoMEUCsheFVDjRpEpmAwCbSLoRnZ9yJWDPwude6Zi1RLEFDKsahXpBtdQkrnX6YYxfBhy\""
    )?;
    let deser = serde_json::from_str(&ser)?;
    assert_eq!(sig, deser);
    Ok(())
}

#[test]
fn serde_public_key_var_gen() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = StdRng::seed_from_u64(2321u64);
    let pk = PublicKeyVarGen::from(&SecretKeyVarGen::random(&mut rng));
    let ser = assert_canonical_json(
        &pk,
        "\"CNFKfgP331GhG5uVaMftF2Dgm9TWUoF9tqj7VJwf66QTXiMX73u8jhBiHHEu9wckBrrwR8X9H5Yt4NJ9GGEzWR3\""
    )?;
    let deser = serde_json::from_str(&ser)?;
    assert_eq!(pk, deser);
    Ok(())
}

#[test]
fn serde_secret_key_var_gen() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = StdRng::seed_from_u64(2321u64);
    let sk = SecretKeyVarGen::random(&mut rng);
    let ser = assert_canonical_json(
        &sk,
        "\"DuexcrF7ezofjV6RPDabrqKgEtjzWURdaLSp1vdig84eUbZw4Ud7y9qCnmiZBDMKVoik12DXo1YBeHG3C7CHZYh\""
    )?;
    let deser = serde_json::from_str(&ser)?;
    assert_eq!(sk, deser);
    Ok(())
}

#[test]
fn serde_signature_var_gen() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = StdRng::seed_from_u64(2321u64);
    let sk = SecretKeyVarGen::random(&mut rng);
    let msg = BlsScalar::random(&mut rng);
    let sig = sk.sign(&mut rng, msg);
    let ser = assert_canonical_json(
        &sig,
        "\"2stTAEp4aUw3XwWU8W5bC4RSNnseTTYdoLo3xPyentVBLgtzTyH4jSP5ehUJQdvoz5fzHKPEiVV3hiVWnYMwsLMC\""
    )?;
    let deser = serde_json::from_str(&ser)?;
    assert_eq!(sig, deser);
    Ok(())
}

#[test]
fn serde_wrong_encoded() {
    let wrong_encoded = "\"wrong-encoded\"";
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
fn serde_too_long_encoded() {
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
fn serde_too_short_encoded() {
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
