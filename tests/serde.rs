// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg(feature = "serde")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::fmt::Debug;

use dusk_bls12_381::BlsScalar;
use ff::Field;
use jubjub_schnorr::{
    PublicKey, PublicKeyDouble, PublicKeyVarGen, SecretKey, SecretKeyVarGen,
    Signature, SignatureDouble, SignatureVarGen,
};
use rand::SeedableRng;
use rand::rngs::StdRng;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde::de::value::{BorrowedStrDeserializer, Error};

thread_local! {
    static ALLOCATED_BYTES: Cell<Option<usize>> = const { Cell::new(None) };
}

struct Allocator;

fn record(size: usize) {
    let _ = ALLOCATED_BYTES.try_with(|allocated| {
        if let Some(previous) = allocated.get() {
            allocated.set(Some(previous.saturating_add(size)));
        }
    });
}

unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

/// Deserializes borrowed input, returning the bytes allocated meanwhile.
fn decode<T: DeserializeOwned>(input: &str) -> (Result<T, Error>, usize) {
    ALLOCATED_BYTES.set(Some(0));
    let result = T::deserialize(BorrowedStrDeserializer::<Error>::new(input));
    (result, ALLOCATED_BYTES.replace(None).unwrap())
}

fn encoded<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value)
        .unwrap()
        .trim_matches('"')
        .to_string()
}

/// Checks bounded Base58 decoding for a value whose maximum encoding length is
/// `bound`.
fn check_bounded<T: DeserializeOwned + Serialize + Debug + PartialEq>(
    value: T,
    bound: usize,
) {
    let encoded = encoded(&value);
    assert!(encoded.len() <= bound);
    let (decoded, allocated) = decode::<T>(&encoded);
    assert_eq!(decoded.unwrap(), value);
    assert_eq!(allocated, 0, "valid borrowed input must not allocate");

    // Not Base58: only the length check reports it as over-long.
    let (decoded, _) = decode::<T>(&"0".repeat(bound + 1));
    assert!(decoded.unwrap_err().to_string().contains("over-long"));
    // Within the bound but decoding to more than `N` bytes: only the decoder
    // reports it as over-long.
    let (decoded, _) = decode::<T>(&"z".repeat(bound));
    assert!(decoded.unwrap_err().to_string().contains("over-long"));

    for oversized in ["1".repeat(1 << 20), "z".repeat(1 << 16)] {
        let (decoded, allocated) = decode::<T>(&oversized);
        assert!(decoded.is_err());
        assert!(allocated < 1024, "oversized input was copied or decoded");
    }
}

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
        "\"4NDC5ZPKjsD3SR42Swy1E3rSJ2sqky7Br9tQ3r7EjgQ7TVSSRLzs7mSFchzhqEn81jJvyMQsWwAs66smLeBAs6d4\"",
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
        "\"4otCV6kFoJ6PXxwcFM1z9AFyiqwGHp3VPj3rUBCD25TcyNJWtMqSfNndztYMjG6RodvSpTvnZQjpMEvD1dCodKZd\"",
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
        "\"26byas5ZGSMGQY8x9e9v7Y3vDEzpJLiTKBLxXTs7tViGf7ddfz4AkEz1o11pqainXdsGi12nUoP7ArUbdrb3CBK5G5AeSAVFTkE4QQiFWDcD4zhy16GLSFqBno7Pr3sM9L4y\"",
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
        "\"CNFKfgP331GhG5uVaMftF2Dgm9TWUoF9tqj7VJwf66QTXiMX73u8jhBiHHEu9wckBrrwR8X9H5Yt4NJ9GGEzWR3\"",
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
        "\"DuexcrF7ezofjV6RPDabrqKgEtjzWURdaLSp1vdig84eUbZw4Ud7y9qCnmiZBDMKVoik12DXo1YBeHG3C7CHZYh\"",
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
        "\"5iici2CCiZyYQbfQEXfzkAhgJwwPotZXLJ6zc8u6mDZBg731BmYZgKbcy1eiB3Yy4ShpYQLcyKaza2uyq87B3qJ9\"",
    )?;
    let deser = serde_json::from_str(&ser)?;
    assert_eq!(sig, deser);
    Ok(())
}

#[test]
fn serde_wrong_encoded() {
    let wrong_encoded = "\"wrong-encoded\"";
    let public_key: Result<PublicKey, _> = serde_json::from_str(wrong_encoded);
    assert!(public_key.is_err());

    let secret_key: Result<SecretKey, _> = serde_json::from_str(wrong_encoded);
    assert!(secret_key.is_err());

    let signature: Result<Signature, _> = serde_json::from_str(wrong_encoded);
    assert!(signature.is_err());

    let public_key_double: Result<PublicKeyDouble, _> =
        serde_json::from_str(wrong_encoded);
    assert!(public_key_double.is_err());

    let signature_double: Result<SignatureDouble, _> =
        serde_json::from_str(wrong_encoded);
    assert!(signature_double.is_err());

    let public_key_var_gen: Result<PublicKeyVarGen, _> =
        serde_json::from_str(wrong_encoded);
    assert!(public_key_var_gen.is_err());

    let secret_key_var_gen: Result<SecretKeyVarGen, _> =
        serde_json::from_str(wrong_encoded);
    assert!(secret_key_var_gen.is_err());

    let signature_var_gen: Result<SignatureVarGen, _> =
        serde_json::from_str(wrong_encoded);
    assert!(signature_var_gen.is_err());
}

#[test]
fn serde_too_long_encoded() {
    let length_33_enc = "\"yaujE5CNg7SRYuf3Vw7G8QQdM7267QxJtfqGUEjLbxyCC\"";
    let length_65_enc = "\"Hovyh2MvKLSnTfv2aKMMD1s7MgzWVCdzKJbbLwzU3kgVmo2JugxpGPASJWVQVXcxUqxtxVrQ63myzLRr1ko6oJvyv\"";
    let length_97_enc = "\"7a5RpCdtr1aaXvaR3AofnEnVRh7kpzyqE8eYJpCBVLKLLpXVeN9UrXGRTZyq2upTVaJT5QnPQwZCGXW1oxrEAzrPvQ4vbWFwiHMJijZMzrPsTjQJFju1H4shrajuqUG4fYFpC\"";

    let public_key: Result<PublicKey, _> = serde_json::from_str(length_33_enc);
    assert!(public_key.is_err());

    let secret_key: Result<SecretKey, _> = serde_json::from_str(length_33_enc);
    assert!(secret_key.is_err());

    let signature: Result<Signature, _> = serde_json::from_str(length_65_enc);
    assert!(signature.is_err());

    let public_key_double: Result<PublicKeyDouble, _> =
        serde_json::from_str(length_65_enc);
    assert!(public_key_double.is_err());

    let signature_double: Result<SignatureDouble, _> =
        serde_json::from_str(length_97_enc);
    assert!(signature_double.is_err());

    let public_key_var_gen: Result<PublicKeyVarGen, _> =
        serde_json::from_str(length_65_enc);
    assert!(public_key_var_gen.is_err());

    let secret_key_var_gen: Result<SecretKeyVarGen, _> =
        serde_json::from_str(length_65_enc);
    assert!(secret_key_var_gen.is_err());

    let signature_var_gen: Result<SignatureVarGen, _> =
        serde_json::from_str(length_65_enc);
    assert!(signature_var_gen.is_err());
}

#[test]
fn serde_too_short_encoded() {
    let length_31_enc = "\"3uTp29S3e2HQBekFYvVwsmoeEzk4uVWwQUjvJPwWKwU\"";
    let length_63_enc = "\"YrHj6pQ3kRkpELFJK8a8ESdYyXaH9fQeb4pXRNEb8mSxDCrin1bF4uHz9BN13kN15mmH5fxXXSAusfLLGLrjCF\"";
    let length_95_enc = "\"LZXkPWnz5xKxYnyDRZyJvL9vF44oQynzozqRBcpgWA3yZicbaxNeKKJrAMv3eXBbyEvk24mgz9Kg9tck5yEW6k16chN4hDWYUr5gDb9PJJ3YmUqcjG8yPaAuz3cNCE8dHv\"";

    let public_key: Result<PublicKey, _> = serde_json::from_str(length_31_enc);
    assert!(public_key.is_err());

    let secret_key: Result<SecretKey, _> = serde_json::from_str(length_31_enc);
    assert!(secret_key.is_err());

    let signature: Result<Signature, _> = serde_json::from_str(length_63_enc);
    assert!(signature.is_err());

    let public_key_double: Result<PublicKeyDouble, _> =
        serde_json::from_str(length_63_enc);
    assert!(public_key_double.is_err());

    let signature_double: Result<SignatureDouble, _> =
        serde_json::from_str(length_95_enc);
    assert!(signature_double.is_err());

    let public_key_var_gen: Result<PublicKeyVarGen, _> =
        serde_json::from_str(length_63_enc);
    assert!(public_key_var_gen.is_err());

    let secret_key_var_gen: Result<SecretKeyVarGen, _> =
        serde_json::from_str(length_63_enc);
    assert!(secret_key_var_gen.is_err());

    let signature_var_gen: Result<SignatureVarGen, _> =
        serde_json::from_str(length_63_enc);
    assert!(signature_var_gen.is_err());
}

#[test]
fn serde_decoding_is_bounded() {
    let mut rng = StdRng::seed_from_u64(2321u64);
    let sk = SecretKey::random(&mut rng);
    let pk = PublicKey::from(&sk);
    let msg = BlsScalar::random(&mut rng);
    let sig = sk.sign(&mut rng, msg);
    let pk_double = PublicKeyDouble::from(&sk);
    let sig_double = sk.sign_double(&mut rng, msg);
    let sk_var = SecretKeyVarGen::random(&mut rng);
    let pk_var = PublicKeyVarGen::from(&sk_var);
    let sig_var = sk_var.sign(&mut rng, msg);

    check_bounded(pk, 44);
    check_bounded(sk, 44);
    check_bounded(sig, 88);
    check_bounded(pk_double, 88);
    check_bounded(sig_double, 132);
    check_bounded(pk_var, 88);
    check_bounded(sk_var, 88);
    check_bounded(sig_var, 88);
}
