// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bls12_381::BlsScalar;
use dusk_bytes::Serializable;
use dusk_jubjub::{GENERATOR_EXTENDED, JubJubScalar};
use dusk_poseidon::{Domain, Hash};
use ff::Field;
use jubjub_schnorr::{
    Error, PublicKeyVarGen, SecretKeyVarGen, SignatureVarGen,
};
use rand::SeedableRng;
use rand::rngs::StdRng;

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
fn cross_generator_forgery_fails() {
    let mut rng = StdRng::seed_from_u64(0xdead);

    // Create a valid VarGen signature under generator G1.
    let sk = SecretKeyVarGen::random(&mut rng);
    let pk = PublicKeyVarGen::from(&sk);
    let message = BlsScalar::random(&mut rng);
    let sig = sk.sign(&mut rng, message);
    assert!(pk.verify(&sig, message).is_ok());

    // Forge a (pk2, G2) pair that satisfies the verification equation
    // u * G2 + c * pk2 == R  when the challenge omits the generator.
    //
    // Attack recipe (only works with the old H(R || pk || m) hash):
    //   1. Pick an arbitrary point P.
    //   2. Compute c' = H(R || P || m)  — the challenge the verifier would
    //      derive if pk2 = P and the generator is not hashed.
    //   3. Solve  G2 = u^{-1} * (R - c' * P).
    //   4. (P, G2) passes verification because u*G2 + c'*P = R holds by
    //      construction.
    //
    // With the fix the verifier computes c'' = H(R || P || G2 || m),
    // which differs from c', so the forged pair no longer satisfies
    // the equation and this assertion holds.
    let u = sig.u();
    let r_point = sig.R();

    let p = GENERATOR_EXTENDED * JubJubScalar::random(&mut rng);

    // c' = H(R || P || m) — the generator-free challenge hash
    let r_coords = r_point.to_hash_inputs();
    let p_coords = p.to_hash_inputs();
    let c_prime = Hash::digest_truncated(
        Domain::Other,
        &[r_coords[0], r_coords[1], p_coords[0], p_coords[1], message],
    )[0];
    let c_prime =
        JubJubScalar::from_bytes(&c_prime.to_bytes()[..32].try_into().unwrap())
            .unwrap();

    // G2 = u^{-1} * (R - c' * P)
    let u_inv = u.invert().unwrap();
    let g2 = (r_point - p * c_prime) * u_inv;

    let pk_forged = PublicKeyVarGen::from_raw_unchecked(p, g2);
    // Sanity check
    assert_ne!(pk_forged, pk);

    assert_eq!(
        pk_forged.verify(&sig, message).unwrap_err(),
        Error::InvalidSignature,
    );
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
