// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg(feature = "alloc")]

use dusk_bls12_381::BlsScalar;
use dusk_bytes::Serializable;
use dusk_jubjub::{GENERATOR_EXTENDED, JubJubExtended, JubJubScalar};
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

    let pk_vec = vec![pk_1, pk_2];

    // First round: all signers compute the following elements
    let (nonce_1, R_1, S_1) = multisig::sign_round_1(&mut rng);
    let (nonce_2, R_2, S_2) = multisig::sign_round_1(&mut rng);

    // All signers share `R_vec` and `S_vec` with all the other signers
    let R_vec = vec![R_1, R_2];
    let S_vec = vec![S_1, S_2];

    // Second round: all the signers compute their share `z`
    let z_1 = multisig::sign_round_2(
        &sk_1,
        nonce_1,
        &pk_vec.clone(),
        &R_vec.clone(),
        &S_vec.clone(),
        &message,
    )
    .expect("Multisig Round 2 shouldn't fail");
    let z_2 = multisig::sign_round_2(
        &sk_2,
        nonce_2,
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
    let sig = multisig::combine(&z_vec, &pk_vec, &R_vec, &S_vec, &message)
        .expect("valid multisig transcript should combine");

    // Anyone can verify using the delinearized aggregate public key
    let pk = multisig::aggregate_pk(&pk_vec);
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

fn valid_three_party_transcript() -> (
    BlsScalar,
    Vec<PublicKey>,
    Vec<JubJubExtended>,
    Vec<JubJubExtended>,
    Vec<JubJubScalar>,
) {
    let mut rng = StdRng::seed_from_u64(0x6573);
    let sk_vec: Vec<_> = (0..3).map(|_| SecretKey::random(&mut rng)).collect();
    let pk_vec: Vec<_> = sk_vec.iter().map(PublicKey::from).collect();
    let message = BlsScalar::random(&mut rng);
    let rounds: Vec<_> =
        (0..3).map(|_| multisig::sign_round_1(&mut rng)).collect();
    let r_vec: Vec<_> = rounds.iter().map(|(_, r, _)| *r).collect();
    let s_vec: Vec<_> = rounds.iter().map(|(_, _, s)| *s).collect();
    let z_vec = sk_vec
        .iter()
        .zip(rounds)
        .map(|(sk, (nonce, _, _))| {
            multisig::sign_round_2(sk, nonce, &pk_vec, &r_vec, &s_vec, &message)
        })
        .collect::<Result<Vec<_>, _>>()
        .expect("valid transcript should produce every share");

    (message, pk_vec, r_vec, s_vec, z_vec)
}

#[test]
fn verifies_every_valid_share_before_aggregation() {
    let (message, pk_vec, r_vec, s_vec, z_vec) = valid_three_party_transcript();

    for (participant_index, share) in z_vec.iter().enumerate() {
        assert_eq!(
            multisig::verify_share(
                share,
                participant_index,
                &pk_vec,
                &r_vec,
                &s_vec,
                &message,
            ),
            Ok(())
        );
    }

    let signature =
        multisig::combine(&z_vec, &pk_vec, &r_vec, &s_vec, &message)
            .expect("valid shares should aggregate");
    assert!(
        multisig::aggregate_pk(&pk_vec)
            .verify(&signature, message)
            .is_ok()
    );
}

#[test]
fn rejects_a_malformed_share_in_every_participant_slot() {
    let (message, pk_vec, r_vec, s_vec, z_vec) = valid_three_party_transcript();

    for participant_index in 0..z_vec.len() {
        let mut malformed_shares = z_vec.clone();
        malformed_shares[participant_index] += JubJubScalar::from(1u64);

        assert_eq!(
            multisig::verify_share(
                &malformed_shares[participant_index],
                participant_index,
                &pk_vec,
                &r_vec,
                &s_vec,
                &message,
            ),
            Err(Error::InvalidMultisigShare(participant_index))
        );
        assert_eq!(
            multisig::combine(
                &malformed_shares,
                &pk_vec,
                &r_vec,
                &s_vec,
                &message,
            ),
            Err(Error::InvalidMultisigShare(participant_index))
        );
    }
}

#[test]
fn verify_share_rejects_an_invalid_participant_slot() {
    let (message, pk_vec, r_vec, s_vec, z_vec) = valid_three_party_transcript();

    assert_eq!(
        multisig::verify_share(
            &z_vec[0],
            pk_vec.len(),
            &pk_vec,
            &r_vec,
            &s_vec,
            &message,
        ),
        Err(Error::InvalidMultisigTranscript)
    );
}

#[test]
fn verify_share_rejects_invalid_lengths() {
    let message = BlsScalar::from(1u64);
    let share = JubJubScalar::from(1u64);
    let pk_vec = [PublicKey::from(GENERATOR_EXTENDED); 3];
    let r_vec = [GENERATOR_EXTENDED; 3];
    let s_vec = [GENERATOR_EXTENDED; 3];

    for (pk_len, r_len, s_len) in [
        (0, 0, 0),
        (1, 2, 2),
        (2, 1, 2),
        (2, 2, 1),
        (3, 2, 2),
        (2, 3, 2),
        (2, 2, 3),
    ] {
        assert_eq!(
            multisig::verify_share(
                &share,
                0,
                &pk_vec[..pk_len],
                &r_vec[..r_len],
                &s_vec[..s_len],
                &message,
            ),
            Err(Error::InvalidMultisigTranscript)
        );
    }
}

#[test]
fn verify_share_rejects_a_share_from_another_slot() {
    let (message, pk_vec, r_vec, s_vec, z_vec) = valid_three_party_transcript();

    assert_eq!(
        multisig::verify_share(&z_vec[0], 1, &pk_vec, &r_vec, &s_vec, &message,),
        Err(Error::InvalidMultisigShare(1))
    );
}

#[test]
fn combine_reports_the_first_invalid_share() {
    let (message, pk_vec, r_vec, s_vec, mut z_vec) =
        valid_three_party_transcript();
    z_vec[2] += JubJubScalar::from(1u64);
    z_vec[0] += JubJubScalar::from(1u64);

    assert_eq!(
        multisig::combine(&z_vec, &pk_vec, &r_vec, &s_vec, &message),
        Err(Error::InvalidMultisigShare(0))
    );
}

#[test]
fn combine_rejects_invalid_lengths() {
    let message = BlsScalar::from(1u64);
    let z_vec = [JubJubScalar::from(1u64); 3];
    let pk_vec = [PublicKey::from(GENERATOR_EXTENDED); 3];
    let r_vec = [GENERATOR_EXTENDED; 3];
    let s_vec = [GENERATOR_EXTENDED; 3];

    for (z_len, pk_len, r_len, s_len) in [
        (0, 0, 0, 0),
        (1, 2, 2, 2),
        (2, 1, 2, 2),
        (2, 2, 1, 2),
        (2, 2, 2, 1),
        (3, 2, 2, 2),
        (2, 3, 2, 2),
        (2, 2, 3, 2),
        (2, 2, 2, 3),
        (2, 2, 3, 3),
        (3, 3, 2, 2),
    ] {
        assert_eq!(
            multisig::combine(
                &z_vec[..z_len],
                &pk_vec[..pk_len],
                &r_vec[..r_len],
                &s_vec[..s_len],
                &message,
            ),
            Err(Error::InvalidMultisigTranscript)
        );
    }
}

/// Regression test: delinearization defeats the rogue-key attack.
///
/// Mallory crafts a rogue public key that cancels Alice's key under
/// plain summation, then solo-signs a message. Without delinearization,
/// this forged signature verifies against the plain-sum aggregate key.
/// With delinearized aggregation, the same forgery is rejected.
#[test]
fn rogue_key_attack() {
    let mut rng = StdRng::seed_from_u64(0xdeadbeef);

    // Honest Alice generates her keypair
    let sk_alice = SecretKey::random(&mut rng);
    let pk_alice = PublicKey::from(&sk_alice);

    // Mallory picks her own secret key
    let sk_mallory = SecretKey::random(&mut rng);

    // Mallory crafts a rogue public key: pk_m = G * sk_m - pk_alice
    // Under plain summation: pk_alice + pk_m = G * sk_m
    let pk_mallory_rogue = PublicKey::from(
        GENERATOR_EXTENDED * sk_mallory.as_ref() - pk_alice.as_ref(),
    );

    let message = BlsScalar::random(&mut rng);

    // Mallory solo-signs using her real secret key
    let forged_sig = sk_mallory.sign(&mut rng, message);

    // WITHOUT delinearization: the plain-sum aggregate key equals
    // Mallory's public key, so her solo signature verifies — the
    // attack succeeds.
    let pk_plain_sum =
        PublicKey::from(pk_alice.as_ref() + pk_mallory_rogue.as_ref());
    assert!(
        pk_plain_sum.verify(&forged_sig, message).is_ok(),
        "attack must succeed under plain summation"
    );

    // WITH delinearization: the aggregate key is no longer Mallory's
    // key, so the same forged signature is rejected.
    let pk_vec = vec![pk_alice, pk_mallory_rogue];
    let pk_agg = multisig::aggregate_pk(&pk_vec);
    assert!(
        pk_agg.verify(&forged_sig, message).is_err(),
        "delinearized aggregate must reject Mallory's forgery"
    );
}

#[test]
#[allow(non_snake_case)]
fn duplicated_nonce() {
    let mut rng = StdRng::seed_from_u64(2321u64);

    let sk = SecretKey::random(&mut rng);
    let pk = PublicKey::from(&sk);
    let other_sk = SecretKey::random(&mut rng);
    let other_pk = PublicKey::from(&other_sk);
    let pk_vec = vec![pk, other_pk];

    let message = BlsScalar::random(&mut rng);

    let (nonce, R, S) = multisig::sign_round_1(&mut rng);

    let R_vec = vec![R, R]; // duplicated nonce
    let S_vec = vec![S, S]; // duplicated nonce

    let result = multisig::sign_round_2(
        &sk,
        nonce,
        &pk_vec.clone(),
        &R_vec.clone(),
        &S_vec.clone(),
        &message,
    );

    assert_eq!(result, Err(Error::DuplicatedNonce));
}

#[test]
#[allow(non_snake_case)]
fn round_two_rejects_misaligned_commitments() {
    let mut rng = StdRng::seed_from_u64(0x1234);
    let sk = SecretKey::random(&mut rng);
    let pk = PublicKey::from(&sk);
    let message = BlsScalar::random(&mut rng);

    let (nonce, R, S) = multisig::sign_round_1(&mut rng);
    let (_, wrong_R, _) = multisig::sign_round_1(&mut rng);
    assert_eq!(
        multisig::sign_round_2(&sk, nonce, &[pk], &[wrong_R], &[S], &message),
        Err(Error::InvalidMultisigTranscript)
    );
    assert_ne!(R, wrong_R);

    let (nonce, R, S) = multisig::sign_round_1(&mut rng);
    let (_, _, wrong_S) = multisig::sign_round_1(&mut rng);
    assert_eq!(
        multisig::sign_round_2(&sk, nonce, &[pk], &[R], &[wrong_S], &message),
        Err(Error::InvalidMultisigTranscript)
    );
    assert_ne!(S, wrong_S);
}

#[test]
#[allow(non_snake_case)]
fn round_two_requires_exactly_one_signer_key() {
    let mut rng = StdRng::seed_from_u64(0x3456);
    let sk = SecretKey::random(&mut rng);
    let other_sk = SecretKey::random(&mut rng);
    let pk = PublicKey::from(&sk);
    let other_pk = PublicKey::from(&other_sk);
    let message = BlsScalar::random(&mut rng);

    let (nonce, R, S) = multisig::sign_round_1(&mut rng);
    assert_eq!(
        multisig::sign_round_2(&sk, nonce, &[other_pk], &[R], &[S], &message,),
        Err(Error::InvalidMultisigTranscript)
    );

    let (nonce, R, S) = multisig::sign_round_1(&mut rng);
    let (_, other_R, other_S) = multisig::sign_round_1(&mut rng);
    assert_eq!(
        multisig::sign_round_2(
            &sk,
            nonce,
            &[pk, pk],
            &[R, other_R],
            &[S, other_S],
            &message,
        ),
        Err(Error::InvalidMultisigTranscript)
    );
}

#[test]
#[allow(non_snake_case)]
fn round_two_rejects_unequal_commitment_lengths() {
    let mut rng = StdRng::seed_from_u64(0x5678);
    let sk = SecretKey::random(&mut rng);
    let pk = PublicKey::from(&sk);
    let message = BlsScalar::random(&mut rng);

    let (nonce, R, S) = multisig::sign_round_1(&mut rng);
    assert_eq!(
        multisig::sign_round_2(&sk, nonce, &[pk], &[R, R], &[S], &message),
        Err(Error::InvalidMultisigTranscript)
    );

    let (nonce, R, S) = multisig::sign_round_1(&mut rng);
    assert_eq!(
        multisig::sign_round_2(&sk, nonce, &[pk], &[R], &[S, S], &message),
        Err(Error::InvalidMultisigTranscript)
    );
}
