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
use jubjub_schnorr::{PublicKeyDouble, SecretKey, SignatureDouble};

pub struct LegacyDoubleSignatureFixture {
    pub signature: SignatureDouble,
    pub public_key: PublicKeyDouble,
    pub message: BlsScalar,
}

/// Recreates the legacy challenge that omitted the secondary public key, then
/// solves the second verification equation for an adaptive secondary key.
pub fn legacy_double_signature_fixture() -> LegacyDoubleSignatureFixture {
    let sk = SecretKey::from(JubJubScalar::from(17u64));
    let pk = PublicKeyDouble::from(&sk);
    let message = BlsScalar::from(23u64);
    let nonce = JubJubScalar::from(31u64);
    let r = GENERATOR_EXTENDED * nonce;
    let r_prime = GENERATOR_NUMS_EXTENDED * JubJubScalar::from(37u64);

    let r_coordinates = r.to_hash_inputs();
    let r_prime_coordinates = r_prime.to_hash_inputs();
    let pk_coordinates = pk.pk().to_hash_inputs();
    let legacy_challenge: JubJubScalar = Hash::digest_truncated(
        Domain::Other,
        &[
            r_coordinates[0],
            r_coordinates[1],
            r_prime_coordinates[0],
            r_prime_coordinates[1],
            pk_coordinates[0],
            pk_coordinates[1],
            message,
        ],
    )[0];
    let inverse_challenge = legacy_challenge
        .invert()
        .expect("the deterministic legacy challenge is nonzero");
    let u = nonce - legacy_challenge * sk.as_ref();
    let pk_prime = (r_prime - GENERATOR_NUMS_EXTENDED * u) * inverse_challenge;

    let public_key = PublicKeyDouble::from_raw_unchecked(*pk.pk(), pk_prime);
    let mut signature_bytes = [0u8; 96];
    signature_bytes[..32].copy_from_slice(&u.to_bytes());
    signature_bytes[32..64].copy_from_slice(&JubJubAffine::from(r).to_bytes());
    signature_bytes[64..]
        .copy_from_slice(&JubJubAffine::from(r_prime).to_bytes());
    let signature = SignatureDouble::from_bytes(&signature_bytes)
        .expect("the attack fixture uses valid subgroup points");

    LegacyDoubleSignatureFixture {
        signature,
        public_key,
        message,
    }
}
