// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg(feature = "alloc")]

//! # Multisignature Module
//!
//! Implementation of a MuSig-style Schnorr-based multisignature scheme
//! with delinearized key aggregation. It allows several signers to
//! create a signature that proves a message to be signed by them all,
//! given their public keys.
//!
//! Delinearization prevents rogue-key attacks by weighting each public
//! key with a coefficient derived from hashing the full key set:
//!
//! ```text
//! d_i = H(pk_i, pk_1, pk_2, ..., pk_n)
//! pk_agg = d_1 * pk_1 + d_2 * pk_2 + ... + d_n * pk_n
//! ```
//!
//! reference: https://eprint.iacr.org/2021/1375.pdf - pag. 19
//!
//! ## Feature
//!
//! Only available with the "alloc" feature enabled.
//!
//! ## Example
//!
//! Generate and verify a multisignature:
//! ```rust
//! use dusk_bls12_381::BlsScalar;
//! use ff::Field;
//! use jubjub_schnorr::multisig;
//! use jubjub_schnorr::{PublicKey, SecretKey};
//! use rand::{rngs::StdRng, SeedableRng};
//!
//! let mut rng = StdRng::seed_from_u64(2321u64);
//!
//! // signer 1
//! let sk_1 = SecretKey::random(&mut rng);
//! let pk_1 = PublicKey::from(&sk_1);
//!
//! // signer 2
//! let sk_2 = SecretKey::random(&mut rng);
//! let pk_2 = PublicKey::from(&sk_2);
//!
//! let message = BlsScalar::random(&mut rng);
//!
//! let pk_vec = vec![pk_1, pk_2];
//!
//! // First round: all signers compute the following elements for the
//! // message and the ordered public keys. A signer may also pass a session
//! // input, such as a counter of its signing attempts.
//! let attempt = BlsScalar::from(1u64);
//! let (nonce_1, R_1, S_1) = multisig::sign_round_1(
//!     &mut rng,
//!     &sk_1,
//!     &pk_vec,
//!     &message,
//!     Some(&attempt),
//! );
//! let (nonce_2, R_2, S_2) =
//!     multisig::sign_round_1(&mut rng, &sk_2, &pk_vec, &message, None);
//!
//! // All signers share `R_vec` and `S_vec` with all the other signers
//! let R_vec = vec![R_1, R_2];
//! let S_vec = vec![S_1, S_2];
//!
//! // Second round: all the signers compute their share `z`
//! let z_1 = multisig::sign_round_2(
//!     &sk_1,
//!     nonce_1,
//!     &pk_vec.clone(),
//!     &R_vec.clone(),
//!     &S_vec.clone(),
//!     &message,
//! )
//! .expect("Multisig Round 2 shouldn't fail");
//! let z_2 = multisig::sign_round_2(
//!     &sk_2,
//!     nonce_2,
//!     &pk_vec.clone(),
//!     &R_vec.clone(),
//!     &S_vec.clone(),
//!     &message,
//! )
//! .expect("Multisig Round 2 shouldn't fail");
//!
//! // All signers share their share `z` with a signer wishing to combine them
//! // all
//! let z_vec = vec![z_1, z_2];
//!
//! // A signer combines all the shares into a signature `sig`
//! let sig = multisig::combine(&z_vec, &pk_vec, &R_vec, &S_vec, &message)
//!     .expect("Multisig combination shouldn't fail");
//!
//! // Anyone can verify using the delinearized aggregate public key
//! let pk = multisig::aggregate_pk(&pk_vec)
//!     .expect("valid participant keys should aggregate");
//! assert!(pk.verify(&sig, message).is_ok());
//! ```

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use dusk_bls12_381::BlsScalar;
use dusk_jubjub::{GENERATOR_EXTENDED, JubJubExtended, JubJubScalar};
use dusk_poseidon::{Domain, Hash};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::{Error, PublicKey, SecretKey, Signature};

/// Secret nonce state produced by [`sign_round_1`] and consumed by
/// [`sign_round_2`].
///
/// The state is bound to the message and the ordered public keys it was
/// produced for, and [`sign_round_2`] rejects it for any other.
///
/// The state deliberately implements neither [`Clone`] nor [`Copy`]. Its
/// scalar fields owned by this state are zeroized whenever it is consumed or
/// dropped. This does not guarantee clearing transient copies created during
/// scalar arithmetic.
///
/// A nonce cannot be submitted to round two twice:
///
/// ```compile_fail,E0382
/// use dusk_bls12_381::BlsScalar;
/// use jubjub_schnorr::{PublicKey, SecretKey, multisig};
/// use rand::{SeedableRng, rngs::StdRng};
///
/// let mut rng = StdRng::seed_from_u64(7);
/// let sk = SecretKey::random(&mut rng);
/// let pk = PublicKey::from(&sk);
/// let message = BlsScalar::from(11u64);
/// let (nonce, r, s) =
///     multisig::sign_round_1(&mut rng, &sk, &[pk], &message, None);
///
/// let _ = multisig::sign_round_2(&sk, nonce, &[pk], &[r], &[s], &message);
/// let _ = multisig::sign_round_2(&sk, nonce, &[pk], &[r], &[s], &message);
/// ```
#[derive(Zeroize)]
pub struct MultisigNonce {
    r: JubJubScalar,
    s: JubJubScalar,
    transcript: BlsScalar,
}

impl Drop for MultisigNonce {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Computes the delinearized aggregate public key for a set of signers.
///
/// Each public key is weighted by a coefficient derived from hashing the
/// full key set, preventing rogue-key attacks:
///
/// ```text
/// d_i = H(pk_i, pk_1, pk_2, ..., pk_n)
/// pk_agg = d_1 * pk_1 + d_2 * pk_2 + ... + d_n * pk_n
/// ```
///
/// Use this to compute the verification key for a multisignature.
///
/// ## Errors
///
/// Returns [`Error::InvalidMultisigTranscript`] if `pk_vec` is empty or any
/// public key is invalid or repeated. Invalid keys include the identity and
/// small-order points.
pub fn aggregate_pk(pk_vec: &[PublicKey]) -> Result<PublicKey, Error> {
    if pk_vec.is_empty() || has_invalid_key(pk_vec) {
        return Err(Error::InvalidMultisigTranscript);
    }
    Ok(PublicKey::from(
        aggregate_key(pk_vec, &hash_inputs(pk_vec)).point,
    ))
}

/// Performs the first round to sign a message using the
/// multisignature scheme
///
/// Both nonces hash fresh RNG output together with the secret key, the
/// message, the ordered public keys and the session input, if any, so
/// repeated RNG output repeats them only when all of these repeat too. The
/// RNG must still be cryptographically secure.
///
/// ## Parameters
///
/// - `rng`: Reference to the random number generator.
/// - `sk`: Reference to the signer's secret key.
/// - `pk_vec`: Ordered vector of public keys, as later passed to
///   [`sign_round_2`].
/// - `msg`: Message to sign, as later passed to [`sign_round_2`].
/// - `session`: Optional value that both nonces also hash, such as a counter or
///   a session identifier. It keeps the nonces of two attempts to sign the same
///   message with the same key list apart if the RNG repeats its output. It
///   need not be secret, and only this signer's round one uses it. A value
///   unique to each signing attempt is best. If the RNG repeats and `session`
///   is `None` or repeated, a co-signer that forces three signing attempts on
///   the same message and key list recovers the secret key.
///
/// ## Returns
///
/// Returns an opaque one-shot [`MultisigNonce`] and the public commitment
/// points `(R, S)`.
///
/// Round one does not validate `pk_vec`: [`sign_round_2`] does, and rejects
/// the state for any other message or key list.
pub fn sign_round_1<R>(
    rng: &mut R,
    sk: &SecretKey,
    pk_vec: &[PublicKey],
    msg: &BlsScalar,
    session: Option<&BlsScalar>,
) -> (MultisigNonce, JubJubExtended, JubJubExtended)
where
    R: RngCore + CryptoRng,
{
    let transcript = transcript_digest(&hash_inputs(pk_vec), msg);
    let [r, s] = crate::nonce::hedged_multisig_nonces(
        rng,
        sk.as_ref(),
        transcript,
        session,
    );

    // Compute R = r * G, S = s * G
    let R = GENERATOR_EXTENDED * r;
    let S = GENERATOR_EXTENDED * s;

    (MultisigNonce { r, s, transcript }, R, S)
}

/// Performs the second round to sign a message using the
/// multisignature scheme
///
/// ## Parameters
///
/// - `sk`: Reference to the secret key.
/// - `nonce`: One-shot secret nonce state returned by [`sign_round_1`] for
///   `pk_vec` and `msg`.
/// - `pk_vec`: Ordered vector of public keys; the signer's key must occur
///   exactly once.
/// - `R_vec`: Vector of R values, index-aligned with `pk_vec`.
/// - `S_vec`: Vector of S values, index-aligned with `pk_vec`.
/// - `msg`: Message to sign.
///
/// ## Returns
///
/// Returns a [`JubJubScalar`] being the signature share 'z'
///
/// ## Errors
///
/// Returns [`Error::InvalidMultisigTranscript`] if the participant vectors do
/// not have equal lengths, `pk_vec` or `msg` differ from those passed to
/// [`sign_round_1`] for this state, any public key is invalid or repeated, the
/// signer key is not in the key list, or this state does not match the
/// signer's commitment slot. Returns
/// [`Error::DuplicatedNonce`] if any two participants supplied the same `R` or
/// `S` commitment.
pub fn sign_round_2(
    sk: &SecretKey,
    nonce: MultisigNonce,
    pk_vec: &[PublicKey],
    R_vec: &[JubJubExtended],
    S_vec: &[JubJubExtended],
    msg: &BlsScalar,
) -> Result<JubJubScalar, Error> {
    if pk_vec.len() != R_vec.len() || R_vec.len() != S_vec.len() {
        return Err(Error::InvalidMultisigTranscript);
    }
    let keys = hash_inputs(pk_vec);
    if transcript_digest(&keys, msg) != nonce.transcript
        || has_invalid_key(pk_vec)
    {
        return Err(Error::InvalidMultisigTranscript);
    }

    let signer_pk = PublicKey::from(sk);
    let signer_index = pk_vec
        .iter()
        .position(|pk| *pk == signer_pk)
        .ok_or(Error::InvalidMultisigTranscript)?;
    if R_vec[signer_index] != GENERATOR_EXTENDED * nonce.r
        || S_vec[signer_index] != GENERATOR_EXTENDED * nonce.s
    {
        return Err(Error::InvalidMultisigTranscript);
    }

    // Check if (R_i == R_j) || (S_i == S_j) for any i != j
    // and return error if so
    for i in 0..R_vec.len() {
        for j in (i + 1)..R_vec.len() {
            if R_vec[i] == R_vec[j] || S_vec[i] == S_vec[j] {
                return Err(Error::DuplicatedNonce);
            }
        }
    }

    let coefficients = multisig_common(pk_vec, &keys, R_vec, S_vec, msg);
    let d_i = coefficients.aggregate_key.delinearization[signer_index];

    // Compute the share z = r + s * a - c * d_i * sk
    Ok(nonce.r + (nonce.s * coefficients.a)
        - (coefficients.c * d_i * sk.as_ref()))
}

/// Verifies one multisignature share against its participant slot.
///
/// The verification derives the transcript coefficients from the full,
/// ordered public-key and nonce-commitment vectors, then checks:
///
/// ```text
/// z_i * G + c * d_i * pk_i == R_i + a * S_i
/// ```
///
/// Here `a` binds all participant commitments, `c` is the aggregate Schnorr
/// challenge, and `d_i` delinearizes the participant public key.
///
/// ## Parameters
///
/// - `share`: Signature share to verify.
/// - `participant_index`: Slot corresponding to the share in every transcript
///   vector.
/// - `pk_vec`: Ordered vector of participant public keys.
/// - `R_vec`: Vector of R commitments, index-aligned with `pk_vec`.
/// - `S_vec`: Vector of S commitments, index-aligned with `pk_vec`.
/// - `msg`: Signed message.
///
/// ## Errors
///
/// Returns [`Error::InvalidMultisigTranscript`] if the participant vectors are
/// empty, have unequal lengths, contain an invalid or repeated public key, or
/// do not contain `participant_index`. Returns
/// [`Error::InvalidMultisigShare`] with `participant_index` if the share does
/// not satisfy its verification equation.
pub fn verify_share(
    share: &JubJubScalar,
    participant_index: usize,
    pk_vec: &[PublicKey],
    R_vec: &[JubJubExtended],
    S_vec: &[JubJubExtended],
    msg: &BlsScalar,
) -> Result<(), Error> {
    if pk_vec.is_empty()
        || pk_vec.len() != R_vec.len()
        || R_vec.len() != S_vec.len()
        || participant_index >= pk_vec.len()
        || has_invalid_key(pk_vec)
    {
        return Err(Error::InvalidMultisigTranscript);
    }

    let coefficients =
        multisig_common(pk_vec, &hash_inputs(pk_vec), R_vec, S_vec, msg);
    verify_share_with_coefficients(
        share,
        participant_index,
        pk_vec,
        R_vec,
        S_vec,
        &coefficients,
    )
}

/// Combines all the multisignature shares `z_vec`.
///
/// ## Parameters
///
/// - `z_vec`: Vector of shares.
/// - `pk_vec`: Vector of public keys.
/// - `R_vec`: Vector of R values.
/// - `S_vec`: Vector of S values.
/// - `msg`: Message to sign.
///
/// ## Returns
///
/// Returns a new [`Signature`] wrapped in [`Ok`] on success.
///
/// ## Errors
///
/// Returns [`Error::InvalidMultisigTranscript`] if the participant vectors are
/// empty, do not have equal lengths, or contain an invalid or repeated public
/// key. Returns
/// [`Error::InvalidMultisigShare`] with the participant slot of the first share
/// that fails verification. No aggregate signature is returned when a share is
/// invalid.
pub fn combine(
    z_vec: &[JubJubScalar],
    pk_vec: &[PublicKey],
    R_vec: &[JubJubExtended],
    S_vec: &[JubJubExtended],
    msg: &BlsScalar,
) -> Result<Signature, Error> {
    if z_vec.is_empty()
        || z_vec.len() != pk_vec.len()
        || pk_vec.len() != R_vec.len()
        || R_vec.len() != S_vec.len()
        || has_invalid_key(pk_vec)
    {
        return Err(Error::InvalidMultisigTranscript);
    }

    let coefficients =
        multisig_common(pk_vec, &hash_inputs(pk_vec), R_vec, S_vec, msg);

    for (participant_index, share) in z_vec.iter().enumerate() {
        verify_share_with_coefficients(
            share,
            participant_index,
            pk_vec,
            R_vec,
            S_vec,
            &coefficients,
        )?;
    }

    // Sum all the shares u = z_1 + z_2 + ... + z_n for `n` signers
    let u = z_vec.iter().sum();

    Ok(Signature::new(u, coefficients.aggregate_commitment))
}

/// Domain tag of the digest that binds a round-one nonce state to its message
/// and ordered public keys.
const TRANSCRIPT_DOMAIN: u64 = u64::from_be_bytes(*b"JJSCHMTX");

/// Digest of the message and the ordered public keys, as [`hash_inputs`],
/// that round one binds its nonces to and round two checks:
///
/// t = H(tag, m, pk_1, pk_2, ..., pk_n)
fn transcript_digest(keys: &[[BlsScalar; 2]], msg: &BlsScalar) -> BlsScalar {
    let mut preimage = Vec::with_capacity(2 + 2 * keys.len());
    preimage.push(BlsScalar::from(TRANSCRIPT_DOMAIN));
    preimage.push(*msg);
    preimage.extend(keys.iter().flatten());
    Hash::digest(Domain::Other, &preimage)[0]
}

/// The affine coordinates of each public key, which the transcript digest and
/// every delinearization coefficient hash. A conversion to affine costs a field
/// inversion, so each key is converted once and its coordinates are shared.
fn hash_inputs(pk_vec: &[PublicKey]) -> Vec<[BlsScalar; 2]> {
    pk_vec
        .iter()
        .map(|pk| pk.as_ref().to_hash_inputs())
        .collect()
}

/// Identity and small-order keys satisfy share verification without any
/// secret, and a repeated key lets one secret sign for several entries, so
/// either counts participants that never signed.
fn has_invalid_key(pk_vec: &[PublicKey]) -> bool {
    pk_vec
        .iter()
        .enumerate()
        .any(|(i, pk)| !pk.is_valid() || pk_vec[..i].contains(pk))
}

fn verify_share_with_coefficients(
    share: &JubJubScalar,
    participant_index: usize,
    pk_vec: &[PublicKey],
    r_vec: &[JubJubExtended],
    s_vec: &[JubJubExtended],
    coefficients: &MultisigCoefficients,
) -> Result<(), Error> {
    let pk_i = &pk_vec[participant_index];
    let r_i = &r_vec[participant_index];
    let s_i = &s_vec[participant_index];
    let d_i = coefficients.aggregate_key.delinearization[participant_index];
    let response =
        (GENERATOR_EXTENDED * share) + (pk_i.as_ref() * (coefficients.c * d_i));
    let commitment = *r_i + (*s_i * coefficients.a);

    if response != commitment {
        return Err(Error::InvalidMultisigShare(participant_index));
    }

    Ok(())
}

/// Computes the delinearization coefficient for a signer's public key
/// given the full set of public keys, all as [`hash_inputs`].
///
/// d_i = H(pk_i, pk_1, pk_2, ..., pk_n)
fn delinearization_coeff(
    pk_i: &[BlsScalar; 2],
    keys: &[[BlsScalar; 2]],
) -> JubJubScalar {
    let mut preimage = Vec::with_capacity(2 + 2 * keys.len());
    preimage.extend(pk_i);
    preimage.extend(keys.iter().flatten());
    Hash::digest_truncated(Domain::Other, &preimage)[0]
}

struct AggregateKey {
    delinearization: Vec<JubJubScalar>,
    point: JubJubExtended,
}

fn aggregate_key(
    pk_vec: &[PublicKey],
    keys: &[[BlsScalar; 2]],
) -> AggregateKey {
    let mut delinearization = Vec::with_capacity(pk_vec.len());
    let mut point = JubJubExtended::default();
    for (pk, key) in pk_vec.iter().zip(keys) {
        let d = delinearization_coeff(key, keys);
        delinearization.push(d);
        point += pk.as_ref() * d;
    }

    AggregateKey {
        delinearization,
        point,
    }
}

struct MultisigCoefficients {
    aggregate_key: AggregateKey,
    a: JubJubScalar,
    c: JubJubScalar,
    aggregate_commitment: JubJubExtended,
}

/// Performs some common operations required in different parts
/// of the multisignature scheme
fn multisig_common(
    pk_vec: &[PublicKey],
    keys: &[[BlsScalar; 2]],
    R_vec: &[JubJubExtended],
    S_vec: &[JubJubExtended],
    msg: &BlsScalar,
) -> MultisigCoefficients {
    // Compute the delinearized aggregate key
    // pk = d_1 * pk_1 + d_2 * pk_2 + ... + d_n * pk_n
    let aggregate_key = aggregate_key(pk_vec, keys);

    // Compute the hash
    // a = H(pk || m || R_1 || S_1 || R_2 || S_2 || ... || R_n || S_n)
    // for `n` signers
    let mut preimage = vec![];
    let pk_coordinates = aggregate_key.point.to_hash_inputs();

    preimage.push(pk_coordinates[0]);
    preimage.push(pk_coordinates[1]);
    preimage.push(*msg);

    for it in 0..R_vec.len() {
        let R_coordinates = R_vec[it].to_hash_inputs();
        let S_coordinates = S_vec[it].to_hash_inputs();

        preimage.push(R_coordinates[0]);
        preimage.push(R_coordinates[1]);
        preimage.push(S_coordinates[0]);
        preimage.push(S_coordinates[1]);
    }

    let a = Hash::digest_truncated(Domain::Other, &preimage)[0];

    // Compute RSa = R_1 + (S_1 * a) + R_2 + (S_2 * a) + ... + R_n + (S_n *
    // a) for `n` signers
    let mut RSa = JubJubExtended::default();
    for it in 0..R_vec.len() {
        RSa = RSa + R_vec[it] + (S_vec[it] * a);
    }

    // Compute challenge c = H(RSa || pk || m);
    let RSa_coordinates = RSa.to_hash_inputs();
    let c = Hash::digest_truncated(
        Domain::Other,
        &[
            RSa_coordinates[0],
            RSa_coordinates[1],
            pk_coordinates[0],
            pk_coordinates[1],
            *msg,
        ],
    )[0];

    MultisigCoefficients {
        aggregate_key,
        a,
        c,
        aggregate_commitment: RSa,
    }
}

#[cfg(test)]
mod tests {
    use dusk_bls12_381::BlsScalar;
    use dusk_bytes::Serializable;
    use dusk_jubjub::{
        GENERATOR_EXTENDED, JubJubAffine, JubJubExtended, JubJubScalar,
    };
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use rand_core::{CryptoRng, RngCore};
    use zeroize::Zeroize;

    use super::{
        MultisigNonce, aggregate_pk, combine, delinearization_coeff,
        hash_inputs, multisig_common, sign_round_1, sign_round_2,
        transcript_digest,
    };
    use crate::{PublicKey, SecretKey};

    /// An RNG that fills every buffer with the same byte.
    struct ConstRng(u8);

    impl RngCore for ConstRng {
        fn next_u32(&mut self) -> u32 {
            u32::from_le_bytes([self.0; 4])
        }

        fn next_u64(&mut self) -> u64 {
            u64::from_le_bytes([self.0; 8])
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(self.0);
        }

        fn try_fill_bytes(
            &mut self,
            dest: &mut [u8],
        ) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for ConstRng {}

    fn point_bytes(point: &JubJubExtended) -> [u8; 32] {
        JubJubAffine::from(*point).to_bytes()
    }

    /// This vector was generated in an isolated checkout of the exact
    /// pre-#70 implementation at commit
    /// 014598a1d0f2e9274f2a2ed664094d464af2a9ea. A temporary unit-only
    /// helper called its private `multisig_common`, `sign_round_2`, and
    /// `combine` functions; the helper was then removed. The assertions below
    /// cross-check the post-#70 implementation against those frozen results.
    ///
    /// Participants are ordered by `(sk, r, s)` as `(3, 11, 19)`,
    /// `(5, 13, 23)`, `(7, 17, 29)`, and `m = 31`. For affine coordinates
    /// `(u, v)`, the Poseidon `Domain::Other` preimages are:
    ///
    /// - `d_i`: `pk_i.u, pk_i.v, pk_0.u, pk_0.v, ...`
    /// - `a`: `pk_agg.u, pk_agg.v, m, R_0.u, R_0.v, S_0.u, S_0.v, ...`
    /// - `c`: `RSa.u, RSa.v, pk_agg.u, pk_agg.v, m`
    ///
    /// Here `pk_agg = sum(d_i * pk_i)`,
    /// `RSa = sum(R_i + a * S_i)`, and
    /// `z_i = r_i + a * s_i - c * d_i * sk_i`. Scalar arrays use canonical
    /// 32-byte little-endian encoding. Point arrays use the canonical 32-byte
    /// compressed affine encoding: little-endian `v`, with the `u` sign in
    /// the top bit. Each individual `z_i` is pinned before signature bytes,
    /// which are `sum(z_i)` followed by compressed `RSa`.
    #[test]
    fn multisig_transcript_known_answer() {
        const PUBLIC_KEYS: [[u8; 32]; 3] = [
            [
                0x65, 0xea, 0x90, 0xb3, 0x0f, 0xfa, 0xdc, 0x4c, 0x6d, 0xa5,
                0x4c, 0xb6, 0xcb, 0xcf, 0xa2, 0xff, 0xe1, 0xba, 0x78, 0xf2,
                0xd6, 0x0d, 0x87, 0x6e, 0x64, 0x69, 0x36, 0x8c, 0x56, 0x54,
                0x0a, 0x92,
            ],
            [
                0xd1, 0x62, 0xbd, 0x48, 0xb1, 0x53, 0xb9, 0xf3, 0xeb, 0x4c,
                0xea, 0xbb, 0x11, 0x29, 0x19, 0x1f, 0x15, 0xed, 0x97, 0xd5,
                0xf6, 0x79, 0xbe, 0x2a, 0xb5, 0x3d, 0x0a, 0xcb, 0xde, 0xc7,
                0x32, 0xe3,
            ],
            [
                0xc9, 0x43, 0x5b, 0x58, 0x97, 0x55, 0x05, 0xcf, 0x20, 0x94,
                0xa5, 0xa2, 0xc9, 0x78, 0x26, 0x16, 0x36, 0x85, 0x63, 0xc4,
                0xab, 0x0c, 0x95, 0x22, 0x5d, 0xef, 0xd0, 0x1c, 0x01, 0x6e,
                0x62, 0xe9,
            ],
        ];
        const R_POINTS: [[u8; 32]; 3] = [
            [
                0x93, 0xf8, 0xe3, 0x64, 0x19, 0xd2, 0x38, 0xb3, 0xfa, 0xe4,
                0x6a, 0xf6, 0x62, 0xc4, 0x1e, 0xfc, 0x2b, 0x5f, 0xd7, 0xaf,
                0xb5, 0x01, 0x13, 0x02, 0xc9, 0x9e, 0xa7, 0xe8, 0x5a, 0x86,
                0x06, 0x14,
            ],
            [
                0x4e, 0xb4, 0x04, 0x07, 0xae, 0x95, 0x00, 0x44, 0x02, 0x73,
                0x9b, 0x83, 0x13, 0x5b, 0xde, 0x20, 0x71, 0xda, 0x57, 0xa7,
                0x10, 0x7f, 0x46, 0x61, 0x20, 0x72, 0x2a, 0xc1, 0x89, 0x1a,
                0x51, 0x43,
            ],
            [
                0x03, 0x0f, 0xa1, 0x71, 0x56, 0xc3, 0x6a, 0xf8, 0x3d, 0xeb,
                0xa1, 0xa9, 0x59, 0xc7, 0x22, 0xce, 0xf3, 0xae, 0x9c, 0x5c,
                0x23, 0xa1, 0xee, 0x36, 0xaa, 0x5f, 0x22, 0x17, 0x5c, 0xd4,
                0xb3, 0xb2,
            ],
        ];
        const S_POINTS: [[u8; 32]; 3] = [
            [
                0xa8, 0x59, 0x4d, 0x43, 0x55, 0x54, 0xe9, 0x6f, 0xf4, 0x86,
                0x15, 0x33, 0x42, 0x0f, 0x36, 0x43, 0xb9, 0x1b, 0xda, 0xdb,
                0x44, 0xc8, 0x33, 0x3e, 0x9a, 0x1c, 0x41, 0x2b, 0x57, 0xfa,
                0x7f, 0x8f,
            ],
            [
                0xfd, 0x3a, 0xad, 0x1d, 0x0f, 0x5b, 0xcf, 0x15, 0x85, 0x68,
                0x5a, 0xe2, 0x9a, 0x51, 0x1d, 0xd9, 0xdd, 0xbf, 0xaf, 0x5c,
                0x24, 0xdc, 0xce, 0xd3, 0xa4, 0x3f, 0xa8, 0x66, 0x16, 0x3a,
                0x38, 0xd1,
            ],
            [
                0x4a, 0xe9, 0xf5, 0x81, 0xa9, 0x04, 0x54, 0x87, 0x71, 0xee,
                0x6e, 0x06, 0x98, 0xd1, 0xf7, 0xe3, 0x24, 0x41, 0xbf, 0x97,
                0x36, 0x1b, 0x92, 0x1d, 0x9e, 0xcc, 0x72, 0xf9, 0xf1, 0x17,
                0x2a, 0xce,
            ],
        ];
        const DELINEARIZATION: [[u8; 32]; 3] = [
            [
                0xc3, 0xe0, 0x44, 0xfd, 0xfd, 0x3a, 0xf6, 0x9b, 0x98, 0xe8,
                0xcd, 0xbe, 0xdc, 0xb7, 0x11, 0xaf, 0x49, 0x61, 0x1e, 0x2e,
                0x38, 0xc8, 0x91, 0x6b, 0xd8, 0x9b, 0x78, 0x40, 0x61, 0x94,
                0xc6, 0x03,
            ],
            [
                0x84, 0x53, 0x5c, 0xdd, 0x82, 0xd0, 0x0b, 0x75, 0xe4, 0xc5,
                0xfc, 0x73, 0xe4, 0xf7, 0x7c, 0x49, 0x33, 0x47, 0x62, 0x33,
                0x79, 0xb7, 0xe5, 0x89, 0x40, 0xd8, 0x02, 0xc9, 0xc3, 0x72,
                0x68, 0x02,
            ],
            [
                0x0b, 0xd1, 0x61, 0xd4, 0x38, 0x4b, 0x5e, 0xfc, 0xb6, 0x69,
                0x1a, 0xc2, 0x43, 0xb5, 0xb8, 0xa3, 0x1e, 0xbf, 0xe9, 0x31,
                0x03, 0x71, 0x6b, 0x5f, 0x6a, 0xd6, 0x0f, 0xbc, 0x0c, 0x05,
                0x3a, 0x00,
            ],
        ];
        const AGGREGATE_PUBLIC_KEY: [u8; 32] = [
            0xe7, 0xb0, 0xb6, 0xf2, 0x7c, 0x61, 0x2c, 0x27, 0x87, 0x9b, 0x30,
            0x2b, 0x92, 0x17, 0xfc, 0x71, 0xda, 0x31, 0x54, 0x3e, 0x18, 0x6f,
            0x65, 0xbc, 0x03, 0xfd, 0x8c, 0x99, 0xf7, 0x55, 0xbe, 0x2e,
        ];
        const BINDING_COEFFICIENT: [u8; 32] = [
            0x6f, 0x5d, 0x41, 0x73, 0xf3, 0xf5, 0x73, 0xe4, 0x8f, 0xc1, 0x19,
            0xa7, 0xf2, 0xa8, 0x3b, 0xfb, 0x76, 0x0d, 0x07, 0x14, 0x95, 0xb5,
            0xe7, 0x03, 0xdc, 0x9e, 0xb3, 0xb0, 0x1a, 0x37, 0xb5, 0x01,
        ];
        const AGGREGATE_COMMITMENT: [u8; 32] = [
            0xc8, 0x63, 0xd8, 0x8c, 0xbc, 0x96, 0x64, 0xae, 0x94, 0x4f, 0xa5,
            0xdc, 0xc8, 0xe8, 0xec, 0x43, 0xaf, 0xda, 0x23, 0x68, 0x4b, 0x3f,
            0x07, 0xfa, 0x69, 0xe5, 0x7f, 0xc1, 0x27, 0x2b, 0x4b, 0x0e,
        ];
        const CHALLENGE: [u8; 32] = [
            0x13, 0x88, 0xd9, 0x07, 0x87, 0x49, 0x7d, 0x07, 0xf6, 0x29, 0xd4,
            0x8d, 0x25, 0xb5, 0x85, 0xef, 0xbd, 0xfe, 0x52, 0x93, 0x81, 0x3f,
            0x83, 0x91, 0x3e, 0x64, 0x9f, 0x66, 0x1a, 0x00, 0xc2, 0x01,
        ];
        const INDIVIDUAL_SHARES: [[u8; 32]; 3] = [
            [
                0xe4, 0xa8, 0x6c, 0xcd, 0xb8, 0xf1, 0x41, 0xa6, 0xc8, 0x76,
                0x13, 0xd4, 0xa6, 0x0f, 0xaa, 0xc8, 0x4c, 0x1a, 0xd3, 0x6b,
                0x02, 0x52, 0xd8, 0x20, 0xd8, 0xaa, 0x71, 0x4d, 0xbe, 0x80,
                0x01, 0x0b,
            ],
            [
                0x6b, 0x3c, 0x11, 0xd4, 0x5b, 0x07, 0x6f, 0x25, 0xe5, 0x92,
                0xbc, 0xae, 0x3f, 0x35, 0xe7, 0xf9, 0x77, 0x67, 0x14, 0xea,
                0x04, 0x80, 0x1f, 0x8c, 0xb3, 0x11, 0x30, 0x81, 0x31, 0xa1,
                0x5d, 0x02,
            ],
            [
                0x32, 0x20, 0xc5, 0x21, 0xa6, 0xb7, 0xf6, 0xf5, 0xed, 0x1e,
                0x92, 0xc5, 0x4a, 0x7f, 0x1c, 0xec, 0xcf, 0xc3, 0x0f, 0x16,
                0xe9, 0x7a, 0x33, 0x5d, 0x6c, 0x59, 0x6c, 0x89, 0x66, 0xfa,
                0x77, 0x05,
            ],
        ];
        const SIGNATURE: [u8; 64] = [
            0xca, 0xd8, 0x4b, 0xec, 0x5b, 0xa2, 0x10, 0xf1, 0x18, 0x18, 0x9a,
            0x7b, 0x9d, 0xa3, 0x45, 0x08, 0x94, 0x0a, 0xc3, 0x6a, 0xef, 0x11,
            0xc4, 0x03, 0x4f, 0x66, 0xda, 0xf2, 0x6b, 0x67, 0x59, 0x04, 0xc8,
            0x63, 0xd8, 0x8c, 0xbc, 0x96, 0x64, 0xae, 0x94, 0x4f, 0xa5, 0xdc,
            0xc8, 0xe8, 0xec, 0x43, 0xaf, 0xda, 0x23, 0x68, 0x4b, 0x3f, 0x07,
            0xfa, 0x69, 0xe5, 0x7f, 0xc1, 0x27, 0x2b, 0x4b, 0x0e,
        ];

        let secret_keys = [3u64, 5, 7]
            .map(|value| SecretKey::from(JubJubScalar::from(value)));
        let public_keys = secret_keys.each_ref().map(PublicKey::from);
        let r_scalars = [11u64, 13, 17].map(JubJubScalar::from);
        let s_scalars = [19u64, 23, 29].map(JubJubScalar::from);
        let r_points = r_scalars.map(|scalar| GENERATOR_EXTENDED * scalar);
        let s_points = s_scalars.map(|scalar| GENERATOR_EXTENDED * scalar);
        let message = BlsScalar::from(31u64);

        assert_eq!(public_keys.map(|pk| pk.to_bytes()), PUBLIC_KEYS);
        assert_eq!(r_points.each_ref().map(point_bytes), R_POINTS);
        assert_eq!(s_points.each_ref().map(point_bytes), S_POINTS);

        let keys = hash_inputs(&public_keys);
        let transcript = multisig_common(
            &public_keys,
            &keys,
            &r_points,
            &s_points,
            &message,
        );
        assert_eq!(
            transcript.aggregate_key.delinearization.len(),
            DELINEARIZATION.len()
        );
        for ((pk_i, d_i), expected) in keys
            .iter()
            .zip(&transcript.aggregate_key.delinearization)
            .zip(DELINEARIZATION)
        {
            assert_eq!(*d_i, delinearization_coeff(pk_i, &keys));
            assert_eq!(d_i.to_bytes(), expected);
        }
        assert_eq!(
            point_bytes(&transcript.aggregate_key.point),
            AGGREGATE_PUBLIC_KEY
        );
        assert_eq!(
            aggregate_pk(&public_keys).map(|pk| pk.to_bytes()),
            Ok(AGGREGATE_PUBLIC_KEY)
        );
        assert_eq!(transcript.a.to_bytes(), BINDING_COEFFICIENT);
        assert_eq!(
            point_bytes(&transcript.aggregate_commitment),
            AGGREGATE_COMMITMENT
        );
        assert_eq!(transcript.c.to_bytes(), CHALLENGE);

        let shares: [JubJubScalar; 3] = core::array::from_fn(|index| {
            sign_round_2(
                &secret_keys[index],
                MultisigNonce {
                    r: r_scalars[index],
                    s: s_scalars[index],
                    transcript: transcript_digest(&keys, &message),
                },
                &public_keys,
                &r_points,
                &s_points,
                &message,
            )
            .expect("fixed transcript should produce a valid share")
        });
        assert_eq!(
            shares.each_ref().map(JubJubScalar::to_bytes),
            INDIVIDUAL_SHARES
        );
        let signature =
            combine(&shares, &public_keys, &r_points, &s_points, &message)
                .expect("fixed shares should combine");
        assert_eq!(signature.to_bytes(), SIGNATURE);
    }

    #[test]
    fn nonce_state_zeroizes_every_field() {
        let mut nonce = MultisigNonce {
            r: JubJubScalar::from(41u64),
            s: JubJubScalar::from(43u64),
            transcript: BlsScalar::from(47u64),
        };

        nonce.zeroize();

        assert_eq!(nonce.r, JubJubScalar::zero());
        assert_eq!(nonce.s, JubJubScalar::zero());
        assert_eq!(nonce.transcript, BlsScalar::zero());
    }

    /// Round two consumes the nonce state, so its drop is what wipes it.
    #[test]
    fn nonce_state_zeroizes_on_drop() {
        let mut slot = core::mem::MaybeUninit::new(MultisigNonce {
            r: JubJubScalar::from(41u64),
            s: JubJubScalar::from(43u64),
            transcript: BlsScalar::from(47u64),
        });
        let nonce = slot.as_mut_ptr();

        // SAFETY: `slot` holds an initialized state, dropped exactly once.
        unsafe { core::ptr::drop_in_place(nonce) };

        // Read the storage as bytes, without forming a reference to the
        // dropped state. Its fields are all runs of `u64` limbs, so it has no
        // padding, and the drop leaves every byte written.
        let bytes = nonce.cast::<u8>();
        for i in 0..core::mem::size_of::<MultisigNonce>() {
            // SAFETY: `i` lies within `slot`, which is still allocated.
            let byte = unsafe { core::ptr::read_volatile(bytes.add(i)) };
            assert_eq!(byte, 0, "byte {i}");
        }
    }

    type RoundOne = (MultisigNonce, JubJubExtended, JubJubExtended);

    /// Runs three sessions of the signer `sk = 7`, with the given round-one
    /// outputs, next to a co-signer that commits afresh in each.
    ///
    /// The signer's shares `z_i = r + a_i * s - c_i * d * sk` are three linear
    /// equations. If the sessions share `(r, s)`, they determine `sk`. Returns
    /// their solution.
    #[allow(non_snake_case)]
    fn solve_shares_for_key(
        msgs: [BlsScalar; 3],
        round_1: [RoundOne; 3],
    ) -> JubJubScalar {
        let sk = SecretKey::from(JubJubScalar::from(7u64));
        let co_signer = SecretKey::from(JubJubScalar::from(11u64));
        let pk_vec = [PublicKey::from(&sk), PublicKey::from(&co_signer)];
        let keys = hash_inputs(&pk_vec);
        let mut rng = StdRng::seed_from_u64(59);

        let [mut z, mut a, mut cd] = [[JubJubScalar::zero(); 3]; 3];
        for (i, (msg, (nonce, R, S))) in msgs.iter().zip(round_1).enumerate() {
            let (_, R_co, S_co) =
                sign_round_1(&mut rng, &co_signer, &pk_vec, msg, None);
            let (R_vec, S_vec) = ([R, R_co], [S, S_co]);
            let coefficients =
                multisig_common(&pk_vec, &keys, &R_vec, &S_vec, msg);

            z[i] = sign_round_2(&sk, nonce, &pk_vec, &R_vec, &S_vec, msg)
                .expect("valid transcript");
            a[i] = coefficients.a;
            cd[i] =
                coefficients.c * coefficients.aggregate_key.delinearization[0];
        }

        // Eliminate r, then s.
        let [dz2, dz3] = [z[1] - z[0], z[2] - z[0]];
        let [da2, da3] = [a[1] - a[0], a[2] - a[0]];
        let [dcd2, dcd3] = [cd[1] - cd[0], cd[2] - cd[0]];
        (dz3 * da2 - dz2 * da3)
            * (da3 * dcd2 - da2 * dcd3)
                .invert()
                .expect("independent equations")
    }

    /// Shared nonces over three messages give away the key. Under a constant
    /// RNG, round one derives a fresh pair for each message instead, and the
    /// same solution misses the key.
    #[test]
    fn three_shares_fix_the_key_only_with_shared_nonces() {
        let sk = SecretKey::from(JubJubScalar::from(7u64));
        let co_signer = SecretKey::from(JubJubScalar::from(11u64));
        let pk_vec = [PublicKey::from(&sk), PublicKey::from(&co_signer)];
        let msgs = [1u64, 2, 3].map(BlsScalar::from);

        let shared = msgs.each_ref().map(|msg| {
            let r = JubJubScalar::from(13u64);
            let s = JubJubScalar::from(17u64);
            let transcript = transcript_digest(&hash_inputs(&pk_vec), msg);
            let nonce = MultisigNonce { r, s, transcript };
            (nonce, GENERATOR_EXTENDED * r, GENERATOR_EXTENDED * s)
        });
        assert_eq!(solve_shares_for_key(msgs, shared), *sk.as_ref());

        let hedged = msgs.each_ref().map(|msg| {
            sign_round_1(&mut ConstRng(0x42), &sk, &pk_vec, msg, None)
        });
        assert_ne!(solve_shares_for_key(msgs, hedged), *sk.as_ref());
    }

    /// Under a constant RNG, three attempts to sign one message with one key
    /// list share their nonces, and give away the key, unless each attempt
    /// passes its own session input.
    #[test]
    fn session_inputs_separate_attempts_at_one_transcript() {
        let sk = SecretKey::from(JubJubScalar::from(7u64));
        let co_signer = SecretKey::from(JubJubScalar::from(11u64));
        let pk_vec = [PublicKey::from(&sk), PublicKey::from(&co_signer)];
        let msg = BlsScalar::from(1u64);
        let sessions = [1u64, 2, 3].map(BlsScalar::from);
        let attempts = |sessions: [Option<&BlsScalar>; 3]| {
            let round_1 = sessions.map(|session| {
                sign_round_1(&mut ConstRng(0x42), &sk, &pk_vec, &msg, session)
            });
            solve_shares_for_key([msg; 3], round_1)
        };

        assert_eq!(attempts([None; 3]), *sk.as_ref());
        assert_eq!(attempts([Some(&sessions[0]); 3]), *sk.as_ref());
        assert_ne!(attempts(sessions.each_ref().map(Some)), *sk.as_ref());
    }
}
