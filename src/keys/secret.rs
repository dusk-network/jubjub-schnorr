// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! # Secret Key Module
//!
//! This module provides the `SecretKey` and `SecretKeyVarGen`, essential for
//! signing messages, proving ownership. It facilitates the generation of
//! Schnorr signatures, supporting both single and double signature schemes, as
//! well as signatures with variable generators.

use dusk_bls12_381::BlsScalar;
use dusk_bytes::{Error, Serializable};
use dusk_jubjub::{JubJubScalar, GENERATOR_EXTENDED};
use ff::Field;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::{PublicKey, Signature};

#[cfg(feature = "var_generator")]
pub(crate) mod var_gen;

#[cfg(feature = "double")]
mod double;

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

/// Structure representing a [`SecretKey`], represented as a private scalar
/// in the JubJub scalar field.
///
/// ## Safety
///
/// To ensure that no secret information lingers in memory after the variable
/// goes out of scope, we advice calling `zeroize` before the variable goes out
/// of scope.
///
/// ## Examples
///
/// Generate a random `SecretKey`:
/// ```
/// use jubjub_schnorr::SecretKey;
/// use rand::rngs::StdRng;
/// use rand::SeedableRng;
/// use zeroize::Zeroize;
///
/// let mut rng = StdRng::seed_from_u64(12345);
/// let mut sk = SecretKey::random(&mut rng);
///
/// // do something with the sk
///
/// sk.zeroize();
/// ```
#[allow(non_snake_case)]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Zeroize)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct SecretKey(pub(crate) JubJubScalar);

impl From<JubJubScalar> for SecretKey {
    fn from(s: JubJubScalar) -> SecretKey {
        SecretKey(s)
    }
}

impl From<&JubJubScalar> for SecretKey {
    fn from(s: &JubJubScalar) -> SecretKey {
        SecretKey(*s)
    }
}

impl AsRef<JubJubScalar> for SecretKey {
    fn as_ref(&self) -> &JubJubScalar {
        &self.0
    }
}

impl SecretKey {
    /// This will create a random [`SecretKey`] from a scalar
    /// of the Field JubJubScalar.
    pub fn random<T>(rand: &mut T) -> SecretKey
    where
        T: RngCore + CryptoRng,
    {
        let fr = JubJubScalar::random(rand);

        SecretKey(fr)
    }
}

impl Serializable<32> for SecretKey {
    type Error = Error;

    fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        let sk = match JubJubScalar::from_bytes(bytes).into() {
            Some(sk) => sk,
            None => return Err(Error::InvalidData),
        };
        Ok(Self(sk))
    }
}

impl SecretKey {
    /// Signs a chosen message with a given secret key using the dusk variant
    /// of the Schnorr signature scheme.
    ///
    /// This function performs the following cryptographic operations:
    /// - Generates a random nonce `r`.
    /// - Computes `R = r * G`.
    /// - Computes the challenge `c = H(R || pk || m)`.
    /// - Computes the signature `u = r - c * sk`.
    ///
    /// ## Parameters
    ///
    /// - `rng`: Reference to the random number generator.
    /// - `message`: The message in [`BlsScalar`] to be signed.
    ///
    /// ## Returns
    ///
    /// Returns a new [`Signature`] containing the `u` scalar and `R` point.
    ///
    /// ## Example
    ///
    /// Sign a message with a [`SecretKey`] and verify with the respective
    /// [`PublicKey`]:
    /// ```
    /// use jubjub_schnorr::{SecretKey, PublicKey};
    /// use dusk_jubjub::JubJubScalar;
    /// use dusk_bls12_381::BlsScalar;
    /// use rand::rngs::StdRng;
    /// use rand::SeedableRng;
    /// use ff::Field;
    ///
    /// let mut rng = StdRng::seed_from_u64(12345);
    ///
    /// let message = BlsScalar::random(&mut rng);
    ///
    /// let sk = SecretKey::random(&mut rng);
    /// let pk = PublicKey::from(&sk);
    ///
    /// let signature = sk.sign(&mut rng, message);
    ///
    /// assert!(pk.verify(&signature, message).is_ok());
    /// ```
    ///
    /// [`PublicKey`]: [`crate::PublicKey`]
    #[allow(non_snake_case)]
    pub fn sign<R>(&self, rng: &mut R, msg: BlsScalar) -> Signature
    where
        R: RngCore + CryptoRng,
    {
        // Create random scalar value for scheme, r
        let r = JubJubScalar::random(rng);

        // Derive a point from r, to sign with the message
        // R = r * G
        let R = GENERATOR_EXTENDED * r;

        // Compute challenge value, c = H(R||pk||m);
        let c =
            crate::signatures::challenge_hash(&R, PublicKey::from(self), msg);

        // Compute scalar signature, U = r - c * sk,
        let u = r - (c * self.as_ref());

        Signature::new(u, R)
    }
}
