// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! # Public Key Module
//!
//! This module provides the public key components for the Schnorr signature
//! scheme, necessary for verifying signature validity. It includes single and
//! double public keys, as well as public keys for signing with a variable
//! generator. Public keys in this context are points on the JubJub
//! elliptic curve generated from the [`SecretKey`] and generator point, and
//! they provide the basis for signature verification.

use dusk_bls12_381::BlsScalar;
use dusk_bytes::{Error as BytesError, Serializable};
use dusk_jubjub::{JubJubAffine, JubJubExtended, GENERATOR_EXTENDED};

use crate::{Error, SecretKey, Signature};

#[cfg(feature = "double")]
pub(crate) mod double;

#[cfg(feature = "var_generator")]
pub(crate) mod var_gen;

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

/// Structure representing a [`PublicKey`], consisting of a [`JubJubExtended`]
/// point on the JubJub curve. This public key allows for the verification of
/// signatures created with its corresponding secret key without revealing the
/// secret key itself.
///
/// ## Examples
///
/// Generate a [`PublicKey`] from a [`SecretKey`]:
/// ```
/// use jubjub_schnorr::{SecretKey, PublicKey};
/// use dusk_bls12_381::BlsScalar;
/// use rand::rngs::StdRng;
/// use rand::SeedableRng;
///
/// let mut rng = StdRng::seed_from_u64(12345);
/// let sk = SecretKey::random(&mut rng);
/// let pk = PublicKey::from(&sk);
/// ```
#[derive(Default, Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct PublicKey(JubJubExtended);

impl From<&SecretKey> for PublicKey {
    fn from(sk: &SecretKey) -> Self {
        let pk = GENERATOR_EXTENDED * sk.0;

        PublicKey(pk)
    }
}

impl From<JubJubExtended> for PublicKey {
    fn from(p: JubJubExtended) -> PublicKey {
        PublicKey(p)
    }
}

impl From<&JubJubExtended> for PublicKey {
    fn from(p: &JubJubExtended) -> PublicKey {
        PublicKey(*p)
    }
}

impl AsRef<JubJubExtended> for PublicKey {
    fn as_ref(&self) -> &JubJubExtended {
        &self.0
    }
}

impl Serializable<32> for PublicKey {
    type Error = BytesError;

    fn to_bytes(&self) -> [u8; 32] {
        JubJubAffine::from(self.0).to_bytes()
    }

    fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Self::Error> {
        let pk: JubJubAffine = match JubJubAffine::from_bytes(*bytes).into() {
            Some(pk) => pk,
            None => return Err(BytesError::InvalidData),
        };
        Ok(Self(pk.into()))
    }
}

impl PublicKey {
    /// Verifies that the given Schnorr [`Signature`] is valid.
    ///
    /// This function computes a challenge hash `c` using the stored `R` point
    /// and the provided message, then performs the verification by checking
    /// that:
    /// ```text
    /// u * G + c * PK == R
    /// ```
    ///
    /// ## Parameters
    ///
    /// - `sig`: Reference to the [`Signature`] to be verified.
    /// - `message`: The message as [`BlsScalar`].
    ///
    /// ## Returns
    ///
    /// Returns a `Result` indicating if the Schnorr [`Signature`] is valid.
    pub fn verify(
        &self,
        sig: &Signature,
        message: BlsScalar,
    ) -> Result<(), Error> {
        if !self.is_valid() || !sig.is_valid() {
            return Err(Error::InvalidPoint);
        }

        // Compute challenge value, c = H(R||pk||m);
        let c = crate::signatures::challenge_hash(sig.R(), *self, message);

        // Compute verification steps
        // u * G + c * PK
        let point_1 = (GENERATOR_EXTENDED * sig.u()) + (self.as_ref() * c);

        if !point_1.eq(sig.R()) {
            return Err(Error::InvalidSignature);
        }

        Ok(())
    }

    /// Create a [`PublicKey`] from its internal parts.
    ///
    /// The public keys are generated from a bijective function that takes a
    /// secret keys domain. If keys are generated directly from curve
    /// points, there is no guarantee a secret key exists - in fact, the
    /// discrete logarithm property will guarantee the secret key cannot be
    /// extracted from this public key.
    ///
    /// If you opt to generate the keys manually, be sure you have its secret
    /// counterpart - otherwise this key will be of no use.
    pub const fn from_raw_unchecked(key: JubJubExtended) -> Self {
        Self(key)
    }

    /// Returns true if the inner point is valid according to certain criteria.
    ///
    /// A [`PublicKey`] is considered valid if its inner point meets the
    /// following conditions:
    /// 1. It is free of an $h$-torsion component and exists within the
    ///    $q$-order subgroup $\mathbb{G}_2$.
    /// 2. It is on the curve.
    /// 3. It is not the identity.
    pub fn is_valid(&self) -> bool {
        let is_identity: bool = self.0.is_identity().into();
        self.0.is_torsion_free().into()
            && self.0.is_on_curve().into()
            && !is_identity
    }
}
