// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bls12_381::BlsScalar;
use dusk_bytes::{DeserializableSlice, Serializable};
use dusk_jubjub::{
    JubJubAffine, JubJubExtended, GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED,
};

use crate::{Error, SecretKey, SignatureDouble};

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

/// Structure representing a [`PublicKeyDouble`], consisting of two
/// [`JubJubExtended`] poinst on the JubJub curve.
///
/// The [`PublicKeyDouble`] struct contains two public keys: `(pk, pk')`,
/// which are generated from different bases.
/// Specifically: `pk = sk * G` with the standard generator point [`G`],
/// and `pk' = sk * G'` with generator point [`G'`].
///
/// This construct allows for a double-key mechanism to enable more advanced
/// uses then the single-key variant. For example, it is used in Phoenix for
/// proof delegation while preventing the leakage of secret keys.
///
/// ## Fields
///
/// - `(pk, pk')`: two [`PublicKey`], where `pk` is generated with [`G`] and
///   `pk'` with [`G'`]
///
/// Generate a [`PublicKeyDouble`] from a [`SecretKey`]:
/// ## Example
/// ```
/// use rand::rngs::StdRng;
/// use rand::SeedableRng;
/// use jubjub_schnorr::{SecretKey, PublicKeyDouble};
///
/// let mut rng = StdRng::seed_from_u64(12345);
/// let sk = SecretKey::random(&mut rng);
/// let pk_double = PublicKeyDouble::from(&sk);
/// ```
///
/// [`G`]: `GENERATOR_EXTENDED`
/// [`G'`]: `GENERATOR_NUMS_EXTENDED`
#[derive(Default, Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct PublicKeyDouble(JubJubExtended, JubJubExtended);

impl PublicKeyDouble {
    /// Returns the `PublicKey` corresponding to the standard elliptic curve
    /// generator point `sk * G`.
    #[allow(non_snake_case)]
    pub fn pk(&self) -> &JubJubExtended {
        &self.0
    }

    /// Returns the `PublicKey` corresponding to the secondary elliptic
    /// curve generator point `sk * G'`.
    #[allow(non_snake_case)]
    pub fn pk_prime(&self) -> &JubJubExtended {
        &self.1
    }

    /// Verifies that the given Schnorr [`SignatureDouble`] is valid.
    ///
    /// It computes the challenge scalar and verifies the equality of points,
    /// thereby ensuring the [`SignatureDouble`] is valid.
    ///
    /// # Parameters
    ///
    /// * `sig_double`: Reference to the [`SignatureDouble`] to be verified.
    /// - `message`: The message as [`BlsScalar`].
    ///
    /// # Returns
    ///
    /// Returns a `Result` indicating if the Schnorr [`SignatureDouble`] is
    /// valid.
    #[allow(non_snake_case)]
    pub fn verify(
        &self,
        sig_double: &SignatureDouble,
        message: BlsScalar,
    ) -> Result<(), Error> {
        if !self.is_valid() || !sig_double.is_valid() {
            return Err(Error::InvalidPoint);
        }

        // Compute challenge value, c = H(R||R_prime||pk||m);
        let c = crate::signatures::double::challenge_hash(
            sig_double.R(),
            sig_double.R_prime(),
            self.pk().into(),
            message,
        );

        // Compute verification steps
        // u * G + c * PK
        let point_1 = (GENERATOR_EXTENDED * sig_double.u()) + (self.pk() * c);
        // u * G' + c * PK'
        let point_2 =
            (GENERATOR_NUMS_EXTENDED * sig_double.u()) + (self.pk_prime() * c);

        // Verify point equations
        // point_1 = R && point_2 = R_prime
        if !(point_1.eq(sig_double.R()) && point_2.eq(sig_double.R_prime())) {
            return Err(Error::InvalidSignature);
        }

        Ok(())
    }

    /// Create a [`PublicKeyDouble`] from its internal parts
    ///
    /// The public keys are generated from a bijective function that takes a
    /// secret keys domain. If keys are generated directly from curve
    /// points, there is no guarantee a secret key exists - in fact, the
    /// discrete logarithm property will guarantee the secret key cannot be
    /// extracted from this public key.
    ///
    /// If you opt to generate the keys manually, be sure you have its secret
    /// counterpart - otherwise this key will be of no use.
    pub const fn from_raw_unchecked(
        pk: JubJubExtended,
        pk_prime: JubJubExtended,
    ) -> Self {
        Self(pk, pk_prime)
    }

    /// Returns true if the inner points are valid according to certain
    /// criteria.
    ///
    /// A [`PublicKeyDouble`] is considered valid if its inner points meets the
    /// following conditions:
    /// 1. It is free of an $h$-torsion component and exists within the
    ///    $q$-order subgroup $\mathbb{G}_2$.
    /// 2. It is on the curve.
    /// 3. It is not the identity.
    pub fn is_valid(&self) -> bool {
        let is_identity: bool = self.0.is_identity().into();
        let point_0_valid = self.0.is_torsion_free().into()
            && self.0.is_on_curve().into()
            && !is_identity;

        let is_identity: bool = self.1.is_identity().into();
        let point_1_valid = self.1.is_torsion_free().into()
            && self.1.is_on_curve().into()
            && !is_identity;

        point_0_valid && point_1_valid
    }
}

impl From<&SecretKey> for PublicKeyDouble {
    fn from(sk: &SecretKey) -> Self {
        let pk = GENERATOR_EXTENDED * sk.as_ref();
        let pk_prime = GENERATOR_NUMS_EXTENDED * sk.as_ref();

        PublicKeyDouble(pk, pk_prime)
    }
}

impl Serializable<64> for PublicKeyDouble {
    type Error = Error;

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        let pk: JubJubAffine = self.pk().into();
        let pk_prime: JubJubAffine = self.pk_prime().into();
        buf[..32].copy_from_slice(&pk.to_bytes()[..]);
        buf[32..].copy_from_slice(&pk_prime.to_bytes()[..]);
        buf
    }

    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let pk = JubJubAffine::from_slice(&bytes[..32])?;
        let pk_prime = JubJubAffine::from_slice(&bytes[32..])?;
        Ok(PublicKeyDouble(pk.into(), pk_prime.into()))
    }
}
