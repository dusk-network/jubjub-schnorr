// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bls12_381::BlsScalar;
use dusk_bytes::Serializable;
use dusk_jubjub::{JubJubAffine, JubJubExtended};

use crate::{Error, SecretKeyVarGen, SignatureVarGen};

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

/// Structure representing a [`PublicKeyVarGen`], consisting of a public key
/// [`JubJubExtended`] point and a variable generator [`JubJubExtended`] point
/// on the JubJub curve. This public key allows for the verification of
/// signatures created with its corresponding variable generator secret key
/// without revealing the secret key itself.
///
/// # Feature
///
/// Only available with the "var_generator" feature enabled.
///
/// ## Examples
///
/// Generate a [`PublicKeyVarGen`] from a [`SecretKeyVarGen`]:
/// ```
/// use jubjub_schnorr::{SecretKeyVarGen, PublicKeyVarGen};
/// use dusk_bls12_381::BlsScalar;
/// use rand::rngs::StdRng;
/// use rand::SeedableRng;
///
/// let mut rng = StdRng::seed_from_u64(12345);
/// let sk = SecretKeyVarGen::random(&mut rng);
/// let pk = PublicKeyVarGen::from(&sk);
/// ```
#[derive(Default, Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct PublicKeyVarGen {
    pk: JubJubExtended,
    generator: JubJubExtended,
}

impl From<&SecretKeyVarGen> for PublicKeyVarGen {
    fn from(sk: &SecretKeyVarGen) -> Self {
        let generator = *sk.generator();
        let pk = generator * sk.secret_key();

        PublicKeyVarGen { pk, generator }
    }
}

impl Serializable<64> for PublicKeyVarGen {
    type Error = Error;

    fn to_bytes(&self) -> [u8; 64] {
        let mut buf = [0u8; 64];
        let pk: JubJubAffine = self.pk.into();
        let pk_bytes = pk.to_bytes();
        let gen: JubJubAffine = self.generator.into();
        let gen_bytes = gen.to_bytes();
        buf[..32].copy_from_slice(&pk_bytes);
        buf[32..].copy_from_slice(&gen_bytes);
        buf
    }

    fn from_bytes(bytes: &[u8; 64]) -> Result<Self, Error> {
        let mut pk_bytes = [0u8; 32];
        let mut gen_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(&bytes[..32]);
        gen_bytes.copy_from_slice(&bytes[32..]);
        let pk: JubJubExtended =
            <JubJubAffine as Serializable<32>>::from_bytes(&pk_bytes)?.into();
        let generator: JubJubExtended =
            <JubJubAffine as Serializable<32>>::from_bytes(&gen_bytes)?.into();
        Ok(Self { pk, generator })
    }
}

impl PublicKeyVarGen {
    /// Returns a reference to the [`JubJubExtended`] public key.
    pub fn public_key(&self) -> &JubJubExtended {
        &self.pk
    }

    /// Returns a reference to the [`JubJubExtended`] generator.
    pub fn generator(&self) -> &JubJubExtended {
        &self.generator
    }

    /// Verifies that the given Schnorr [`SignatureVarGen`] is valid.
    ///
    /// This function computes a challenge hash using the stored `R` point, the
    /// public key `pk`, and the provided message, then performs the
    /// verification by checking the equality of `u * G + c * PK` and `R`.
    ///
    /// ## Parameters
    ///
    /// - `sig_var_gen`: Reference to the [`SignatureVarGen`] to be verified.
    /// - `message`: The message in [`BlsScalar`] format.
    ///
    /// ## Returns
    ///
    /// Returns a `Result` indicating if the Schnorr [`SignatureVarGen`] is
    /// valid.
    pub fn verify(
        &self,
        sig_var_gen: &SignatureVarGen,
        message: BlsScalar,
    ) -> Result<(), Error> {
        if !self.is_valid() || !sig_var_gen.is_valid() {
            return Err(Error::InvalidPoint);
        }

        // Compute challenge value, c = H(R||pk||m);
        let c = crate::signatures::challenge_hash(
            sig_var_gen.R(),
            self.public_key().into(),
            message,
        );

        // Compute verification steps
        // u * G + c * PK
        let point_1 =
            (*self.generator() * sig_var_gen.u()) + (self.public_key() * c);

        if !point_1.eq(sig_var_gen.R()) {
            return Err(Error::InvalidSignature);
        }

        Ok(())
    }

    /// Create a [`PublicKeyVarGen`] from its internal parts
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
        generator: JubJubExtended,
    ) -> Self {
        Self { pk, generator }
    }

    /// Returns true if the inner point is valid according to certain criteria.
    ///
    /// A [`PublicKeyVarGen`] is considered valid if its inner points meets the
    /// following conditions:
    /// 1. It is free of an $h$-torsion component and exists within the
    ///    $q$-order subgroup $\mathbb{G}_2$.
    /// 2. It is on the curve.
    /// 3. It is not the identity.
    pub fn is_valid(&self) -> bool {
        let is_identity: bool = self.pk.is_identity().into();
        let pk_is_valid = self.pk.is_torsion_free().into()
            && self.pk.is_on_curve().into()
            && !is_identity;

        let is_identity: bool = self.generator.is_identity().into();
        let gen_is_valid = self.generator.is_torsion_free().into()
            && self.generator.is_on_curve().into()
            && !is_identity;

        pk_is_valid && gen_is_valid
    }
}
