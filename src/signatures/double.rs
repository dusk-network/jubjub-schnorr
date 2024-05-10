// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bls12_381::BlsScalar;
use dusk_bytes::{DeserializableSlice, Error as BytesError, Serializable};
use dusk_jubjub::{JubJubAffine, JubJubExtended, JubJubScalar};
use dusk_poseidon::sponge::truncated::hash;

use crate::PublicKey;

#[cfg(feature = "zk")]
use dusk_plonk::prelude::{Composer, Witness, WitnessPoint};

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

/// Structure representing a Schnorr signature with a double-key mechanism.
///
/// # Feature
///
/// Only available with the "double" feature enabled.
///
/// ## Fields
///
/// - `u`: A [`JubJubScalar`] scalar value representing part of the Schnorr
///   signature.
/// - 'R': A [`JubJubExtended`] point representing the nonce generated with the
///   generator point [`G`].
/// - 'R_prime': A [`JubJubExtended`] point representing the nonce generated
///   with the generator point [`G'`].
///
/// ## Example
/// ```
/// use rand::rngs::StdRng;
/// use rand::SeedableRng;
/// use jubjub_schnorr::{SecretKey, PublicKeyDouble, SignatureDouble};
/// use dusk_bls12_381::BlsScalar;
/// use ff::Field;
///
/// let mut rng = StdRng::seed_from_u64(2321u64);
///
/// let sk = SecretKey::random(&mut rng);
/// let message = BlsScalar::random(&mut rng);
/// let pk_double = PublicKeyDouble::from(&sk);
///
/// let signature = sk.sign_double(&mut rng, message);
///
/// assert!(pk_double.verify(&signature, message).is_ok());
/// ```
///
/// [`G`]: `GENERATOR_EXTENDED`
/// [`G'`]: `GENERATOR_NUMS_EXTENDED`
#[derive(Default, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
#[allow(non_snake_case)]
pub struct SignatureDouble {
    u: JubJubScalar,
    R: JubJubExtended,
    R_prime: JubJubExtended,
}

impl SignatureDouble {
    /// Returns the `JubJubScalar` `u` component of the Schnorr signature.
    pub fn u(&self) -> &JubJubScalar {
        &self.u
    }

    /// Returns the nonce point `R`
    #[allow(non_snake_case)]
    pub fn R(&self) -> &JubJubExtended {
        &self.R
    }

    /// Returns the nonce point `R_prime`
    #[allow(non_snake_case)]
    pub fn R_prime(&self) -> &JubJubExtended {
        &self.R_prime
    }

    /// Creates a new [`SignatureDouble`]
    #[allow(non_snake_case)]
    pub(crate) fn new(
        u: JubJubScalar,
        R: JubJubExtended,
        R_prime: JubJubExtended,
    ) -> Self {
        Self { u, R, R_prime }
    }

    /// Appends the `Signature` as a witness to the circuit composed by the
    /// `Composer`.
    ///
    /// # Feature
    ///
    /// This function is only available when the "zk" feature is enabled.
    ///
    /// # Parameters
    ///
    /// * `composer`: Mutable reference to a `Composer`.
    ///
    /// # Returns
    ///
    /// A tuple comprising the `Witness` of scalar `u`, and `WitnessPoint`s of
    /// `R` and `R'`.
    #[cfg(feature = "zk")]
    pub fn append(
        &self,
        composer: &mut Composer,
    ) -> (Witness, WitnessPoint, WitnessPoint) {
        // TODO: check whether the signature should be public
        let u = composer.append_witness(self.u);
        let r = composer.append_point(self.R());
        let r_p = composer.append_point(self.R_prime());

        (u, r, r_p)
    }

    /// Returns true if the inner point is valid according to certain criteria.
    ///
    /// A [`DoubleSignature`] is considered valid if its inner points `R` and
    /// `R_prime` meet the following conditions:
    /// 1. It is free of an $h$-torsion component and exists within the
    ///    $q$-order subgroup $\mathbb{G}_2$.
    /// 2. It is on the curve.
    /// 3. It is not the identity.
    pub fn is_valid(&self) -> bool {
        let is_identity: bool = self.R.is_identity().into();
        let r_is_valid = self.R.is_torsion_free().into()
            && self.R.is_on_curve().into()
            && !is_identity;

        let is_identity: bool = self.R_prime.is_identity().into();
        let r_prime_is_valid = self.R_prime.is_torsion_free().into()
            && self.R_prime.is_on_curve().into()
            && !is_identity;
        r_is_valid && r_prime_is_valid
    }
}

impl Serializable<96> for SignatureDouble {
    type Error = BytesError;

    #[allow(non_snake_case)]
    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let R_affine: JubJubAffine = self.R().into();
        let R_p_affine: JubJubAffine = self.R_prime().into();

        let mut buf = [0u8; Self::SIZE];
        buf[..32].copy_from_slice(&self.u.to_bytes()[..]);
        buf[32..64].copy_from_slice(&R_affine.to_bytes()[..]);
        buf[64..].copy_from_slice(&R_p_affine.to_bytes()[..]);
        buf
    }

    #[allow(non_snake_case)]
    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let u = JubJubScalar::from_slice(&bytes[..32])?;
        let R: JubJubExtended =
            JubJubAffine::from_slice(&bytes[32..64])?.into();
        let R_prime: JubJubExtended =
            JubJubAffine::from_slice(&bytes[64..])?.into();

        Ok(Self { u, R, R_prime })
    }
}

// Create a challenge hash for the double signature scheme.
#[allow(non_snake_case)]
pub(crate) fn challenge_hash(
    R: &JubJubExtended,
    R_prime: &JubJubExtended,
    pk: PublicKey,
    message: BlsScalar,
) -> JubJubScalar {
    let R_coordinates = R.to_hash_inputs();
    let R_p_coordinates = R_prime.to_hash_inputs();
    let pk_coordinates = pk.as_ref().to_hash_inputs();

    hash(&[
        R_coordinates[0],
        R_coordinates[1],
        R_p_coordinates[0],
        R_p_coordinates[1],
        pk_coordinates[0],
        pk_coordinates[1],
        message,
    ])
}
