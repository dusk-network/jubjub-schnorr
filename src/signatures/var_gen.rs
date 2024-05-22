// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bls12_381::BlsScalar;
use dusk_bytes::{DeserializableSlice, Error as BytesError, Serializable};
use dusk_jubjub::{JubJubAffine, JubJubExtended, JubJubScalar};
use dusk_poseidon::{Domain, Hash};

use crate::PublicKeyVarGen;

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

/// An Schnorr SignatureVarGen, produced by signing a message with a
/// [`SecretKeyVarGen`].
///
/// The `SignatureVarGen` struct encapsulates variables of the Schnorr scheme.
///
/// ## Fields
///
/// - `u`: A [`JubJubScalar`] scalar representing the Schnorr signature.
/// - `R`: A [`JubJubExtended`] point produced as part of the Schnorr signature.
///
/// ## Example
///
/// ```
/// use dusk_bls12_381::BlsScalar;
/// use jubjub_schnorr::{PublicKeyVarGen, SecretKeyVarGen, SignatureVarGen};
/// use rand::rngs::StdRng;
/// use rand::SeedableRng;
/// use ff::Field;
///
/// let mut rng = StdRng::seed_from_u64(1234u64);
///
/// let sk = SecretKeyVarGen::random(&mut rng);
/// let message = BlsScalar::random(&mut rng);
/// let pk = PublicKeyVarGen::from(&sk);
///
/// // Sign the message
/// let signature = sk.sign(&mut rng, message);
///
/// // Verify the signature
/// assert!(pk.verify(&signature, message).is_ok());
/// ```
///
/// [`SecretKeyVarGen`]: [`crate::SecretKeyVarGen`]
#[allow(non_snake_case)]
#[derive(Default, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct SignatureVarGen {
    u: JubJubScalar,
    R: JubJubExtended,
}

impl SignatureVarGen {
    /// Exposes the `u` scalar of the Schnorr SignatureVarGen.
    pub fn u(&self) -> &JubJubScalar {
        &self.u
    }

    /// Exposes the `R` point of the Schnorr SignatureVarGen.
    #[allow(non_snake_case)]
    pub fn R(&self) -> &JubJubExtended {
        &self.R
    }

    /// Creates a new single key [`SignatureVarGen`] with the given parameters
    #[allow(non_snake_case)]
    pub(crate) fn new(u: JubJubScalar, R: JubJubExtended) -> Self {
        Self { u, R }
    }

    /// Returns true if the inner point is valid according to certain criteria.
    ///
    /// A [`SignatureVarGen`] is considered valid if its inner point `R` meets
    /// the following conditions:
    /// 1. It is free of an $h$-torsion component and exists within the
    ///    $q$-order subgroup $\mathbb{G}_2$.
    /// 2. It is on the curve.
    /// 3. It is not the identity.
    pub fn is_valid(&self) -> bool {
        let is_identity: bool = self.R.is_identity().into();
        self.R.is_torsion_free().into()
            && self.R.is_on_curve().into()
            && !is_identity
    }
}

impl Serializable<64> for SignatureVarGen {
    type Error = BytesError;

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[..32].copy_from_slice(&self.u.to_bytes()[..]);
        buf[32..].copy_from_slice(&JubJubAffine::from(self.R).to_bytes()[..]);
        buf
    }

    #[allow(non_snake_case)]
    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let u = JubJubScalar::from_slice(&bytes[..32])?;
        let R = JubJubExtended::from(JubJubAffine::from_slice(&bytes[32..])?);

        Ok(Self { u, R })
    }
}

// Create a challenge hash for the signature scheme with a variable generator.
#[allow(non_snake_case)]
pub(crate) fn challenge_hash(
    R: &JubJubExtended,
    pk: PublicKeyVarGen,
    message: BlsScalar,
) -> JubJubScalar {
    let R_coordinates = R.to_hash_inputs();
    let pk_coordinates = pk.public_key().to_hash_inputs();

    Hash::digest_truncated(
        Domain::Other,
        &[
            R_coordinates[0],
            R_coordinates[1],
            pk_coordinates[0],
            pk_coordinates[1],
            message,
        ],
    )[0]
}
