// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bls12_381::BlsScalar;
use dusk_bytes::{Error, Serializable};
use dusk_jubjub::{
    JubJubAffine, JubJubExtended, JubJubScalar, GENERATOR_EXTENDED,
};
use ff::Field;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::{PublicKeyVarGen, SecretKey, SignatureVarGen};

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

impl SecretKey {
    /// Create a [`SecretKeyVarGen`], a `SecretKey` with a generator
    /// other than [`GENERATOR_EXTENDED`].
    ///
    /// # Feature
    ///
    /// Only available with the "var_generator" feature enabled.
    ///
    /// # Parameters
    ///
    /// * `generator`: A `JubJubExtended` point that will replace
    /// `GENERATOR_EXTENDED` in the signature algorithm
    ///
    /// # Returns
    ///
    /// A new [`SecretKeyVarGen`] instance.
    pub fn with_variable_generator(
        self,
        generator: JubJubExtended,
    ) -> SecretKeyVarGen {
        SecretKeyVarGen::new(self.0, generator)
    }
}

/// Structure representing a [`SecretKeyVarGen`], represented as a private
/// scalar in the JubJub scalar field, with a variable generator,
/// represented as a point on the JubJub curve.
///
/// # Feature
///
/// Only available with the "var_generator" feature enabled.
///
/// ## Examples
///
/// Generate a random `SecretKey`:
/// Generating a random `SecretKeyVarGen` with a variable generator
/// ```
/// use jubjub_schnorr::{SecretKey, SecretKeyVarGen};
/// use rand::rngs::StdRng;
/// use rand::SeedableRng;
/// use dusk_jubjub::{JubJubScalar, GENERATOR_EXTENDED};
/// use ff::Field;
///
/// let mut rng = StdRng::seed_from_u64(12345);
///
/// // generate a variable generator secret key from an existing standard
/// // SecretKey:
/// let sk = SecretKey::random(&mut rng);
/// let generator = GENERATOR_EXTENDED * JubJubScalar::random(&mut rng);
/// let sk_var_gen: SecretKeyVarGen = sk.with_variable_generator(generator);
///
/// // generate a variable generator secret key from the raw values:
/// let sk_var_gen = SecretKeyVarGen::new(JubJubScalar::from(42u64), generator);
///
/// // generate a variable generator secret key at random:
/// let sk_var_gen = SecretKeyVarGen::random(&mut rng);
/// ```
#[allow(non_snake_case)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Zeroize)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct SecretKeyVarGen {
    sk: JubJubScalar,
    generator: JubJubExtended,
}

impl Serializable<64> for SecretKeyVarGen {
    type Error = Error;

    fn to_bytes(&self) -> [u8; 64] {
        let mut buf = [0u8; 64];
        let sk_bytes = self.sk.to_bytes();
        let gen: JubJubAffine = self.generator.into();
        let gen_bytes = gen.to_bytes();
        buf[..32].copy_from_slice(&sk_bytes);
        buf[32..].copy_from_slice(&gen_bytes);
        buf
    }

    fn from_bytes(bytes: &[u8; 64]) -> Result<Self, Error> {
        let mut sk_bytes = [0u8; 32];
        let mut gen_bytes = [0u8; 32];
        sk_bytes.copy_from_slice(&bytes[..32]);
        gen_bytes.copy_from_slice(&bytes[32..]);
        let sk = <JubJubScalar as Serializable<32>>::from_bytes(&sk_bytes)?;
        let generator: JubJubExtended =
            <JubJubAffine as Serializable<32>>::from_bytes(&gen_bytes)?.into();
        Ok(Self { sk, generator })
    }
}

impl SecretKeyVarGen {
    /// Create a new [`SecretKeyVarGen`] with a given secret key and a
    /// generator point.
    ///
    /// ## Parameters
    ///
    /// - `sk`: The secret key as `JubJubScalar`.
    /// - `generator`: The generator point as `JubJubExtended`.
    ///
    /// ## Returns
    ///
    /// - A new [`SecretKeyVarGen`] instance for signing with a variable
    ///   generator.
    pub fn new(sk: JubJubScalar, generator: JubJubExtended) -> Self {
        Self { sk, generator }
    }

    /// Create a random [`SecretKeyVarGen`] from a scalar.
    /// of the Field JubJubScalar.
    ///
    /// ## Parameters
    ///
    /// - `rng`: Reference to a random number generator.
    ///
    /// ## Returns
    ///
    /// - A new [`SecretKeyVarGen`] instance for signing with a variable
    ///   generator.
    pub fn random<T>(rand: &mut T) -> SecretKeyVarGen
    where
        T: RngCore + CryptoRng,
    {
        let sk = JubJubScalar::random(&mut *rand);
        let scalar = JubJubScalar::random(&mut *rand);
        let generator = GENERATOR_EXTENDED * scalar;

        SecretKeyVarGen { sk, generator }
    }

    /// Returns a reference to the [`JubJubScalar`] secret key.
    pub(crate) fn secret_key(&self) -> &JubJubScalar {
        &self.sk
    }

    /// Returns a reference to the [`JubJubExtended`] generator.
    pub(crate) fn generator(&self) -> &JubJubExtended {
        &self.generator
    }

    /// Signs a chosen message with a given secret key using the dusk
    /// variant of the Schnorr signature scheme.
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
    /// Returns a new [`SignatureVarGen`] containing the `u` scalar and `R`
    /// point.
    ///
    /// ## Example
    ///
    /// Sign a message with a [`SecretKeyVarGen`] and verify with the respective
    /// [`PublicKeyVarGen`]:
    /// ```
    /// use jubjub_schnorr::{SecretKeyVarGen, PublicKeyVarGen};
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
    /// let sk = SecretKeyVarGen::random(&mut rng);
    /// let pk = PublicKeyVarGen::from(&sk);
    ///
    /// let signature = sk.sign(&mut rng, message);
    ///
    /// assert!(pk.verify(&signature, message).is_ok());
    /// ```
    ///
    /// [`PublicKeyVarGen`]: [`crate::PublicKeyVarGen`]
    #[allow(non_snake_case)]
    pub fn sign<R>(&self, rng: &mut R, msg: BlsScalar) -> SignatureVarGen
    where
        R: RngCore + CryptoRng,
    {
        // Create random scalar value for scheme, r
        let r = JubJubScalar::random(rng);

        // Derive a points from r, to sign with the message
        // R = r * G
        let R = self.generator() * r;

        // Compute challenge value, c = H(R||pk||m);
        let c = crate::signatures::var_gen::challenge_hash(
            &R,
            PublicKeyVarGen::from(self),
            msg,
        );

        // Compute scalar signature, U = r - c * sk,
        let u = r - (c * self.secret_key());

        SignatureVarGen::new(u, R)
    }
}
