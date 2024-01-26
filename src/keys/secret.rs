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

use crate::{PublicKey, Signature};

#[cfg(feature = "var_generator")]
use crate::PublicKeyVarGen;
#[cfg(feature = "var_generator")]
use crate::SignatureVarGen;
#[cfg(feature = "var_generator")]
use dusk_jubjub::{JubJubAffine, JubJubExtended};

#[cfg(feature = "double")]
use crate::SignatureDouble;
#[cfg(feature = "double")]
use dusk_jubjub::GENERATOR_NUMS_EXTENDED;

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

#[cfg(feature = "multisig")]
extern crate alloc;
#[cfg(feature = "multisig")]
use alloc::vec;
#[cfg(feature = "multisig")]
use alloc::vec::Vec;
#[cfg(feature = "multisig")]
use dusk_jubjub::JubJubExtended;

/// Structure representing a [`SecretKey`], represented as a private scalar
/// in the JubJub scalar field.
///
/// ## Examples
///
/// Generate a random `SecretKey`:
/// ```
/// use jubjub_schnorr::SecretKey;
/// use rand::rngs::StdRng;
/// use rand::SeedableRng;
///
/// let mut rng = StdRng::seed_from_u64(12345);
/// let sk = SecretKey::random(&mut rng);
/// ```
#[allow(non_snake_case)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
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
    /// assert!(pk.verify(&signature, message));
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

    /// Constructs a new `Signature` instance by signing a given message with
    /// a `SecretKey`.
    ///
    /// Utilizes a secure random number generator to create a unique random
    /// scalar, and subsequently computes public key points `(R, R')` and a
    /// scalar signature `u`.
    ///
    /// # Feature
    ///
    /// Only available with the "double" feature enabled.
    ///
    /// # Parameters
    ///
    /// * `rng`: Cryptographically secure random number generator.
    /// * `message`: Message as a `BlsScalar`.
    ///
    /// # Returns
    ///
    /// A new [`SignatureDouble`] instance.
    ///
    /// ## Example
    ///
    /// Double sign a message with a [`SecretKey`] and verify with the
    /// respective [`PublicKeyDouble`]:
    /// ```
    /// use jubjub_schnorr::{SecretKey, PublicKeyDouble};
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
    /// let pk = PublicKeyDouble::from(&sk);
    ///
    /// let signature = sk.sign_double(&mut rng, message);
    ///
    /// assert!(pk.verify(&signature, message));
    /// ```
    ///
    /// [`PublicKeyDouble`]: [`crate::PublicKeyDouble`]
    #[allow(non_snake_case)]
    #[cfg(feature = "double")]
    pub fn sign_double<R>(
        &self,
        rng: &mut R,
        message: BlsScalar,
    ) -> SignatureDouble
    where
        R: RngCore + CryptoRng,
    {
        // Create random scalar value for scheme, r
        let r = JubJubScalar::random(rng);

        // Derive two points from r, to sign with the message
        // R = r * G
        // R_prime = r * G'
        let R = GENERATOR_EXTENDED * r;
        let R_prime = GENERATOR_NUMS_EXTENDED * r;
        // Compute challenge value, c = H(R||R_prime||pk||m);
        let c = crate::signatures::challenge_hash_double(
            &R,
            &R_prime,
            PublicKey::from(self),
            message,
        );

        // Compute scalar signature, u = r - c * sk,
        let u = r - (c * self.as_ref());

        SignatureDouble::new(u, R, R_prime)
    }

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
    #[cfg(feature = "var_generator")]
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
#[derive(Clone, Copy, PartialEq, Debug, Default)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
#[cfg(feature = "var_generator")]
pub struct SecretKeyVarGen {
    sk: JubJubScalar,
    generator: JubJubExtended,
}

#[cfg(feature = "var_generator")]
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

#[cfg(feature = "var_generator")]
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
    /// assert!(pk.verify(&signature, message));
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
        let c = crate::signatures::challenge_hash_var_gen(
            &R,
            PublicKeyVarGen::from(self),
            msg,
        );

        // Compute scalar signature, U = r - c * sk,
        let u = r - (c * self.secret_key());

        SignatureVarGen::new(u, R)
    }
}

/// Implementation of the `SpeedyMuSig` Schnorr-based
/// multisignature scheme. It allows several signers to
/// create a signature that proves a message to be signed by
/// them all, given their public keys. The signature can be
/// verified using the same function used for the standard
/// Schnorr signature, using the sum of all the signers' public keys.
///
/// reference: https://eprint.iacr.org/2021/1375.pdf - pag. 19
///
/// # Feature
///
/// Only available with the "multisig" feature enabled.
#[cfg(feature = "multisig")]
#[allow(non_snake_case)]
pub trait SecretKeyMultisig {
    /// Performs the first round to sign a message using the
    /// multisignature scheme
    /// ## Returns
    ///
    /// Returns two [`JubJubScalar`] being the scalars (r, s), and
    /// two [`JubJubExtended`] being the points (R, S)
    fn multisig_sign_round_1<R>(
        rng: &mut R,
    ) -> (JubJubScalar, JubJubScalar, JubJubExtended, JubJubExtended)
    where
        R: RngCore + CryptoRng;

    /// Performs the second round to sign a message using the
    /// multisignature scheme
    /// ## Returns
    ///
    /// Returns a [`JubJubScalar`] being the signature share 'z'
    fn multisig_sign_round_2(
        &self,
        r: JubJubScalar,
        s: JubJubScalar,
        pk_vec: Vec<PublicKey>,
        R_vec: Vec<JubJubExtended>,
        S_vec: Vec<JubJubExtended>,
        msg: BlsScalar,
    ) -> Result<JubJubScalar, MultisigError>;

    /// Combines all the multisignature shares `z_vec` and returns
    /// a new signature [`JubJubScalar`]
    fn multisig_combine(
        z_vec: Vec<JubJubScalar>,
        pk_vec: Vec<PublicKey>,
        R_vec: Vec<JubJubExtended>,
        S_vec: Vec<JubJubExtended>,
        msg: BlsScalar,
    ) -> Signature;
}

#[cfg(feature = "multisig")]
#[allow(non_snake_case)]
impl SecretKeyMultisig for SecretKey {
    fn multisig_sign_round_1<R>(
        mut rng: &mut R,
    ) -> (JubJubScalar, JubJubScalar, JubJubExtended, JubJubExtended)
    where
        R: RngCore + CryptoRng,
    {
        // Sample two random values (r, s)
        let r = JubJubScalar::random(&mut rng);
        let s = JubJubScalar::random(&mut rng);

        // Compute R = r * G, S = s * G
        let R = GENERATOR_EXTENDED * r;
        let S = GENERATOR_EXTENDED * s;

        (r, s, R, S)
    }

    fn multisig_sign_round_2(
        &self,
        r: JubJubScalar,
        s: JubJubScalar,
        pk_vec: Vec<PublicKey>,
        R_vec: Vec<JubJubExtended>,
        S_vec: Vec<JubJubExtended>,
        msg: BlsScalar,
    ) -> Result<JubJubScalar, MultisigError> {
        // Check if (R_i == R_j) || (S_i == S_j) for any i != j
        // and return error if so
        for i in 0..R_vec.len() {
            for j in (i + 1)..R_vec.len() {
                if R_vec[i] == R_vec[j] || R_vec[i] == R_vec[j] {
                    return Err(MultisigError::DuplicatedNonce);
                }
            }
        }

        let (a, c, _RSa) = multisig_common(pk_vec, R_vec, S_vec, msg);

        // Compute the share z = r + s * a - c * sk,
        Ok(r + (s * a) - (c * self.as_ref()))
    }

    fn multisig_combine(
        z_vec: Vec<JubJubScalar>,
        pk_vec: Vec<PublicKey>,
        R_vec: Vec<JubJubExtended>,
        S_vec: Vec<JubJubExtended>,
        msg: BlsScalar,
    ) -> Signature {
        let (_a, _c, RSa) = multisig_common(pk_vec, R_vec, S_vec, msg);

        // Sum all the shares u = z_1 + z_2 + ... + z_n for `n` signers
        let u = z_vec.iter().sum();

        Signature::new(u, RSa)
    }
}

/// Performs some common operations required in different parts
/// of the multisignature scheme
#[cfg(feature = "multisig")]
#[allow(non_snake_case)]
fn multisig_common(
    pk_vec: Vec<PublicKey>,
    R_vec: Vec<JubJubExtended>,
    S_vec: Vec<JubJubExtended>,
    msg: BlsScalar,
) -> (JubJubScalar, JubJubScalar, JubJubExtended) {
    use dusk_poseidon::sponge::truncated::hash;

    // Sum all the public keys pk = pk_1 + pk_2 + ... + pk_n for `n` signers
    let mut pk = JubJubExtended::default();
    for pk_it in pk_vec {
        pk += pk_it.as_ref();
    }

    // Compute the hash
    // a = H(pk || m || R_1 || S_1 || R_2 || S_2 || ... || R_n || S_n)
    // for `n` signers
    let mut preimage = vec![];
    let pk_coordinates = pk.to_hash_inputs();

    preimage.push(pk_coordinates[0]);
    preimage.push(pk_coordinates[1]);
    preimage.push(msg);

    for it in 0..R_vec.len() {
        let R_coordinates = R_vec[it].to_hash_inputs();
        let S_coordinates = S_vec[it].to_hash_inputs();

        preimage.push(R_coordinates[0]);
        preimage.push(R_coordinates[1]);
        preimage.push(S_coordinates[0]);
        preimage.push(S_coordinates[1]);
    }

    let a = hash(&preimage);

    // Compute RSa = R_1 + (S_1 * a) + R_2 + (S_2 * a) + ... + R_n + (S_n *
    // a) for `n` signers
    let mut RSa = JubJubExtended::default();
    for it in 0..R_vec.len() {
        RSa = RSa + R_vec[it] + (S_vec[it] * a);
    }

    // Compute challenge c = H(RSa || pk || m);
    let RSa_coordinates = RSa.to_hash_inputs();
    let c = hash(&[
        RSa_coordinates[0],
        RSa_coordinates[1],
        pk_coordinates[0],
        pk_coordinates[1],
        msg,
    ]);

    (a, c, RSa)
}

/// Error variants for the multisignature scheme
#[cfg(feature = "multisig")]
#[derive(Debug)]
pub enum MultisigError {
    DuplicatedNonce,
}
