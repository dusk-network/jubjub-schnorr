// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bls12_381::BlsScalar;
use dusk_jubjub::{JubJubScalar, GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};
use ff::Field;
use rand_core::{CryptoRng, RngCore};

use crate::{PublicKey, SecretKey, SignatureDouble};

impl SecretKey {
    /// Constructs a new `Signature` instance by signing a given message with
    /// a `SecretKey`.
    ///
    /// Utilizes a secure random number generator to create a unique random
    /// scalar, and subsequently computes public key points `(R, R')` and a
    /// scalar signature `u`.
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
    /// assert!(pk.verify(&signature, message).is_ok());
    /// ```
    ///
    /// [`PublicKeyDouble`]: [`crate::PublicKeyDouble`]
    #[allow(non_snake_case)]
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
        let c = crate::signatures::double::challenge_hash(
            &R,
            &R_prime,
            PublicKey::from(self),
            message,
        );

        // Compute scalar signature, u = r - c * sk,
        let u = r - (c * self.as_ref());

        SignatureDouble::new(u, R, R_prime)
    }
}
