// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! # Schnorr Signature Gadgets
//!
//! This module provides Plonk gadgets for verification of Schnorr signatures.

use dusk_jubjub::{
    EDWARDS_D, GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED, JubJubAffine,
    JubJubExtended, JubJubScalar,
};
use dusk_plonk::prelude::*;
use dusk_poseidon::{Domain, HashGadget};

/// Constrains a witnessed point to be a non-identity member of the prime-order
/// JubJub subgroup.
///
/// A point is in the prime-order subgroup exactly when it is in the image of
/// multiplication by JubJub's cofactor, eight. We witness an eighth root,
/// constrain it to the curve, and constrain three doublings to recover the
/// supplied point. This avoids an expensive multiplication by the subgroup
/// order while retaining the native verifier's subgroup requirement.
fn constrain_valid_point(composer: &mut Composer, point: WitnessPoint) {
    let affine = JubJubAffine::from_raw_unchecked(
        composer[*point.x()],
        composer[*point.y()],
    );
    let inverse_cofactor = JubJubScalar::from(8u64)
        .invert()
        .expect("eight is invertible in the JubJub scalar field");
    let root: JubJubAffine =
        (JubJubExtended::from(affine) * inverse_cofactor).into();
    let root = composer.append_point(root);

    // Enforce -x^2 + y^2 = 1 + d*x^2*y^2 for the subgroup root.
    let x_squared =
        composer.gate_mul(Constraint::new().mult(1).a(*root.x()).b(*root.x()));
    let y_squared =
        composer.gate_mul(Constraint::new().mult(1).a(*root.y()).b(*root.y()));
    let x_squared_y_squared =
        composer.gate_mul(Constraint::new().mult(1).a(x_squared).b(y_squared));
    composer.append_gate(
        Constraint::new()
            .left(-BlsScalar::one())
            .right(BlsScalar::one())
            .output(-EDWARDS_D)
            .constant(-BlsScalar::one())
            .a(x_squared)
            .b(y_squared)
            .c(x_squared_y_squared),
    );

    let twice_root = composer.component_add_point(root, root);
    let four_times_root = composer.component_add_point(twice_root, twice_root);
    let eight_times_root =
        composer.component_add_point(four_times_root, four_times_root);
    composer.assert_equal_point(point, eight_times_root);

    // The only prime-order JubJub point with x = 0 is the identity. Proving
    // that x has an inverse therefore excludes it without branching on the
    // witness value.
    let x_inverse = composer[*point.x()].invert().unwrap_or(BlsScalar::zero());
    let x_inverse = composer.append_witness(x_inverse);
    composer.append_gate(
        Constraint::new()
            .mult(BlsScalar::one())
            .constant(-BlsScalar::one())
            .a(*point.x())
            .b(x_inverse),
    );
}

/// Verifies a single-key Schnorr signature [`Signature`]within a Plonk circuit
/// without requiring the secret key as a witness.
///
/// The function performs Schnorr verification by calculating the challenge and
/// confirming the signature equation.
///
/// # Feature
///
/// Only available with the "zk" feature enabled.
///
/// ### Parameters
///
/// - `composer`: A mutable reference to the Plonk [`Composer`]`.
/// - `u`: Witness for the random nonce used during signature generation.
/// - `r`: Witness Point representing the nonce point `r = u*G`.
/// - `pk`: Witness Point representing the public key `pk = sk*G`.
/// - `msg`: Witness for the message.
///
/// ### Returns
///
/// - `Result<(), Error>`: Returns an empty `Result` on successful gadget
///   creation or an `Error` if the witness `u` is not a valid [`JubJubScalar`].
///
/// ### Errors
///
/// This function will return an `Error` if the witness `u` is not a valid
/// [`JubJubScalar`].
///
/// [`Signature`]: [`crate::Signature`]
pub fn verify_signature(
    composer: &mut Composer,
    u: Witness,
    r: WitnessPoint,
    pk: WitnessPoint,
    msg: Witness,
) -> Result<(), Error> {
    constrain_valid_point(composer, r);
    constrain_valid_point(composer, pk);

    let r_x = *r.x();
    let r_y = *r.y();

    let pk_x = *pk.x();
    let pk_y = *pk.y();

    let challenge = [r_x, r_y, pk_x, pk_y, msg];
    let challenge_hash =
        HashGadget::digest_truncated(composer, Domain::Other, &challenge)[0];

    let s_a = composer.component_mul_generator(u, GENERATOR_EXTENDED)?;
    let s_b = composer.component_mul_point(challenge_hash, pk);
    let point = composer.component_add_point(s_a, s_b);

    composer.assert_equal_point(r, point);

    Ok(())
}

/// Verifies a [`SignatureDouble`] within a Plonk circuit without requiring
/// the secret key as a witness.
///
/// # Feature
///
/// Only available with the "zk" feature enabled.
///
/// ### Parameters
///
/// - `composer`: A mutable reference to the Plonk [`Composer`].
/// - `u`: Witness for the random nonce used during signature generation.
/// - `r`: Witness Point representing the nonce points `R = u*G`
/// - `r_p`: Witness Point representing the nonce points `R' = u*G'`.
/// - `pk`: Witness Point public key `PK = sk*G`
/// - `pk_p`: Witness Point public key `PK' = sk*G'`
/// - `msg`: Witness for the message.
///
/// ### Returns
///
/// - `Result<(), Error>`: Returns an empty `Result` on successful gadget
///   creation or an `Error` if the witness `u` is not a valid [`JubJubScalar`].
///
/// ### Errors
///
/// This function will return an `Error` if the witness `u` is not a valid
/// [`JubJubScalar`].
///
/// [`SignatureDouble`]: [`crate::SignatureDouble`]
pub fn verify_signature_double(
    composer: &mut Composer,
    u: Witness,
    r: WitnessPoint,
    r_p: WitnessPoint,
    pk: WitnessPoint,
    pk_p: WitnessPoint,
    msg: Witness,
) -> Result<(), Error> {
    constrain_valid_point(composer, r);
    constrain_valid_point(composer, r_p);
    constrain_valid_point(composer, pk);
    constrain_valid_point(composer, pk_p);

    let r_x = *r.x();
    let r_y = *r.y();

    let r_p_x = *r_p.x();
    let r_p_y = *r_p.y();

    let pk_x = *pk.x();
    let pk_y = *pk.y();

    let pk_p_x = *pk_p.x();
    let pk_p_y = *pk_p.y();

    let domain = composer.append_constant(BlsScalar::from(
        crate::signatures::double::DOUBLE_CHALLENGE_DOMAIN,
    ));
    let challenge = [
        domain, r_x, r_y, r_p_x, r_p_y, pk_x, pk_y, pk_p_x, pk_p_y, msg,
    ];
    let challenge_hash =
        HashGadget::digest_truncated(composer, Domain::Other, &challenge)[0];

    let s_a = composer.component_mul_generator(u, GENERATOR_EXTENDED)?;
    let s_b = composer.component_mul_point(challenge_hash, pk);
    let point = composer.component_add_point(s_a, s_b);

    let s_p_a = composer.component_mul_generator(u, GENERATOR_NUMS_EXTENDED)?;
    let s_p_b = composer.component_mul_point(challenge_hash, pk_p);
    let point_p = composer.component_add_point(s_p_a, s_p_b);

    composer.assert_equal_point(r, point);
    composer.assert_equal_point(r_p, point_p);

    Ok(())
}

/// Verifies a Schnorr signature with variable generator [`SignatureVarGen`]
/// within a Plonk circuit without requiring the secret key as a witness.
///
/// The function performs Schnorr verification by calculating the challenge and
/// confirming the signature equation.
///
/// # Feature
///
/// Only available with the "zk" feature enabled.
///
/// ### Parameters
///
/// - `composer`: A mutable reference to the Plonk [`Composer`]`.
/// - `u`: Witness for the random nonce used during signature generation.
/// - `r`: Witness Point representing the nonce point `r = u*G`.
/// - `pk`: Witness Point representing the public key `pk = sk*G`.
/// - `generator`: Witness Point representing the variable generator `G`
/// - `msg`: Witness for the message.
///
/// ### Returns
///
/// - `Result<(), Error>`: Returns an empty `Result` on successful gadget
///   creation or an `Error` if the witness `u` is not a valid [`JubJubScalar`].
///
/// ### Errors
///
/// This function will return an `Error` if the witness `u` is not a valid
/// [`JubJubScalar`].
///
/// [`SignatureVarGen`]: [`crate::SignatureVarGen`]
pub fn verify_signature_var_gen(
    composer: &mut Composer,
    u: Witness,
    r: WitnessPoint,
    pk: WitnessPoint,
    generator: WitnessPoint,
    msg: Witness,
) -> Result<(), Error> {
    constrain_valid_point(composer, r);
    constrain_valid_point(composer, pk);
    constrain_valid_point(composer, generator);

    let r_x = *r.x();
    let r_y = *r.y();

    let pk_x = *pk.x();
    let pk_y = *pk.y();

    let gen_x = *generator.x();
    let gen_y = *generator.y();

    let challenge = [r_x, r_y, pk_x, pk_y, gen_x, gen_y, msg];
    let challenge_hash =
        HashGadget::digest_truncated(composer, Domain::Other, &challenge)[0];

    let s_a = composer.component_mul_point(u, generator);
    let s_b = composer.component_mul_point(challenge_hash, pk);
    let point = composer.component_add_point(s_a, s_b);

    composer.assert_equal_point(r, point);

    Ok(())
}
