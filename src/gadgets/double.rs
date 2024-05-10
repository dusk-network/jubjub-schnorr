// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::{GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};
use dusk_plonk::prelude::*;
use dusk_poseidon::sponge;

/// Verifies a [`SignatureDouble`] within a Plonk circuit without requiring
/// the secret key as a witness.
///
/// # Feature
///
/// Only available with the "double" and "zk" features enabled.
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
    let r_x = *r.x();
    let r_y = *r.y();

    let r_p_x = *r_p.x();
    let r_p_y = *r_p.y();

    let pk_x = *pk.x();
    let pk_y = *pk.y();

    let challenge = [r_x, r_y, r_p_x, r_p_y, pk_x, pk_y, msg];
    let challenge_hash = sponge::truncated::gadget(composer, &challenge);

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
