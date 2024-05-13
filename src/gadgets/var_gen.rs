// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_plonk::prelude::*;
use dusk_poseidon::sponge;

/// Verifies a Schnorr signature with variable generator [`SignatureVarGen`]
/// within a Plonk circuit without requiring the secret key as a witness.
///
/// The function performs Schnorr verification by calculating the challenge and
/// confirming the signature equation.
///
/// # Feature
///
/// Only available with the "var_generator" and "zk" features enabled.
///
/// ### Parameters
///
/// - `composer`: A mutable reference to the Plonk [`Composer`]`.
/// - `u`: Witness for the random nonce used during signature generation.
/// - `r`: Witness Point representing the nonce point `r = u*G`.
/// - `pk`: Witness Point representing the public key `pk = sk*G`.
/// - `gen`: Witness Point representing the variable generator `G`
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
    gen: WitnessPoint,
    msg: Witness,
) -> Result<(), Error> {
    let r_x = *r.x();
    let r_y = *r.y();

    let pk_x = *pk.x();
    let pk_y = *pk.y();

    let challenge = [r_x, r_y, pk_x, pk_y, msg];
    let challenge_hash = sponge::truncated::gadget(composer, &challenge);

    // TODO: check whether we need to append the generator as a constant
    let s_a = composer.component_mul_point(u, gen);
    let s_b = composer.component_mul_point(challenge_hash, pk);
    let point = composer.component_add_point(s_a, s_b);

    composer.assert_equal_point(r, point);

    Ok(())
}
