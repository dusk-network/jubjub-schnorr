// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bls12_381::BlsScalar;
use jubjub_schnorr::{PublicKey, SecretKey, multisig};
use rand::{SeedableRng, rngs::StdRng};

fn main() {
    let mut rng = StdRng::seed_from_u64(7);
    let sk = SecretKey::random(&mut rng);
    let pk = PublicKey::from(&sk);
    let message = BlsScalar::from(11u64);
    let (nonce, r, s) = multisig::sign_round_1(&mut rng);

    let _ = multisig::sign_round_2(&sk, nonce, &[pk], &[r], &[s], &message);
    let _ = multisig::sign_round_2(&sk, nonce, &[pk], &[r], &[s], &message);
}
