// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use jubjub_schnorr::SecretKey;

// Apply the prohibited bound directly, independent of key construction.
fn requires_partial_ord<T: PartialOrd>() {}

fn main() {
    requires_partial_ord::<SecretKey>();
}
