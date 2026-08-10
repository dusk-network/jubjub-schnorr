// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg(feature = "alloc")]

#[test]
fn multisig_nonce_cannot_be_reused() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/multisig_nonce_reuse.rs");
}

#[test]
fn multisig_nonce_cannot_be_cloned() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/multisig_nonce_not_clone.rs");
}
