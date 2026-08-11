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

#[test]
fn secret_key_cannot_be_ordered() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/secret_key_not_partial_ord.rs");
}

#[test]
fn secret_key_cannot_be_copied() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/secret_key_not_copy.rs");
}

#[test]
fn variable_generator_secret_key_cannot_be_copied() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/secret_key_var_gen_not_copy.rs");
}
