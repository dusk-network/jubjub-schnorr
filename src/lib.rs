// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![doc = include_str!("../README.md")]
#![no_std]

mod error;
mod keys;
mod signatures;

#[cfg(feature = "zk")]
pub mod gadgets;

#[cfg(feature = "serde")]
mod serde_support;

pub use error::Error;
pub use keys::public::PublicKey;
pub use keys::secret::SecretKey;
pub use signatures::Signature;

pub use keys::public::double::PublicKeyDouble;
pub use signatures::double::SignatureDouble;

pub use keys::public::var_gen::PublicKeyVarGen;
pub use keys::secret::var_gen::SecretKeyVarGen;
pub use signatures::var_gen::SignatureVarGen;

#[allow(non_snake_case)]
pub mod multisig;
