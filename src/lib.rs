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

pub use error::Error;
pub use keys::public::PublicKey;
pub use keys::secret::SecretKey;
pub use signatures::Signature;

#[cfg(feature = "double")]
pub use keys::public::double::PublicKeyDouble;
#[cfg(feature = "double")]
pub use signatures::double::SignatureDouble;

#[cfg(feature = "var_generator")]
pub use keys::public::var_gen::PublicKeyVarGen;
#[cfg(feature = "var_generator")]
pub use keys::secret::var_gen::SecretKeyVarGen;
#[cfg(feature = "var_generator")]
pub use signatures::var_gen::SignatureVarGen;

#[cfg(feature = "multisig")]
#[allow(non_snake_case)]
pub mod multisig;
