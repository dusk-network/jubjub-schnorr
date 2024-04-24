// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bytes::Error as DuskBytesError;

use core::fmt;

/// Standard error for the interface
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Error {
    /// Dusk-bytes serialization error
    BytesError(DuskBytesError),
    /// Cryptographic invalidity
    InvalidSignature,
    /// Invalid Point
    InvalidPoint,
    /// Error variants for the multisignature scheme
    DuplicatedNonce,
}

impl From<DuskBytesError> for Error {
    fn from(bytes_err: DuskBytesError) -> Self {
        Self::BytesError(bytes_err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BytesError(err) => write!(f, "{:?}", err),
            Self::InvalidSignature => {
                write!(f, "Invalid Signature")
            }
            Self::InvalidPoint => {
                write!(f, "Invalid Point")
            }
            Self::DuplicatedNonce => {
                write!(f, "Duplicated Nonce in multi-sig")
            }
        }
    }
}
