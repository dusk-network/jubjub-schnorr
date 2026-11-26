// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

extern crate alloc;

use alloc::format;
use core::fmt::{self, Debug};

use dusk_bytes::Serializable;
use serde::de::{Error as SerdeError, Unexpected, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

use crate::{
    PublicKey, PublicKeyDouble, PublicKeyVarGen, SecretKey, SecretKeyVarGen,
    Signature, SignatureDouble, SignatureVarGen,
};

const OVER_LONG: Unexpected = Unexpected::Other("over-long base58 string");

/// Maximum Base58 output size across supported types (`SignatureDouble` is 96
/// bytes, which encodes to at most 132 characters).
const MAX_ENCODED_LEN: usize = 136;

fn serialize_base58<T, S, const N: usize>(
    value: &T,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    T: Serializable<N>,
    S: Serializer,
{
    let mut bytes = value.to_bytes();
    let mut encoded = [0u8; MAX_ENCODED_LEN];
    let len = bs58::encode(&bytes)
        .onto(&mut encoded[..])
        .expect("stack buffer fits encoded bytes");
    let result = serializer.serialize_str(
        core::str::from_utf8(&encoded[..len])
            .expect("base58 output is valid UTF-8"),
    );
    bytes.zeroize();
    encoded.zeroize();
    result
}

/// Decodes a Base58 string of exactly `N` bytes into `T`.
///
/// Longer encodings are rejected before decoding, and decoding writes into a
/// fixed-size buffer that is wiped before returning.
fn deserialize_base58<'de, T, D, const N: usize>(
    deserializer: D,
) -> Result<T, D::Error>
where
    T: Serializable<N>,
    T::Error: Debug,
    D: Deserializer<'de>,
{
    struct Bs58<'a, const N: usize>(&'a mut [u8; N]);

    impl<const N: usize> Visitor<'_> for Bs58<'_, N> {
        type Value = ();

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "a base58 string encoding {N} bytes")
        }

        fn visit_str<E: SerdeError>(
            self,
            value: &str,
        ) -> Result<Self::Value, E> {
            self.visit_bytes(value.as_bytes())
        }

        fn visit_bytes<E: SerdeError>(
            self,
            value: &[u8],
        ) -> Result<Self::Value, E> {
            // `N` bytes encode to at most `ceil(N * log(256) / log(58))`
            // characters, and log(256) / log(58) < 1.366.
            if value.len() > N * 1366 / 1000 + 1 {
                return Err(E::invalid_value(OVER_LONG, &self));
            }
            match bs58::decode(value).onto(&mut self.0[..]) {
                Ok(len) if len == N => Ok(()),
                Ok(len) => Err(E::invalid_length(len, &self)),
                Err(bs58::decode::Error::BufferTooSmall) => {
                    Err(E::invalid_value(OVER_LONG, &self))
                }
                Err(err) => Err(E::custom(err)),
            }
        }
    }

    let mut bytes = [0u8; N];
    let value = deserializer
        .deserialize_str(Bs58(&mut bytes))
        .and_then(|()| {
            T::from_bytes(&bytes)
                .map_err(|err| D::Error::custom(format!("{err:?}")))
        });
    bytes.zeroize();
    value
}

impl Serialize for PublicKey {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serialize_base58::<_, _, 32>(self, serializer)
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        deserialize_base58::<Self, _, 32>(deserializer)
    }
}

impl Serialize for SecretKey {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serialize_base58::<_, _, 32>(self, serializer)
    }
}

impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        deserialize_base58::<Self, _, 32>(deserializer)
    }
}

impl Serialize for Signature {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serialize_base58::<_, _, 64>(self, serializer)
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        deserialize_base58::<Self, _, 64>(deserializer)
    }
}

impl Serialize for PublicKeyDouble {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serialize_base58::<_, _, 64>(self, serializer)
    }
}

impl<'de> Deserialize<'de> for PublicKeyDouble {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        deserialize_base58::<Self, _, 64>(deserializer)
    }
}

impl Serialize for SignatureDouble {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serialize_base58::<_, _, 96>(self, serializer)
    }
}

impl<'de> Deserialize<'de> for SignatureDouble {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        deserialize_base58::<Self, _, 96>(deserializer)
    }
}

impl Serialize for PublicKeyVarGen {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serialize_base58::<_, _, 64>(self, serializer)
    }
}

impl<'de> Deserialize<'de> for PublicKeyVarGen {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        deserialize_base58::<Self, _, 64>(deserializer)
    }
}

impl Serialize for SecretKeyVarGen {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serialize_base58::<_, _, 64>(self, serializer)
    }
}

impl<'de> Deserialize<'de> for SecretKeyVarGen {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        deserialize_base58::<Self, _, 64>(deserializer)
    }
}

impl Serialize for SignatureVarGen {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serialize_base58::<_, _, 64>(self, serializer)
    }
}

impl<'de> Deserialize<'de> for SignatureVarGen {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        deserialize_base58::<Self, _, 64>(deserializer)
    }
}
