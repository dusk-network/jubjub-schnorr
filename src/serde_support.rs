// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use core::fmt::Debug;

use dusk_bytes::Serializable;
use serde::de::Error as SerdeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    PublicKey, PublicKeyDouble, PublicKeyVarGen, SecretKey, SecretKeyVarGen,
    Signature, SignatureDouble, SignatureVarGen,
};

fn serialize_base58<T, S, const N: usize>(
    value: &T,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    T: Serializable<N>,
    S: Serializer,
{
    let encoded = bs58::encode(value.to_bytes()).into_string();
    serializer.serialize_str(&encoded)
}

fn deserialize_base58<'de, T, D, const N: usize>(
    deserializer: D,
) -> Result<T, D::Error>
where
    T: Serializable<N>,
    T::Error: Debug,
    D: Deserializer<'de>,
{
    let encoded = String::deserialize(deserializer)?;
    let decoded = bs58::decode(&encoded)
        .into_vec()
        .map_err(SerdeError::custom)?;
    let decoded_len = decoded.len();
    let byte_length = format!("{N}");
    let bytes: [u8; N] = decoded.try_into().map_err(|_| {
        SerdeError::invalid_length(decoded_len, &byte_length.as_str())
    })?;

    T::from_bytes(&bytes).map_err(|err| SerdeError::custom(format!("{err:?}")))
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
