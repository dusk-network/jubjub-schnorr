// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

extern crate alloc;

use alloc::format;
use alloc::string::String;

use dusk_bytes::Serializable;
use serde::de::Error as SerdeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    PublicKey, PublicKeyDouble, PublicKeyVarGen, SecretKey, SecretKeyVarGen,
    Signature, SignatureDouble, SignatureVarGen,
};

impl Serialize for PublicKey {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let s = bs58::encode(self.to_bytes()).into_string();
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let decoded =
            bs58::decode(&s).into_vec().map_err(SerdeError::custom)?;
        let decoded_len = decoded.len();
        let byte_length_str = format!("{}", Self::SIZE);
        let bytes: [u8; Self::SIZE] = decoded.try_into().map_err(|_| {
            SerdeError::invalid_length(decoded_len, &byte_length_str.as_str())
        })?;
        PublicKey::from_bytes(&bytes)
            .map_err(|err| SerdeError::custom(format!("{err:?}")))
    }
}

impl Serialize for SecretKey {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let s = bs58::encode(self.to_bytes()).into_string();
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let decoded =
            bs58::decode(&s).into_vec().map_err(SerdeError::custom)?;
        let decoded_len = decoded.len();
        let byte_length_str = format!("{}", Self::SIZE);
        let bytes: [u8; Self::SIZE] = decoded.try_into().map_err(|_| {
            SerdeError::invalid_length(decoded_len, &byte_length_str.as_str())
        })?;
        SecretKey::from_bytes(&bytes)
            .map_err(|err| SerdeError::custom(format!("{err:?}")))
    }
}

impl Serialize for Signature {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let s = bs58::encode(self.to_bytes()).into_string();
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let decoded =
            bs58::decode(&s).into_vec().map_err(SerdeError::custom)?;
        let decoded_len = decoded.len();
        let byte_length_str = format!("{}", Self::SIZE);
        let bytes: [u8; Self::SIZE] = decoded.try_into().map_err(|_| {
            SerdeError::invalid_length(decoded_len, &byte_length_str.as_str())
        })?;
        Signature::from_bytes(&bytes)
            .map_err(|err| SerdeError::custom(format!("{err:?}")))
    }
}

impl Serialize for PublicKeyDouble {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let s = bs58::encode(self.to_bytes()).into_string();
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for PublicKeyDouble {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let decoded =
            bs58::decode(&s).into_vec().map_err(SerdeError::custom)?;
        let decoded_len = decoded.len();
        let byte_length_str = format!("{}", Self::SIZE);
        let bytes: [u8; Self::SIZE] = decoded.try_into().map_err(|_| {
            SerdeError::invalid_length(decoded_len, &byte_length_str.as_str())
        })?;
        PublicKeyDouble::from_bytes(&bytes)
            .map_err(|err| SerdeError::custom(format!("{err:?}")))
    }
}

impl Serialize for SignatureDouble {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let s = bs58::encode(self.to_bytes()).into_string();
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for SignatureDouble {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let decoded =
            bs58::decode(&s).into_vec().map_err(SerdeError::custom)?;
        let decoded_len = decoded.len();
        let byte_length_str = format!("{}", Self::SIZE);
        let bytes: [u8; Self::SIZE] = decoded.try_into().map_err(|_| {
            SerdeError::invalid_length(decoded_len, &byte_length_str.as_str())
        })?;
        SignatureDouble::from_bytes(&bytes)
            .map_err(|err| SerdeError::custom(format!("{err:?}")))
    }
}

impl Serialize for PublicKeyVarGen {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let s = bs58::encode(self.to_bytes()).into_string();
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for PublicKeyVarGen {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let decoded =
            bs58::decode(&s).into_vec().map_err(SerdeError::custom)?;
        let decoded_len = decoded.len();
        let byte_length_str = format!("{}", Self::SIZE);
        let bytes: [u8; Self::SIZE] = decoded.try_into().map_err(|_| {
            SerdeError::invalid_length(decoded_len, &byte_length_str.as_str())
        })?;
        PublicKeyVarGen::from_bytes(&bytes)
            .map_err(|err| SerdeError::custom(format!("{err:?}")))
    }
}

impl Serialize for SecretKeyVarGen {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let s = bs58::encode(self.to_bytes()).into_string();
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for SecretKeyVarGen {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let decoded =
            bs58::decode(&s).into_vec().map_err(SerdeError::custom)?;
        let decoded_len = decoded.len();
        let byte_length_str = format!("{}", Self::SIZE);
        let bytes: [u8; Self::SIZE] = decoded.try_into().map_err(|_| {
            SerdeError::invalid_length(decoded_len, &byte_length_str.as_str())
        })?;
        SecretKeyVarGen::from_bytes(&bytes)
            .map_err(|err| SerdeError::custom(format!("{err:?}")))
    }
}

impl Serialize for SignatureVarGen {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let s = bs58::encode(self.to_bytes()).into_string();
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for SignatureVarGen {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let decoded =
            bs58::decode(&s).into_vec().map_err(SerdeError::custom)?;
        let decoded_len = decoded.len();
        let byte_length_str = format!("{}", Self::SIZE);
        let bytes: [u8; Self::SIZE] = decoded.try_into().map_err(|_| {
            SerdeError::invalid_length(decoded_len, &byte_length_str.as_str())
        })?;
        SignatureVarGen::from_bytes(&bytes)
            .map_err(|err| SerdeError::custom(format!("{err:?}")))
    }
}
