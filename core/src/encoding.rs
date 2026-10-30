//! Serde helpers: binary fields are stored as lowercase hex in JSON, except attachments,
//! whose ciphertext is base64 to keep backups small.

pub(crate) mod base64_bytes {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(value: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD
            .decode(&s)
            .map_err(|_| D::Error::custom("invalid base64"))
    }
}

pub(crate) mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer, T: AsRef<[u8]>>(value: &T, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(value))
    }

    pub fn deserialize<'de, D, T>(d: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: TryFrom<Vec<u8>>,
    {
        // Owned, so it also works with readers that cannot borrow (from_reader, from_value).
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(|_| D::Error::custom("invalid hex"))?;
        T::try_from(bytes).map_err(|_| D::Error::custom("invalid length"))
    }
}
