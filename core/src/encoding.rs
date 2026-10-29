//! Serde helpers: binary fields are stored as lowercase hex in JSON.

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
