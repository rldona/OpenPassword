use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::rng::fill_random;
use crate::Result;

pub const KEY_LEN: usize = 32;

/// A 256-bit symmetric key. Wiped from memory on drop and never printed.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Key([u8; KEY_LEN]);

impl Key {
    /// Generates a fresh random key.
    pub fn generate() -> Result<Self> {
        let mut key = Key([0u8; KEY_LEN]);
        fill_random(&mut key.0)?;
        Ok(key)
    }

    /// Builds a key from raw bytes. The caller is responsible for wiping its copy.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Key(bytes)
    }

    /// Raw key bytes. Only for passing to a cipher or to the platform keystore.
    pub fn expose(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key(<redacted>)")
    }
}
