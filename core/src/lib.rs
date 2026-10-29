//! Cryptographic core of OpenPassword.
//!
//! Implements the v1 specification in `docs/crypto-spec.md`: key derivation
//! from the master password and secret key, per-item encryption of the vault
//! and the `.opvault` backup format. The Android, iOS and desktop apps call
//! into this crate so there is a single implementation to audit.

pub mod backup;
pub mod crypto;
mod encoding;
mod error;
pub mod import;
pub mod totp;
pub mod vault;

pub use crypto::{KdfParams, Key, SecretKey};
pub use error::{Error, Result};
pub use vault::{EncryptedItem, Item, ItemDetails, ItemOverview, UnlockedVault, VaultHeader};
