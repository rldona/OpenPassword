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

// Guard: `cargo fuzz build` keeps debug assertions on; a plain release build with `--cfg fuzzing` does not.
#[cfg(all(fuzzing, not(debug_assertions)))]
compile_error!("fuzzing hooks must not be compiled into release builds");

/// Entry points that exist only under `cargo fuzz` (`--cfg fuzzing`, see `fuzz/README.md`).
///
/// Random bytes never pass the AEAD, so the parsers behind it are only reachable by sealing the
/// fuzzer's input with a fixed key. **The key and the header are public constants for tests:
/// this module must never be compiled into a release build.** `cfg(fuzzing)` is set by
/// `cargo fuzz` and by nothing else in this repository.
#[cfg(fuzzing)]
pub mod fuzzing {
    use crate::{KdfParams, Key, UnlockedVault, VaultHeader};

    pub use crate::backup::fuzzing::{open_with_vault, seal_backup};
    pub use crate::vault::fuzzing::seal_item_part;

    /// Marker for `fuzz/README.md`: dead-code elimination removes unreferenced hooks from the
    /// final library, so their names say nothing about whether the cfg was on. `#[used]` keeps
    /// this string in any binary built with `--cfg fuzzing`, which gives the check a positive
    /// control. It never exists in a build without the cfg.
    #[used]
    pub static HOOKS_MARKER: [u8; 26] = *b"OPENPASSWORD_FUZZING_HOOKS";

    /// Vault key of [`vault`]. Not secret: exists so that fuzzers can seal and open data.
    pub const TEST_VAULT_KEY: [u8; 32] = [7; 32];

    /// A well-formed header; its wrapped vault key is empty, so it is only usable through
    /// `unlock_with_vault_key`.
    pub fn header() -> VaultHeader {
        VaultHeader {
            vault_id: [1; 16],
            kdf: KdfParams::RECOMMENDED,
            salt: [2; 32],
            secret_key_id: [3; 4],
            wrapped_vault_key: Vec::new(),
        }
    }

    /// The vault every fuzzer works with.
    pub fn vault() -> UnlockedVault {
        UnlockedVault::unlock_with_vault_key(&header(), Key::from_bytes(TEST_VAULT_KEY))
    }
}
