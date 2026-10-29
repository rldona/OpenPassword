//! UniFFI bindings of `op-core`.
//!
//! A thin translation layer: records mirror the core types, and every call
//! goes through `op-core`, which stays free of FFI concerns. Passwords and
//! plaintext cross the boundary as JVM `String`s, which the JVM cannot wipe;
//! see docs/crypto-spec.md section 10.

use std::sync::{Arc, Mutex};

use op_core::vault::{Field, FieldKind, ItemDetails, ItemKind, ItemOverview};
use op_core::{EncryptedItem, Item, KdfParams, Key, SecretKey, UnlockedVault, VaultHeader, backup};

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum OpError {
    #[error("wrong master password or secret key")]
    WrongCredentials,
    #[error("the secret key does not belong to this vault")]
    WrongSecretKey,
    #[error("invalid secret key: {reason}")]
    InvalidSecretKey { reason: String },
    #[error("invalid input: {reason}")]
    InvalidInput { reason: String },
    #[error("the data is corrupted or was tampered with")]
    Corrupted,
    #[error("unsupported format version {version}")]
    UnsupportedVersion { version: u32 },
    #[error("the vault is locked")]
    Locked,
    #[error("internal error: {reason}")]
    Internal { reason: String },
}

impl From<op_core::Error> for OpError {
    fn from(e: op_core::Error) -> Self {
        use op_core::Error as E;
        match e {
            E::WrongCredentials => OpError::WrongCredentials,
            E::WrongSecretKey => OpError::WrongSecretKey,
            E::InvalidSecretKey(r) => OpError::InvalidSecretKey { reason: r.into() },
            E::InvalidInput(r) => OpError::InvalidInput { reason: r.into() },
            E::Decrypt | E::Malformed(_) => OpError::Corrupted,
            E::UnsupportedVersion(version) => OpError::UnsupportedVersion { version },
            E::Rng | E::Kdf | E::KdfParams(_) => OpError::Internal {
                reason: e.to_string(),
            },
        }
    }
}

type Result<T> = std::result::Result<T, OpError>;

#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum KdfProfile {
    /// 256 MiB. Default.
    Recommended,
    /// 64 MiB, for low-memory devices.
    Minimum,
}

impl From<KdfProfile> for KdfParams {
    fn from(p: KdfProfile) -> Self {
        match p {
            KdfProfile::Recommended => KdfParams::RECOMMENDED,
            KdfProfile::Minimum => KdfParams::MINIMUM,
        }
    }
}

macro_rules! mirror_enum {
    ($name:ident, $core:ty, [$($variant:ident),*]) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
        pub enum $name { $($variant),* }
        impl From<$core> for $name {
            fn from(v: $core) -> Self { match v { $(<$core>::$variant => $name::$variant),* } }
        }
        impl From<$name> for $core {
            fn from(v: $name) -> Self { match v { $($name::$variant => <$core>::$variant),* } }
        }
    };
}

mirror_enum!(
    ItemKindRecord,
    ItemKind,
    [
        Login,
        Card,
        Pin,
        SecureNote,
        Secret,
        BankAccount,
        Identity,
        Wifi
    ]
);
mirror_enum!(
    FieldKindRecord,
    FieldKind,
    [Text, Concealed, Pin, CardNumber, Totp, Date, Url, Email]
);

#[derive(Debug, Clone, uniffi::Record)]
pub struct ItemOverviewRecord {
    pub kind: ItemKindRecord,
    pub title: String,
    pub subtitle: Option<String>,
    pub urls: Vec<String>,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct FieldRecord {
    pub label: String,
    pub kind: FieldKindRecord,
    pub value: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ItemDetailsRecord {
    pub fields: Vec<FieldRecord>,
    pub notes: String,
}

/// An item as stored by the app. Opaque except for `id` and `revision`.
#[derive(Debug, Clone, uniffi::Record)]
pub struct EncryptedItemRecord {
    pub id: String,
    pub revision: u64,
    pub wrapped_item_key: Vec<u8>,
    pub overview: Vec<u8>,
    pub details: Vec<u8>,
}

impl From<&ItemOverview> for ItemOverviewRecord {
    fn from(o: &ItemOverview) -> Self {
        Self {
            kind: o.kind.into(),
            title: o.title.clone(),
            subtitle: o.subtitle.clone(),
            urls: o.urls.clone(),
            tags: o.tags.clone(),
            favorite: o.favorite,
            created_at: o.created_at,
            updated_at: o.updated_at,
        }
    }
}

impl From<ItemOverviewRecord> for ItemOverview {
    fn from(o: ItemOverviewRecord) -> Self {
        Self {
            kind: o.kind.into(),
            title: o.title,
            subtitle: o.subtitle,
            urls: o.urls,
            tags: o.tags,
            favorite: o.favorite,
            created_at: o.created_at,
            updated_at: o.updated_at,
        }
    }
}

impl From<&ItemDetails> for ItemDetailsRecord {
    fn from(d: &ItemDetails) -> Self {
        Self {
            fields: d
                .fields
                .iter()
                .map(|f| FieldRecord {
                    label: f.label.clone(),
                    kind: f.kind.into(),
                    value: f.value.clone(),
                })
                .collect(),
            notes: d.notes.clone(),
        }
    }
}

impl From<ItemDetailsRecord> for ItemDetails {
    fn from(d: ItemDetailsRecord) -> Self {
        Self {
            fields: d
                .fields
                .into_iter()
                .map(|f| Field::new(f.label, f.kind.into(), f.value))
                .collect(),
            notes: d.notes,
        }
    }
}

impl From<EncryptedItem> for EncryptedItemRecord {
    fn from(e: EncryptedItem) -> Self {
        Self {
            id: hex::encode(e.id),
            revision: e.revision,
            wrapped_item_key: e.wrapped_item_key,
            overview: e.overview,
            details: e.details,
        }
    }
}

impl TryFrom<EncryptedItemRecord> for EncryptedItem {
    type Error = OpError;
    fn try_from(r: EncryptedItemRecord) -> Result<Self> {
        let id = hex::decode(&r.id)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or(OpError::Corrupted)?;
        Ok(Self {
            id,
            revision: r.revision,
            wrapped_item_key: r.wrapped_item_key,
            overview: r.overview,
            details: r.details,
        })
    }
}

fn item(overview: ItemOverviewRecord, details: ItemDetailsRecord) -> Item {
    Item {
        overview: overview.into(),
        details: details.into(),
    }
}

/// An unlocked vault. Call [`Vault::lock`] to wipe the key from memory.
#[derive(uniffi::Object)]
pub struct Vault {
    inner: Mutex<Option<UnlockedVault>>,
}

impl Vault {
    fn wrap(vault: UnlockedVault) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Some(vault)),
        })
    }

    fn with<T>(&self, f: impl FnOnce(&UnlockedVault) -> op_core::Result<T>) -> Result<T> {
        let guard = self.inner.lock().map_err(|_| OpError::Internal {
            reason: "poisoned lock".into(),
        })?;
        let vault = guard.as_ref().ok_or(OpError::Locked)?;
        f(vault).map_err(OpError::from)
    }
}

fn parse_header(header_json: &str) -> Result<VaultHeader> {
    serde_json::from_str(header_json).map_err(|_| OpError::Corrupted)
}

#[uniffi::export]
impl Vault {
    /// Creates a vault. Runs Argon2id: call it off the main thread.
    #[uniffi::constructor]
    pub fn create(password: String, secret_key: String, profile: KdfProfile) -> Result<Arc<Self>> {
        let sk = SecretKey::parse(&secret_key)?;
        Ok(Self::wrap(UnlockedVault::create(
            &password,
            &sk,
            profile.into(),
        )?))
    }

    /// Unlocks with the master password. Runs Argon2id: call it off the main thread.
    #[uniffi::constructor]
    pub fn unlock(header_json: String, password: String, secret_key: String) -> Result<Arc<Self>> {
        let sk = SecretKey::parse(&secret_key)?;
        Ok(Self::wrap(UnlockedVault::unlock(
            &parse_header(&header_json)?,
            &password,
            &sk,
        )?))
    }

    /// Unlocks with a vault key released by Android Keystore after biometric auth.
    #[uniffi::constructor]
    pub fn unlock_with_vault_key(header_json: String, vault_key: Vec<u8>) -> Result<Arc<Self>> {
        let bytes: [u8; 32] = vault_key.try_into().map_err(|_| OpError::InvalidInput {
            reason: "vault key must be 32 bytes".into(),
        })?;
        Ok(Self::wrap(UnlockedVault::unlock_with_vault_key(
            &parse_header(&header_json)?,
            Key::from_bytes(bytes),
        )))
    }

    /// Header to persist next to the items. Contains no user data.
    pub fn header_json(&self) -> Result<String> {
        self.with(|v| Ok(serde_json::to_string(v.header()).expect("header serializes")))
    }

    /// Raw vault key, only to seal it with Android Keystore for biometric unlock.
    pub fn vault_key_bytes(&self) -> Result<Vec<u8>> {
        self.with(|v| Ok(v.vault_key().expose().to_vec()))
    }

    pub fn encrypt_item(
        &self,
        overview: ItemOverviewRecord,
        details: ItemDetailsRecord,
    ) -> Result<EncryptedItemRecord> {
        self.with(|v| v.encrypt_item(&item(overview, details)))
            .map(Into::into)
    }

    pub fn update_item(
        &self,
        existing: EncryptedItemRecord,
        overview: ItemOverviewRecord,
        details: ItemDetailsRecord,
    ) -> Result<EncryptedItemRecord> {
        let existing = existing.try_into()?;
        self.with(|v| v.update_item(&existing, &item(overview, details)))
            .map(Into::into)
    }

    pub fn decrypt_overview(&self, item: EncryptedItemRecord) -> Result<ItemOverviewRecord> {
        let item = item.try_into()?;
        self.with(|v| v.decrypt_overview(&item))
            .map(|o| (&o).into())
    }

    pub fn decrypt_details(&self, item: EncryptedItemRecord) -> Result<ItemDetailsRecord> {
        let item = item.try_into()?;
        self.with(|v| v.decrypt_details(&item)).map(|d| (&d).into())
    }

    /// Serializes an encrypted `.opvault` backup of `items`.
    pub fn export_backup(
        &self,
        items: Vec<EncryptedItemRecord>,
        created_at: u64,
    ) -> Result<Vec<u8>> {
        let items = items
            .into_iter()
            .map(EncryptedItem::try_from)
            .collect::<Result<Vec<_>>>()?;
        self.with(|v| backup::write(v, &items, created_at))
    }

    /// Wipes the vault key. Every later call fails with [`OpError::Locked`].
    pub fn lock(&self) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.take();
        }
    }

    pub fn is_locked(&self) -> bool {
        self.inner.lock().map(|g| g.is_none()).unwrap_or(true)
    }
}

#[derive(uniffi::Record)]
pub struct BackupContents {
    pub vault: Arc<Vault>,
    pub items: Vec<EncryptedItemRecord>,
}

/// Opens a `.opvault` backup. Runs Argon2id: call it off the main thread.
#[uniffi::export]
pub fn open_backup(bytes: Vec<u8>, password: String, secret_key: String) -> Result<BackupContents> {
    let sk = SecretKey::parse(&secret_key)?;
    let (vault, items) = backup::open(&bytes, &password, &sk)?;
    Ok(BackupContents {
        vault: Vault::wrap(vault),
        items: items.into_iter().map(Into::into).collect(),
    })
}

/// A new random secret key in display form (`OP1-…`).
#[uniffi::export]
pub fn generate_secret_key() -> Result<String> {
    Ok(SecretKey::generate()?.to_display().to_string())
}

/// Validates user input and returns the canonical display form.
#[uniffi::export]
pub fn normalize_secret_key(input: String) -> Result<String> {
    Ok(SecretKey::parse(&input)?.to_display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn overview(title: &str) -> ItemOverviewRecord {
        ItemOverviewRecord {
            kind: ItemKindRecord::Pin,
            title: title.into(),
            subtitle: None,
            urls: vec![],
            tags: vec![],
            favorite: false,
            created_at: 1,
            updated_at: 1,
        }
    }

    fn details() -> ItemDetailsRecord {
        ItemDetailsRecord {
            fields: vec![FieldRecord {
                label: "PIN".into(),
                kind: FieldKindRecord::Pin,
                value: "2958".into(),
            }],
            notes: String::new(),
        }
    }

    // Uses the minimum profile (64 MiB): this crate does not enable the test-only KDF feature.
    #[test]
    fn full_flow_through_the_ffi_surface() {
        let sk = generate_secret_key().unwrap();
        let vault = Vault::create(
            "contraseña larga de prueba".into(),
            sk.clone(),
            KdfProfile::Minimum,
        )
        .unwrap();
        let enc = vault.encrypt_item(overview("Alarma"), details()).unwrap();
        let enc2 = vault
            .update_item(enc.clone(), overview("Alarma casa"), details())
            .unwrap();
        assert_eq!(enc2.revision, 2);
        assert_eq!(
            vault.decrypt_overview(enc2.clone()).unwrap().title,
            "Alarma casa"
        );
        assert_eq!(
            vault.decrypt_details(enc2.clone()).unwrap().fields[0].value,
            "2958"
        );

        let header = vault.header_json().unwrap();
        let reopened = Vault::unlock(
            header.clone(),
            "contraseña larga de prueba".into(),
            sk.to_lowercase(),
        )
        .unwrap();
        assert_eq!(
            reopened.decrypt_overview(enc2.clone()).unwrap().title,
            "Alarma casa"
        );
        assert!(matches!(
            Vault::unlock(header.clone(), "otra".into(), sk.clone()),
            Err(OpError::WrongCredentials)
        ));

        let key = vault.vault_key_bytes().unwrap();
        let bio = Vault::unlock_with_vault_key(header, key).unwrap();
        assert_eq!(bio.decrypt_details(enc2.clone()).unwrap().notes, "");

        let file = vault.export_backup(vec![enc2.clone()], 1).unwrap();
        let restored = open_backup(file, "contraseña larga de prueba".into(), sk).unwrap();
        assert_eq!(restored.items[0].id, enc2.id);

        vault.lock();
        assert!(vault.is_locked());
        assert!(matches!(vault.decrypt_overview(enc2), Err(OpError::Locked)));
    }

    #[test]
    fn secret_key_errors_are_readable() {
        assert!(matches!(
            normalize_secret_key("OP1-nope".into()),
            Err(OpError::InvalidSecretKey { .. })
        ));
        let sk = generate_secret_key().unwrap();
        assert_eq!(
            normalize_secret_key(sk.replace('-', " ").to_lowercase()).unwrap(),
            sk
        );
    }

    #[test]
    fn corrupted_item_ids_are_rejected() {
        let sk = generate_secret_key().unwrap();
        let vault =
            Vault::create("contraseña larga de prueba".into(), sk, KdfProfile::Minimum).unwrap();
        let mut enc = vault.encrypt_item(overview("x"), details()).unwrap();
        enc.id = "zz".into();
        assert!(matches!(
            vault.decrypt_overview(enc),
            Err(OpError::Corrupted)
        ));
    }
}
