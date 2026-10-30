//! UniFFI bindings of `op-core`.
//!
//! A thin translation layer: records mirror the core types, and every call
//! goes through `op-core`, which stays free of FFI concerns.
//!
//! Secrets and plaintext cross the boundary as `String`s (Kotlin side: JVM `String`s, which
//! cannot be wiped; see docs/crypto-spec.md section 10). Ownership contract:
//! - text secrets (passwords, secret keys, field values, notes, history, TOTP seeds) use
//!   [`SecretString`], which Rust wipes when dropped; Kotlin still sees `String`;
//! - byte inputs that carry secrets (`vault_key`, `key_file`, imported files) are wrapped in
//!   `Zeroizing` as soon as they enter; whoever creates a buffer wipes it, so Kotlin wipes
//!   what it passes in and what `vault_key_bytes` returns;
//! - accepted leftovers: JVM and Compose `String`s, and the outgoing `RustBuffer` plus the
//!   `String` Rust hands over to build it, which UniFFI frees without wiping.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use zeroize::Zeroizing;

use op_core::vault::{
    AttachmentId, EncryptedAttachment, Field, FieldKind, ItemChange, ItemDetails, ItemKind,
    ItemOverview, MAX_IMAGE_BYTES, MAX_IMAGES_PER_ITEM, MAX_VAULT_ATTACHMENT_BYTES, NewImage,
    PasswordChange,
};
use op_core::{EncryptedItem, Item, KdfParams, Key, SecretKey, UnlockedVault, VaultHeader, backup};

mod secret;

pub use secret::SecretString;

uniffi::setup_scaffolding!();

/// Platform ceiling for the KDF cost of a header or backup read from outside: 512 MiB,
/// 6 passes, 8 lanes. Lower than the format's [`KdfParams::MAXIMUM`] (2 GiB / 16 / 16),
/// which stays as is: a phone cannot afford that. Four times the cost of
/// [`KdfParams::RECOMMENDED`], and above anything the app creates.
pub const MOBILE_MAXIMUM: KdfParams = KdfParams::argon2id(524_288, 6, 8);

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
    #[error(
        "the key derivation is too expensive for this device ({m_kib} KiB, {t} passes, {p} lanes)"
    )]
    KdfTooExpensive { m_kib: u32, t: u32, p: u32 },
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
            E::KdfParams(r) => OpError::InvalidInput { reason: r.into() },
            E::Rng | E::Kdf => OpError::Internal {
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
    [Text, Concealed, Pin, CardNumber, Totp, Date, Url, Email, Image]
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
    pub value: SecretString,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ItemDetailsRecord {
    pub fields: Vec<FieldRecord>,
    pub notes: SecretString,
    /// Previous passwords, newest first. Ignored by `update_item`, which computes it.
    #[uniffi(default = [])]
    pub history: Vec<PasswordChangeRecord>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct PasswordChangeRecord {
    pub label: String,
    pub value: SecretString,
    pub changed_at: u64,
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

/// A sealed image as stored by the app and carried in backups.
#[derive(Clone, uniffi::Record)]
pub struct EncryptedAttachmentRecord {
    pub item_id: String,
    pub id: String,
    pub data: Vec<u8>,
}

impl std::fmt::Debug for EncryptedAttachmentRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedAttachmentRecord")
            .field("item_id", &self.item_id)
            .field("id", &self.id)
            .field("data_len", &self.data.len())
            .finish()
    }
}

/// A new image to seal. Kotlin owns `jpeg` and must wipe it after the call.
#[derive(Clone, uniffi::Record)]
pub struct NewImageRecord {
    pub id: String,
    pub jpeg: Vec<u8>,
}

impl std::fmt::Debug for NewImageRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NewImageRecord(<redacted>)")
    }
}

/// What a save writes: the item, the attachments to add and the ids to remove.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ItemChangeRecord {
    pub item: EncryptedItemRecord,
    pub added: Vec<EncryptedAttachmentRecord>,
    pub removed: Vec<String>,
}

/// Product limits, so the app does not duplicate them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct AttachmentLimits {
    pub max_image_bytes: u32,
    pub max_images_per_item: u32,
    pub max_vault_attachment_bytes: u64,
    pub max_backup_bytes: u64,
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
                    value: f.value.as_str().into(),
                })
                .collect(),
            notes: d.notes.as_str().into(),
            history: d
                .history
                .iter()
                .map(|h| PasswordChangeRecord {
                    label: h.label.clone(),
                    value: h.value.as_str().into(),
                    changed_at: h.changed_at,
                })
                .collect(),
        }
    }
}

impl From<ItemDetailsRecord> for ItemDetails {
    fn from(d: ItemDetailsRecord) -> Self {
        Self {
            fields: d
                .fields
                .into_iter()
                .map(|f| Field::new(f.label, f.kind.into(), f.value.expose().to_owned()))
                .collect(),
            notes: d.notes.expose().to_owned(),
            history: d
                .history
                .into_iter()
                .map(|h| PasswordChange {
                    label: h.label,
                    value: h.value.expose().to_owned(),
                    changed_at: h.changed_at,
                })
                .collect(),
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

fn parse_attachment_id(value: &str) -> Result<AttachmentId> {
    hex::decode(value)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(OpError::Corrupted)
}

fn new_image(record: NewImageRecord) -> Result<NewImage> {
    Ok(NewImage {
        id: parse_attachment_id(&record.id)?,
        jpeg: Zeroizing::new(record.jpeg),
    })
}

impl From<EncryptedAttachment> for EncryptedAttachmentRecord {
    fn from(a: EncryptedAttachment) -> Self {
        Self {
            item_id: hex::encode(a.item_id),
            id: hex::encode(a.id),
            data: a.data,
        }
    }
}

impl TryFrom<EncryptedAttachmentRecord> for EncryptedAttachment {
    type Error = OpError;
    fn try_from(r: EncryptedAttachmentRecord) -> Result<Self> {
        Ok(Self {
            item_id: parse_attachment_id(&r.item_id)?,
            id: parse_attachment_id(&r.id)?,
            data: r.data,
        })
    }
}

impl From<ItemChange> for ItemChangeRecord {
    fn from(c: ItemChange) -> Self {
        Self {
            item: c.item.into(),
            added: c.added.into_iter().map(Into::into).collect(),
            removed: c.removed.into_iter().map(hex::encode).collect(),
        }
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

    /// Takes the lock even if a panic poisoned it: the key must stay wipeable.
    fn guard(&self) -> MutexGuard<'_, Option<UnlockedVault>> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Runs `f` with the unlocked vault. If a previous panic poisoned the mutex, the key
    /// is wiped, the poison is cleared and this call returns [`OpError::Internal`]; later
    /// calls answer [`OpError::Locked`].
    fn with<T>(&self, f: impl FnOnce(&UnlockedVault) -> op_core::Result<T>) -> Result<T> {
        let guard = match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                poisoned.into_inner().take();
                self.inner.clear_poison();
                return Err(OpError::Internal {
                    reason: "poisoned lock".into(),
                });
            }
        };
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
    pub fn create(
        password: SecretString,
        secret_key: SecretString,
        profile: KdfProfile,
    ) -> Result<Arc<Self>> {
        let sk = SecretKey::parse(secret_key.expose())?;
        Ok(Self::wrap(UnlockedVault::create(
            password.expose(),
            &sk,
            profile.into(),
        )?))
    }

    /// Unlocks with the master password. Runs Argon2id: call it off the main thread.
    #[uniffi::constructor]
    pub fn unlock(
        header_json: String,
        password: SecretString,
        secret_key: SecretString,
    ) -> Result<Arc<Self>> {
        let sk = SecretKey::parse(secret_key.expose())?;
        let header = parse_header(&header_json)?;
        check_mobile_kdf(&header.kdf)?;
        Ok(Self::wrap(UnlockedVault::unlock(
            &header,
            password.expose(),
            &sk,
        )?))
    }

    /// Unlocks with a vault key released by Android Keystore after biometric auth.
    #[uniffi::constructor]
    pub fn unlock_with_vault_key(header_json: String, vault_key: Vec<u8>) -> Result<Arc<Self>> {
        let vault_key = Zeroizing::new(vault_key);
        let mut bytes = Zeroizing::new([0u8; 32]);
        if vault_key.len() != bytes.len() {
            return Err(OpError::InvalidInput {
                reason: "vault key must be 32 bytes".into(),
            });
        }
        bytes.copy_from_slice(&vault_key);
        Ok(Self::wrap(UnlockedVault::unlock_with_vault_key(
            &parse_header(&header_json)?,
            Key::from_bytes(*bytes),
        )))
    }

    /// Header to persist next to the items. Contains no user data.
    pub fn header_json(&self) -> Result<String> {
        self.with(|v| Ok(serde_json::to_string(v.header()).expect("header serializes")))
    }

    /// Raw vault key, only to seal it with Android Keystore for biometric unlock. The caller
    /// owns the returned bytes and must wipe them; the `RustBuffer` UniFFI builds is a
    /// leftover Rust cannot wipe.
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

    /// Encrypts a new item and its new images.
    pub fn encrypt_item_with_images(
        &self,
        overview: ItemOverviewRecord,
        details: ItemDetailsRecord,
        images: Vec<NewImageRecord>,
    ) -> Result<ItemChangeRecord> {
        let images = images.into_iter().map(new_image).collect::<Result<Vec<_>>>()?;
        self.with(|v| v.encrypt_item_with_images(&item(overview, details), images))
            .map(Into::into)
    }

    /// Re-encrypts an edited item, sealing `images` and reporting the ids to remove.
    pub fn update_item_with_images(
        &self,
        existing: EncryptedItemRecord,
        overview: ItemOverviewRecord,
        details: ItemDetailsRecord,
        images: Vec<NewImageRecord>,
    ) -> Result<ItemChangeRecord> {
        let existing = existing.try_into()?;
        let images = images.into_iter().map(new_image).collect::<Result<Vec<_>>>()?;
        self.with(|v| v.update_item_with_images(&existing, &item(overview, details), images))
            .map(Into::into)
    }

    /// Decrypts one image. The caller owns the bytes and must wipe them; the outgoing
    /// `RustBuffer` is an accepted leftover.
    pub fn decrypt_image(
        &self,
        item: EncryptedItemRecord,
        attachment: EncryptedAttachmentRecord,
    ) -> Result<Vec<u8>> {
        let item = item.try_into()?;
        let attachment = attachment.try_into()?;
        self.with(|v| v.decrypt_image(&item, &attachment))
            .map(|image| image.jpeg.to_vec())
    }

    /// Ids of the images the item references, in field order.
    pub fn image_ids(&self, item: EncryptedItemRecord) -> Result<Vec<String>> {
        let item = item.try_into()?;
        self.with(|v| v.image_ids(&item))
            .map(|ids| ids.into_iter().map(hex::encode).collect())
    }

    /// Moves an item and its images from `source` into this vault. Plaintext never crosses
    /// the FFI boundary. The two locks are never held at the same time.
    pub fn adopt_item(
        &self,
        source: Arc<Vault>,
        item: EncryptedItemRecord,
        attachments: Vec<EncryptedAttachmentRecord>,
    ) -> Result<ItemChangeRecord> {
        if std::ptr::eq(Arc::as_ptr(&source), self) {
            return Err(OpError::InvalidInput {
                reason: "cannot adopt an item into its own vault".into(),
            });
        }
        let item = item.try_into()?;
        let attachments = attachments
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>>>()?;
        let plain = source.with(|v| v.open_item_with_images(&item, &attachments))?;
        self.with(|v| v.adopt_item(&plain)).map(Into::into)
    }

    /// Serializes an encrypted `.opvault` backup of `items` and their attachments.
    pub fn export_backup(
        &self,
        items: Vec<EncryptedItemRecord>,
        attachments: Vec<EncryptedAttachmentRecord>,
        created_at: u64,
    ) -> Result<Vec<u8>> {
        let items = items
            .into_iter()
            .map(EncryptedItem::try_from)
            .collect::<Result<Vec<_>>>()?;
        let attachments = attachments
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>>>()?;
        self.with(|v| backup::write(v, &items, &attachments, created_at))
    }

    /// Wipes the vault key. Every later call fails with [`OpError::Locked`].
    pub fn lock(&self) {
        self.guard().take();
    }

    pub fn is_locked(&self) -> bool {
        self.guard().is_none()
    }
}

#[derive(uniffi::Record)]
pub struct BackupContents {
    pub vault: Arc<Vault>,
    pub items: Vec<EncryptedItemRecord>,
    pub attachments: Vec<EncryptedAttachmentRecord>,
}

/// Opens a `.opvault` backup. Fails with [`OpError::KdfTooExpensive`], before deriving
/// anything, if its KDF is above [`MOBILE_MAXIMUM`]. Runs Argon2id: call it off the main
/// thread.
#[uniffi::export]
pub fn open_backup(
    bytes: Vec<u8>,
    password: SecretString,
    secret_key: SecretString,
) -> Result<BackupContents> {
    let bytes = Zeroizing::new(bytes);
    let sk = SecretKey::parse(secret_key.expose())?;
    check_mobile_kdf(&backup::read_header(&bytes)?.vault.kdf)?;
    let (vault, items, attachments) = backup::open(&bytes, password.expose(), &sk)?;
    Ok(BackupContents {
        vault: Vault::wrap(vault),
        items: items.into_iter().map(Into::into).collect(),
        attachments: attachments.into_iter().map(Into::into).collect(),
    })
}

/// A new random attachment id, as the canonical lowercase hex the image field stores.
#[uniffi::export]
pub fn new_attachment_id() -> Result<String> {
    Ok(hex::encode(op_core::vault::new_attachment_id()?))
}

/// Product limits for images, so the app does not duplicate them.
#[uniffi::export]
pub fn attachment_limits() -> AttachmentLimits {
    AttachmentLimits {
        max_image_bytes: u32::try_from(MAX_IMAGE_BYTES).expect("1.5 MiB fits"),
        max_images_per_item: u32::try_from(MAX_IMAGES_PER_ITEM).expect("10 fits"),
        max_vault_attachment_bytes: MAX_VAULT_ATTACHMENT_BYTES,
        max_backup_bytes: u64::try_from(backup::MAX_FILE_LEN).expect("64 MiB fits"),
    }
}

/// Rejects a header whose KDF is above [`MOBILE_MAXIMUM`], before any derivation.
fn check_mobile_kdf(kdf: &KdfParams) -> Result<()> {
    if kdf.exceeds(&MOBILE_MAXIMUM) {
        return Err(OpError::KdfTooExpensive {
            m_kib: kdf.m_kib,
            t: kdf.t,
            p: kdf.p,
        });
    }
    Ok(kdf.check_within(&MOBILE_MAXIMUM)?)
}

/// KDF cost of a backup, so the app can compare it with the device's memory first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct KdfInfo {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

/// Reads the KDF parameters from a backup's plaintext header. Carries no secret and runs no
/// KDF. Fails if the header is malformed or above the format's maximum.
#[uniffi::export]
pub fn backup_kdf(bytes: Vec<u8>) -> Result<KdfInfo> {
    let kdf = backup::read_header(&bytes)?.vault.kdf;
    Ok(KdfInfo {
        m_kib: kdf.m_kib,
        t: kdf.t,
        p: kdf.p,
    })
}

/// Argon2 cost of a KeePass (`.kdbx`) file, to compare with the device's memory **before**
/// [`parse_import`] runs the KDF (same rule as for backups: `KdfMemory.kt`). Reads only the
/// file's plaintext header: no secret, no KDF. `None` if the file is not KDBX or its key
/// derivation needs no memory worth checking (AES-KDF, KDBX 3.1). Values above the platform
/// ceiling are reported as they are: `parse_import` refuses them with a clear message.
#[uniffi::export]
pub fn import_kdf(bytes: Vec<u8>) -> Result<Option<KdfInfo>> {
    let bytes = Zeroizing::new(bytes);
    let clamp = |v: u64| u32::try_from(v).unwrap_or(u32::MAX);
    Ok(op_core::import::kdbx_argon2_cost(&bytes)?.map(|c| KdfInfo {
        m_kib: clamp(c.memory_kib),
        t: clamp(c.iterations),
        p: clamp(c.lanes),
    }))
}

/// A new random secret key in display form (`OP1-…`).
#[uniffi::export]
pub fn generate_secret_key() -> Result<SecretString> {
    Ok(SecretKey::generate()?.to_display().to_string().into())
}

/// Validates user input and returns the canonical display form.
#[uniffi::export]
pub fn normalize_secret_key(input: SecretString) -> Result<SecretString> {
    Ok(SecretKey::parse(input.expose())?
        .to_display()
        .to_string()
        .into())
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ImportedItemRecord {
    pub overview: ItemOverviewRecord,
    pub details: ItemDetailsRecord,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ImportResult {
    /// "csv", "bitwarden-json", "1password-1pux" or "keepass-kdbx".
    pub format: String,
    pub items: Vec<ImportedItemRecord>,
    pub skipped: u32,
}

/// True if the file is encrypted and [`parse_import`] needs its password (KeePass).
#[uniffi::export]
pub fn import_needs_password(bytes: Vec<u8>) -> bool {
    op_core::import::needs_password(&Zeroizing::new(bytes))
}

/// Parses another manager's export. Nothing is stored: the app encrypts the items.
/// `password` and `key_file` are only used for encrypted formats (KeePass). Runs a KDF for
/// those: call it off the main thread.
#[uniffi::export]
pub fn parse_import(
    bytes: Vec<u8>,
    password: Option<SecretString>,
    key_file: Option<Vec<u8>>,
    now: u64,
) -> Result<ImportResult> {
    let bytes = Zeroizing::new(bytes);
    let key_file = key_file.map(Zeroizing::new);
    let imported = op_core::import::parse_with_credentials(
        &bytes,
        password.as_ref().map(SecretString::expose),
        key_file.as_ref().map(|k| k.as_slice()),
        now,
    )?;
    Ok(ImportResult {
        format: match imported.format {
            op_core::import::ImportFormat::Csv => "csv",
            op_core::import::ImportFormat::BitwardenJson => "bitwarden-json",
            op_core::import::ImportFormat::OnePassword1pux => "1password-1pux",
            op_core::import::ImportFormat::Kdbx => "keepass-kdbx",
        }
        .into(),
        items: imported
            .items
            .iter()
            .map(|i| ImportedItemRecord {
                overview: (&i.overview).into(),
                details: (&i.details).into(),
            })
            .collect(),
        skipped: u32::try_from(imported.skipped).unwrap_or(u32::MAX),
    })
}

/// The code to show for a TOTP field right now.
#[derive(Debug, Clone, uniffi::Record)]
pub struct TotpCode {
    pub code: String,
    pub seconds_remaining: u64,
    pub period: u64,
    pub issuer: Option<String>,
    pub account: Option<String>,
}

/// Current code for an `otpauth://totp/...` link or a base32 secret.
#[uniffi::export]
pub fn totp_code(input: SecretString, unix_time: u64) -> Result<TotpCode> {
    let totp = op_core::totp::Totp::parse(input.expose())?;
    Ok(TotpCode {
        code: totp.code_at(unix_time),
        seconds_remaining: totp.seconds_remaining(unix_time),
        period: totp.period,
        issuer: totp.issuer.clone(),
        account: totp.account.clone(),
    })
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
            notes: SecretString::default(),
            history: Vec::new(),
        }
    }

    const PASSWORD: &str = "contraseña larga de prueba";

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
            vault.decrypt_details(enc2.clone()).unwrap().fields[0]
                .value
                .expose(),
            "2958"
        );

        let header = vault.header_json().unwrap();
        let reopened = Vault::unlock(
            header.clone(),
            "contraseña larga de prueba".into(),
            sk.expose().to_lowercase().into(),
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
        assert_eq!(
            bio.decrypt_details(enc2.clone()).unwrap().notes.expose(),
            ""
        );

        let file = vault.export_backup(vec![enc2.clone()], Vec::new(), 1).unwrap();
        let restored = open_backup(file, "contraseña larga de prueba".into(), sk).unwrap();
        assert_eq!(restored.items[0].id, enc2.id);

        vault.lock();
        assert!(vault.is_locked());
        assert!(matches!(vault.decrypt_overview(enc2), Err(OpError::Locked)));
    }

    fn poisoned_vault() -> (Arc<Vault>, EncryptedItemRecord) {
        let sk = generate_secret_key().unwrap();
        let vault =
            Vault::create("contraseña larga de prueba".into(), sk, KdfProfile::Minimum).unwrap();
        let enc = vault.encrypt_item(overview("Alarma"), details()).unwrap();
        let v = Arc::clone(&vault);
        let result = std::thread::spawn(move || {
            let _guard = v.inner.lock().unwrap();
            panic!("boom");
        })
        .join();
        assert!(result.is_err());
        assert!(vault.inner.is_poisoned());
        (vault, enc)
    }

    #[test]
    fn lock_wipes_key_after_poisoned_mutex() {
        let (vault, _) = poisoned_vault();
        vault.lock();
        assert!(vault.is_locked());
        assert!(vault.guard().is_none());
    }

    #[test]
    fn with_after_poison_returns_internal_and_locks() {
        let (vault, enc) = poisoned_vault();
        assert!(matches!(
            vault.decrypt_overview(enc.clone()),
            Err(OpError::Internal { .. })
        ));
        assert!(vault.is_locked());
        assert!(matches!(vault.decrypt_overview(enc), Err(OpError::Locked)));
    }

    #[test]
    fn secret_key_errors_are_readable() {
        assert!(matches!(
            normalize_secret_key("OP1-nope".into()),
            Err(OpError::InvalidSecretKey { .. })
        ));
        let sk = generate_secret_key().unwrap();
        assert_eq!(
            normalize_secret_key(sk.expose().replace('-', " ").to_lowercase().into())
                .unwrap()
                .expose(),
            sk.expose()
        );
    }

    #[test]
    fn totp_codes_through_the_ffi() {
        // RFC 6238 SHA-1 seed "12345678901234567890" in base32.
        let code = totp_code("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(), 59).unwrap();
        assert_eq!(code.code, "287082");
        assert_eq!(code.seconds_remaining, 1);
        assert!(matches!(
            totp_code("nope!".into(), 0),
            Err(OpError::InvalidInput { .. })
        ));
    }

    #[test]
    fn import_then_encrypt() {
        let result = parse_import(
            b"name,url,username,password\nGitHub,https://github.com,raul,pw\n".to_vec(),
            None,
            None,
            5,
        )
        .unwrap();
        assert_eq!(result.format, "csv");
        let sk = generate_secret_key().unwrap();
        let vault =
            Vault::create("contraseña larga de prueba".into(), sk, KdfProfile::Minimum).unwrap();
        let item = result.items[0].clone();
        let enc = vault.encrypt_item(item.overview, item.details).unwrap();
        assert_eq!(vault.decrypt_overview(enc).unwrap().title, "GitHub");
    }

    #[test]
    fn images_through_the_ffi() {
        fn jpeg() -> Vec<u8> {
            let segment = |marker: u8, payload: &[u8]| {
                let mut out = vec![0xFF, marker];
                out.extend_from_slice(&u16::try_from(payload.len() + 2).unwrap().to_be_bytes());
                out.extend_from_slice(payload);
                out
            };
            let mut out = vec![0xFF, 0xD8];
            out.extend(segment(0xDB, &[0; 65]));
            out.extend(segment(0xC0, &[8, 0, 1, 0, 1, 1, 1, 0x11, 0]));
            out.extend(segment(0xC4, &[0; 20]));
            out.extend(segment(0xDA, &[1, 1, 0, 0, 63, 0]));
            out.extend_from_slice(&[0x12, 0x34, 0xFF, 0xD9]);
            out
        }

        let sk = generate_secret_key().unwrap();
        let vault = Vault::create(PASSWORD.into(), sk.clone(), KdfProfile::Minimum).unwrap();
        let id = new_attachment_id().unwrap();
        let bytes = jpeg();
        let details = ItemDetailsRecord {
            fields: vec![FieldRecord {
                label: "Anverso".into(),
                kind: FieldKindRecord::Image,
                value: id.clone().into(),
            }],
            notes: SecretString::default(),
            history: Vec::new(),
        };
        let change = vault
            .encrypt_item_with_images(
                overview("DNI"),
                details,
                vec![NewImageRecord {
                    id: id.clone(),
                    jpeg: bytes.clone(),
                }],
            )
            .unwrap();
        assert_eq!(change.added.len(), 1);
        assert_eq!(vault.image_ids(change.item.clone()).unwrap(), vec![id]);
        assert_eq!(
            vault
                .decrypt_image(change.item.clone(), change.added[0].clone())
                .unwrap(),
            bytes
        );
        assert!(format!("{:?}", change.added[0]).contains("data_len"));
        assert!(!format!("{:?}", change.added[0]).contains("255"));

        let file = vault
            .export_backup(
                vec![change.item.clone()],
                change.added.clone(),
                1,
            )
            .unwrap();
        let restored = open_backup(file, PASSWORD.into(), sk.clone()).unwrap();
        assert_eq!(restored.attachments.len(), 1);
        assert_eq!(
            restored
                .vault
                .decrypt_image(restored.items[0].clone(), restored.attachments[0].clone())
                .unwrap(),
            bytes
        );

        let other = Vault::create(PASSWORD.into(), sk, KdfProfile::Minimum).unwrap();
        let adopted = other
            .adopt_item(vault.clone(), change.item, change.added)
            .unwrap();
        assert_eq!(other.image_ids(adopted.item.clone()).unwrap().len(), 1);
        assert_eq!(
            other
                .decrypt_image(adopted.item, adopted.added[0].clone())
                .unwrap(),
            bytes
        );
        assert!(matches!(
            other.adopt_item(
                other.clone(),
                EncryptedItemRecord {
                    id: "00".into(),
                    revision: 1,
                    wrapped_item_key: vec![],
                    overview: vec![],
                    details: vec![],
                },
                vec![],
            ),
            Err(OpError::InvalidInput { .. })
        ));
        assert_eq!(attachment_limits().max_images_per_item, 10);
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

    /// A real backup whose header declares `kdf`. The header is not authenticated until the
    /// body is decrypted, so a rewritten one parses fine and only the KDF would reject it.
    fn backup_with_kdf(kdf: KdfParams) -> (Vec<u8>, SecretString) {
        let sk = generate_secret_key().unwrap();
        let vault = Vault::create(PASSWORD.into(), sk.clone(), KdfProfile::Minimum).unwrap();
        let file = vault.export_backup(Vec::new(), Vec::new(), 1).unwrap();
        let start = backup::MAGIC.len() + 4;
        let len = u32::from_le_bytes(file[start - 4..start].try_into().unwrap()) as usize;
        let mut header: serde_json::Value =
            serde_json::from_slice(&file[start..start + len]).unwrap();
        header["vault"]["kdf"] = serde_json::to_value(kdf).unwrap();
        let header = serde_json::to_vec(&header).unwrap();
        let mut out = file[..start - 4].to_vec();
        out.extend_from_slice(&u32::try_from(header.len()).unwrap().to_le_bytes());
        out.extend_from_slice(&header);
        out.extend_from_slice(&file[start + len..]);
        (out, sk)
    }

    #[test]
    fn backup_above_the_mobile_ceiling_fails_fast() {
        for kdf in [
            KdfParams::argon2id(524_289, 6, 8),
            KdfParams::argon2id(524_288, 7, 8),
            KdfParams::argon2id(524_288, 6, 9),
            KdfParams::MAXIMUM,
        ] {
            let (file, sk) = backup_with_kdf(kdf);
            let started = std::time::Instant::now();
            let result = open_backup(file, PASSWORD.into(), sk);
            assert!(
                matches!(
                    result,
                    Err(OpError::KdfTooExpensive { m_kib, t, p })
                        if (m_kib, t, p) == (kdf.m_kib, kdf.t, kdf.p)
                ),
                "{kdf:?}"
            );
            // Argon2 at these costs takes seconds and gigabytes: this must not run it.
            assert!(
                started.elapsed() < std::time::Duration::from_secs(1),
                "{kdf:?}"
            );
        }
    }

    #[test]
    fn mobile_ceiling_is_inclusive() {
        // Checked directly: opening would run a 512 MiB Argon2 for nothing.
        assert!(check_mobile_kdf(&MOBILE_MAXIMUM).is_ok());
        assert!(check_mobile_kdf(&KdfParams::RECOMMENDED).is_ok());
        assert!(matches!(
            check_mobile_kdf(&KdfParams::argon2id(524_289, 6, 8)),
            Err(OpError::KdfTooExpensive { .. })
        ));
        // Unusable parameters under the ceiling are invalid input, not "too expensive".
        assert!(matches!(
            check_mobile_kdf(&KdfParams::argon2id(16, 1, 4)),
            Err(OpError::InvalidInput { .. })
        ));
    }

    #[test]
    fn backup_kdf_reports_the_header_cost() {
        let (file, _) = backup_with_kdf(KdfParams::argon2id(524_289, 6, 8));
        assert_eq!(
            backup_kdf(file).unwrap(),
            KdfInfo {
                m_kib: 524_289,
                t: 6,
                p: 8
            }
        );
        // Above the format's own maximum, `read_header` already refuses it.
        let (file, _) = backup_with_kdf(KdfParams::argon2id(2_097_153, 3, 4));
        assert!(matches!(
            backup_kdf(file),
            Err(OpError::InvalidInput { .. })
        ));
        assert!(matches!(
            backup_kdf(b"nope".to_vec()),
            Err(OpError::Corrupted)
        ));
    }

    const KDBX31: &[u8] = include_bytes!("../../core/src/import/testdata/keepassxc-3.1.kdbx");

    /// The signature and header of a KDBX 4 file with an Argon2id KDF; no body.
    fn kdbx4_argon2(memory_bytes: u64, iterations: u64, lanes: u32) -> Vec<u8> {
        let uuid = [
            0x9e, 0x29, 0x8b, 0x19, 0x56, 0xdb, 0x47, 0x73, 0xb2, 0x3d, 0xfc, 0x3e, 0xc6, 0xf0,
            0xa1, 0xe6,
        ];
        let mut dict = vec![0x00, 0x01];
        for (key, value) in [
            ("$UUID", uuid.to_vec()),
            ("S", vec![3; 32]),
            ("M", memory_bytes.to_le_bytes().to_vec()),
            ("I", iterations.to_le_bytes().to_vec()),
            ("P", lanes.to_le_bytes().to_vec()),
        ] {
            dict.push(0x42);
            dict.extend((key.len() as i32).to_le_bytes());
            dict.extend(key.as_bytes());
            dict.extend((value.len() as i32).to_le_bytes());
            dict.extend(value);
        }
        dict.push(0);
        let mut out = KDBX31[..8].to_vec();
        out.extend([1, 0, 4, 0]);
        for (id, data) in [(4u8, vec![5u8; 32]), (11, dict), (0, vec![])] {
            out.push(id);
            out.extend((data.len() as u32).to_le_bytes());
            out.extend(data);
        }
        out
    }

    #[test]
    fn import_kdf_reports_the_kdbx_argon2_cost_before_the_kdf() {
        assert_eq!(
            import_kdf(kdbx4_argon2(64 << 20, 2, 2)).unwrap(),
            Some(KdfInfo {
                m_kib: 65_536,
                t: 2,
                p: 2
            })
        );
        // The edge the core accepts, then a header far above it (reported, not clamped to it).
        assert_eq!(
            import_kdf(kdbx4_argon2(512 << 20, 6, 4))
                .unwrap()
                .unwrap()
                .m_kib,
            524_288
        );
        assert_eq!(
            import_kdf(kdbx4_argon2(u64::MAX, u64::MAX, 4)).unwrap(),
            Some(KdfInfo {
                m_kib: u32::MAX,
                t: u32::MAX,
                p: 4
            })
        );
        // No memory to check: AES-KDF, and files that are not KeePass at all.
        assert_eq!(import_kdf(KDBX31.to_vec()).unwrap(), None);
        assert_eq!(import_kdf(b"a,b\n1,2".to_vec()).unwrap(), None);
        assert!(
            import_kdf(KDBX31[..10].to_vec()).is_err(),
            "truncated header"
        );
    }

    #[test]
    fn kdbx_above_the_ceiling_is_refused_with_a_clear_message_and_a_normal_one_imports() {
        match parse_import(kdbx4_argon2(1 << 30, 1, 4), Some("x".into()), None, 0) {
            Err(OpError::InvalidInput { reason }) => {
                assert!(reason.contains("too costly for this device"), "{reason}")
            }
            other => panic!("{other:?}"),
        }
        let out = parse_import(KDBX31.to_vec(), Some("prueba-kdbx".into()), None, 0).unwrap();
        assert_eq!(out.format, "keepass-kdbx");
        assert!(!out.items.is_empty());
    }

    #[test]
    fn local_header_above_the_mobile_ceiling_is_refused_before_the_kdf() {
        let sk = generate_secret_key().unwrap();
        let vault = Vault::create(PASSWORD.into(), sk.clone(), KdfProfile::Minimum).unwrap();
        let mut header: serde_json::Value =
            serde_json::from_str(&vault.header_json().unwrap()).unwrap();
        header["kdf"] = serde_json::to_value(KdfParams::argon2id(524_289, 6, 8)).unwrap();
        assert!(matches!(
            Vault::unlock(header.to_string(), PASSWORD.into(), sk),
            Err(OpError::KdfTooExpensive { m_kib: 524_289, .. })
        ));
    }

    #[test]
    fn secret_strings_cross_records_and_options() {
        let details = ItemDetailsRecord {
            fields: vec![FieldRecord {
                label: "x".into(),
                kind: FieldKindRecord::Concealed,
                value: "s3cret".into(),
            }],
            notes: "nota".into(),
            history: vec![PasswordChangeRecord {
                label: "x".into(),
                value: "old".into(),
                changed_at: 1,
            }],
        };
        let item: ItemDetails = details.clone().into();
        assert_eq!(item.fields[0].value, "s3cret");
        assert_eq!(item.notes, "nota");
        let back = ItemDetailsRecord::from(&item);
        assert_eq!(back.history[0].value.expose(), "old");
        assert!(!format!("{back:?}").contains("s3cret"));
        let none: Option<SecretString> = None;
        assert!(format!("{none:?}") == "None");
    }
}
