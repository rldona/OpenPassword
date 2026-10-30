//! Vault key hierarchy and per-item encryption (spec 3, 7 and 8).

pub(crate) mod attachment;
mod item;
mod padding;

use core::fmt;

use serde::{Deserialize, Serialize, de::DeserializeOwned};

pub use attachment::{
    AttachmentId, EncryptedAttachment, Image, ItemChange, MAX_IMAGE_BYTES, MAX_IMAGES_PER_ITEM,
    MAX_SEALED_ATTACHMENT_LEN, MAX_VAULT_ATTACHMENT_BYTES, MediaType, NewImage, PlainItem,
    new_attachment_id,
};
pub use item::{Field, FieldKind, Item, ItemDetails, ItemKind, ItemOverview, PasswordChange};

use crate::crypto::{
    self, DOMAIN_ITEM, DOMAIN_WRAP, KdfParams, Key, SecretKey, aad, derive_kek, random_array,
};
use crate::encoding::hex_bytes;
use crate::{Error, Result};

pub type VaultId = [u8; 16];
pub type ItemId = [u8; 16];

/// Everything needed to unlock a vault. Contains no user data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultHeader {
    #[serde(with = "hex_bytes")]
    pub vault_id: VaultId,
    pub kdf: KdfParams,
    #[serde(with = "hex_bytes")]
    pub salt: [u8; 32],
    #[serde(with = "hex_bytes")]
    pub secret_key_id: [u8; 4],
    #[serde(with = "hex_bytes")]
    pub wrapped_vault_key: Vec<u8>,
}

/// An item as stored on disk and in backups.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedItem {
    #[serde(with = "hex_bytes")]
    pub id: ItemId,
    pub revision: u64,
    #[serde(with = "hex_bytes")]
    pub wrapped_item_key: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub overview: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub details: Vec<u8>,
}

/// A vault whose key is in memory. Dropping it wipes the key.
pub struct UnlockedVault {
    header: VaultHeader,
    vault_key: Key,
}

impl fmt::Debug for UnlockedVault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnlockedVault")
            .field("vault_id", &hex::encode(self.header.vault_id))
            .finish_non_exhaustive()
    }
}

fn vault_key_aad(vault_id: &VaultId) -> Vec<u8> {
    aad(DOMAIN_WRAP, &[b"vault_key", vault_id])
}

fn item_key_aad(vault_id: &VaultId, item_id: &ItemId) -> Vec<u8> {
    aad(DOMAIN_WRAP, &[b"item_key", vault_id, item_id])
}

fn item_part_aad(part: &[u8], vault_id: &VaultId, item_id: &ItemId, revision: u64) -> Vec<u8> {
    aad(
        DOMAIN_ITEM,
        &[part, vault_id, item_id, &revision.to_le_bytes()],
    )
}

fn check_password(password: &str) -> Result<()> {
    if password.is_empty() {
        return Err(Error::InvalidInput("the master password must not be empty"));
    }
    Ok(())
}

fn same_ids(a: &[AttachmentId], b: &[AttachmentId]) -> bool {
    let mut a = a.to_vec();
    let mut b = b.to_vec();
    a.sort_unstable();
    b.sort_unstable();
    a == b
}

impl UnlockedVault {
    /// Creates a new vault with a random vault key.
    pub fn create(password: &str, secret_key: &SecretKey, kdf: KdfParams) -> Result<Self> {
        let header = VaultHeader {
            vault_id: random_array()?,
            kdf,
            salt: [0; 32],
            secret_key_id: [0; 4],
            wrapped_vault_key: Vec::new(),
        };
        let mut vault = UnlockedVault {
            header,
            vault_key: Key::generate()?,
        };
        vault.rekey(password, secret_key, kdf)?;
        Ok(vault)
    }

    /// Unlocks with the master password and secret key.
    pub fn unlock(header: &VaultHeader, password: &str, secret_key: &SecretKey) -> Result<Self> {
        if header.secret_key_id != secret_key.id() {
            return Err(Error::WrongSecretKey);
        }
        let kek = derive_kek(password, secret_key, &header.salt, &header.kdf)?;
        let vault_key = crypto::unwrap_key(
            &kek,
            &header.wrapped_vault_key,
            &vault_key_aad(&header.vault_id),
        )
        .map_err(|_| Error::WrongCredentials)?;
        Ok(UnlockedVault {
            header: header.clone(),
            vault_key,
        })
    }

    /// Unlocks with a vault key released by the platform keystore (biometric unlock).
    /// A wrong key is not detected here: decrypting any item will fail.
    pub fn unlock_with_vault_key(header: &VaultHeader, vault_key: Key) -> Self {
        UnlockedVault {
            header: header.clone(),
            vault_key,
        }
    }

    pub fn header(&self) -> &VaultHeader {
        &self.header
    }

    pub fn vault_id(&self) -> &VaultId {
        &self.header.vault_id
    }

    /// The vault key, to be sealed by the platform keystore for biometric unlock.
    pub fn vault_key(&self) -> &Key {
        &self.vault_key
    }

    /// Changes the master password and/or secret key. Items are not re-encrypted.
    pub fn rekey(&mut self, password: &str, secret_key: &SecretKey, kdf: KdfParams) -> Result<()> {
        check_password(password)?;
        kdf.check_for_new_vault()?;
        let salt = random_array()?;
        let kek = derive_kek(password, secret_key, &salt, &kdf)?;
        let wrapped =
            crypto::wrap_key(&kek, &self.vault_key, &vault_key_aad(&self.header.vault_id))?;
        self.header.kdf = kdf;
        self.header.salt = salt;
        self.header.secret_key_id = secret_key.id();
        self.header.wrapped_vault_key = wrapped;
        Ok(())
    }

    /// Encrypts a new item under a fresh item key. Revision starts at 1.
    pub fn encrypt_item(&self, item: &Item) -> Result<EncryptedItem> {
        Ok(self.encrypt_item_with_images(item, Vec::new())?.item)
    }

    /// Encrypts a new item and its new images. Revision starts at 1.
    pub fn encrypt_item_with_images(
        &self,
        item: &Item,
        images: Vec<NewImage>,
    ) -> Result<ItemChange> {
        let current = item.details.image_ids()?;
        self.check_images(&[], &current, &images)?;
        let id: ItemId = random_array()?;
        let item_key = Key::generate()?;
        let wrapped_item_key = crypto::wrap_key(
            &self.vault_key,
            &item_key,
            &item_key_aad(self.vault_id(), &id),
        )?;
        let encrypted = self.seal_item(id, 1, wrapped_item_key, &item_key, item)?;
        let added = images
            .iter()
            .map(|image| attachment::seal(self.vault_id(), &id, &item_key, image))
            .collect::<Result<Vec<_>>>()?;
        Ok(ItemChange {
            item: encrypted,
            added,
            removed: Vec::new(),
        })
    }

    /// Re-encrypts an edited item: same id and item key, next revision.
    ///
    /// The password history is computed here from the previous revision, not taken from
    /// `item`, so a caller that forgets it cannot erase it. Changes are dated `updated_at`.
    pub fn update_item(&self, existing: &EncryptedItem, item: &Item) -> Result<EncryptedItem> {
        let item_key = self.item_key(existing)?;
        let previous: ItemDetails =
            self.open_part(&item_key, b"details", existing, &existing.details)?;
        let previous_ids = previous.image_ids()?;
        let current = item.details.image_ids()?;
        if !same_ids(&previous_ids, &current) {
            return Err(Error::InvalidInput("image set changed"));
        }
        Ok(self.update_item_with_images(existing, item, Vec::new())?.item)
    }

    /// Re-encrypts an edited item and seals the images added in this edit.
    ///
    /// Images are immutable: adding one seals it under a new id, removing one lists it in
    /// `removed`. The caller writes the item, the added attachments and the removals in one
    /// transaction.
    pub fn update_item_with_images(
        &self,
        existing: &EncryptedItem,
        item: &Item,
        images: Vec<NewImage>,
    ) -> Result<ItemChange> {
        let item_key = self.item_key(existing)?;
        let previous: ItemDetails =
            self.open_part(&item_key, b"details", existing, &existing.details)?;
        let previous_ids = previous.image_ids()?;
        let current = item.details.image_ids()?;
        self.check_images(&previous_ids, &current, &images)?;

        let mut item = item.clone();
        item.details
            .record_changes(&previous, item.overview.kind, item.overview.updated_at);
        let revision = existing
            .revision
            .checked_add(1)
            .ok_or(Error::Malformed("revision overflow"))?;
        let encrypted = self.seal_item(
            existing.id,
            revision,
            existing.wrapped_item_key.clone(),
            &item_key,
            &item,
        )?;
        let added = images
            .iter()
            .map(|image| attachment::seal(self.vault_id(), &existing.id, &item_key, image))
            .collect::<Result<Vec<_>>>()?;
        let removed = previous_ids
            .iter()
            .filter(|id| !current.contains(id))
            .copied()
            .collect();
        Ok(ItemChange {
            item: encrypted,
            added,
            removed,
        })
    }

    /// Checks that the image fields and the images to seal describe the same set, and that
    /// every new image is a metadata-free JPEG.
    fn check_images(
        &self,
        previous: &[AttachmentId],
        current: &[AttachmentId],
        images: &[NewImage],
    ) -> Result<()> {
        if current.len() > MAX_IMAGES_PER_ITEM {
            return Err(Error::InvalidInput("too many images"));
        }
        let mut seen = Vec::with_capacity(images.len());
        for image in images {
            if seen.contains(&image.id) {
                return Err(Error::InvalidInput("duplicate attachment"));
            }
            if !current.contains(&image.id) {
                return Err(Error::InvalidInput("image data without field"));
            }
            if previous.contains(&image.id) {
                return Err(Error::InvalidInput("image id already used"));
            }
            seen.push(image.id);
            attachment::check_jpeg(&image.jpeg)?;
        }
        for id in current {
            if !previous.contains(id) && !images.iter().any(|image| image.id == *id) {
                return Err(Error::InvalidInput("image field without data"));
            }
        }
        Ok(())
    }

    /// Decrypts one image. The returned bytes are wiped when dropped.
    pub fn decrypt_image(
        &self,
        item: &EncryptedItem,
        attachment: &EncryptedAttachment,
    ) -> Result<Image> {
        let key = self.item_key(item)?;
        attachment::open(self.vault_id(), &item.id, &key, attachment)
    }

    /// Ids of the images the item references, in field order.
    pub fn image_ids(&self, item: &EncryptedItem) -> Result<Vec<AttachmentId>> {
        self.decrypt_details(item)?.image_ids()
    }

    /// Decrypts an item and the images it references, to move it to another vault.
    ///
    /// Unreferenced attachments are ignored; a reference without an attachment is kept.
    pub fn open_item_with_images(
        &self,
        item: &EncryptedItem,
        attachments: &[EncryptedAttachment],
    ) -> Result<PlainItem> {
        let key = self.item_key(item)?;
        let plain = Item {
            overview: self.open_part(&key, b"overview", item, &item.overview)?,
            details: self.open_part(&key, b"details", item, &item.details)?,
        };
        let ids = plain.details.image_ids()?;
        let mut images = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(attachment) = attachments
                .iter()
                .find(|a| a.id == id && a.item_id == item.id)
            {
                images.push((
                    id,
                    attachment::open(self.vault_id(), &item.id, &key, attachment)?,
                ));
            }
        }
        Ok(PlainItem {
            item: plain,
            images,
        })
    }

    /// Moves a plaintext item and its images into this vault under a new id and key.
    pub fn adopt_item(&self, plain: &PlainItem) -> Result<ItemChange> {
        let id: ItemId = random_array()?;
        let item_key = Key::generate()?;
        let wrapped_item_key = crypto::wrap_key(
            &self.vault_key,
            &item_key,
            &item_key_aad(self.vault_id(), &id),
        )?;
        let encrypted = self.seal_item(id, 1, wrapped_item_key, &item_key, &plain.item)?;
        let referenced = plain.item.details.image_ids()?;
        let added = plain
            .images
            .iter()
            .filter(|(attachment_id, _)| referenced.contains(attachment_id))
            .map(|(attachment_id, image)| {
                attachment::seal_bytes(self.vault_id(), &id, &item_key, *attachment_id, image)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(ItemChange {
            item: encrypted,
            added,
            removed: Vec::new(),
        })
    }

    pub fn decrypt_overview(&self, item: &EncryptedItem) -> Result<ItemOverview> {
        let key = self.item_key(item)?;
        self.open_part(&key, b"overview", item, &item.overview)
    }

    pub fn decrypt_details(&self, item: &EncryptedItem) -> Result<ItemDetails> {
        let key = self.item_key(item)?;
        self.open_part(&key, b"details", item, &item.details)
    }

    pub fn decrypt_item(&self, item: &EncryptedItem) -> Result<Item> {
        let key = self.item_key(item)?;
        Ok(Item {
            overview: self.open_part(&key, b"overview", item, &item.overview)?,
            details: self.open_part(&key, b"details", item, &item.details)?,
        })
    }

    fn item_key(&self, item: &EncryptedItem) -> Result<Key> {
        crypto::unwrap_key(
            &self.vault_key,
            &item.wrapped_item_key,
            &item_key_aad(self.vault_id(), &item.id),
        )
    }

    fn seal_item(
        &self,
        id: ItemId,
        revision: u64,
        wrapped_item_key: Vec<u8>,
        item_key: &Key,
        item: &Item,
    ) -> Result<EncryptedItem> {
        Ok(EncryptedItem {
            id,
            revision,
            overview: self.seal_part(item_key, b"overview", &id, revision, &item.overview)?,
            details: self.seal_part(item_key, b"details", &id, revision, &item.details)?,
            wrapped_item_key,
        })
    }

    fn seal_part<T: Serialize>(
        &self,
        key: &Key,
        part: &[u8],
        id: &ItemId,
        revision: u64,
        value: &T,
    ) -> Result<Vec<u8>> {
        let json = zeroize::Zeroizing::new(
            serde_json::to_vec(value)
                .map_err(|_| Error::InvalidInput("item is not serializable"))?,
        );
        let padded = padding::pad(&json)?;
        crypto::seal(
            key,
            &padded,
            &item_part_aad(part, self.vault_id(), id, revision),
        )
    }

    fn open_part<T: DeserializeOwned>(
        &self,
        key: &Key,
        part: &[u8],
        item: &EncryptedItem,
        sealed: &[u8],
    ) -> Result<T> {
        let aad = item_part_aad(part, self.vault_id(), &item.id, item.revision);
        let padded = crypto::open(key, sealed, &aad)?;
        let json = padding::unpad(&padded)?;
        serde_json::from_slice(json).map_err(|_| Error::Malformed("item JSON"))
    }
}

/// Fuzzing hook, compiled only with `--cfg fuzzing` (see `crate::fuzzing`).
#[cfg(fuzzing)]
pub mod fuzzing {
    use super::*;
    use crate::crypto::{NONCE_LEN, seal_with_nonce};

    /// Item key of [`seal_item_part`]. A public constant, for tests only.
    const TEST_ITEM_KEY: [u8; 32] = [9; 32];

    /// Builds an item whose `overview` and `details` are both `plaintext` (any bytes) padded
    /// and sealed with fixed keys and nonces, so decrypting reaches `unpad` and the JSON parsers.
    pub fn seal_item_part(vault: &UnlockedVault, plaintext: &[u8]) -> Result<EncryptedItem> {
        let id: ItemId = [2; 16];
        let revision = 1;
        let item_key = Key::from_bytes(TEST_ITEM_KEY);
        let nonce = [5; NONCE_LEN];
        let padded = padding::pad(plaintext)?;
        let part = |name: &[u8]| {
            seal_with_nonce(
                &item_key,
                &nonce,
                &padded,
                &item_part_aad(name, vault.vault_id(), &id, revision),
            )
        };
        Ok(EncryptedItem {
            id,
            revision,
            wrapped_item_key: seal_with_nonce(
                vault.vault_key(),
                &nonce,
                item_key.expose(),
                &item_key_aad(vault.vault_id(), &id),
            ),
            overview: part(b"overview"),
            details: part(b"details"),
        })
    }
}
