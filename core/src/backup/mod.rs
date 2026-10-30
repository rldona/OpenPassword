//! The `.opvault` backup file (docs/opvault-format.md).
//!
//! Version 2 adds encrypted image attachments. A v1 file has no attachments and keeps
//! opening; a reader that only knows v1 rejects v2 by its version byte instead of silently
//! dropping the images.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::stream::{self, STREAM_NONCE_LEN};
use crate::crypto::{self, DOMAIN_WRAP, Key, SecretKey, aad, random_array};
use crate::encoding::hex_bytes;
use crate::vault::{
    EncryptedAttachment, EncryptedItem, MAX_SEALED_ATTACHMENT_LEN, UnlockedVault, VaultHeader,
    VaultId,
};
use crate::{Error, Result};

/// `"OPVAULT"` followed by the major format version.
pub const MAGIC: &[u8; 8] = b"OPVAULT\x02";
pub const FORMAT_VERSION: u32 = 2;
pub const MAX_HEADER_LEN: usize = 64 * 1024;
/// Hard ceiling for a whole backup file. The app refuses to write or read anything bigger.
pub const MAX_FILE_LEN: usize = 64 * 1024 * 1024;
/// Oldest format this reader understands. It has no attachments.
pub const MIN_FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupHeader {
    pub format_version: u32,
    /// Unix seconds.
    pub created_at: u64,
    pub vault: VaultHeader,
    #[serde(with = "hex_bytes")]
    pub stream_nonce: [u8; STREAM_NONCE_LEN],
    #[serde(with = "hex_bytes")]
    pub wrapped_file_key: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct Body {
    items: Vec<EncryptedItem>,
    #[serde(default)]
    attachments: Vec<EncryptedAttachment>,
}

/// A parsed but still encrypted backup.
struct Parsed<'a> {
    header: BackupHeader,
    /// `magic ‖ header_len ‖ header`, authenticated by every body chunk.
    header_region: &'a [u8],
    body: &'a [u8],
}

fn file_key_aad(vault_id: &VaultId, nonce: &[u8; STREAM_NONCE_LEN]) -> Vec<u8> {
    aad(DOMAIN_WRAP, &[b"file_key", vault_id, nonce])
}

fn body_aad(header_region: &[u8]) -> [u8; 32] {
    Sha256::digest(header_region).into()
}

/// Serializes `items` and their `attachments` into an encrypted backup of `vault`.
///
/// Attachments whose item is not in `items` are dropped: they could never be opened again.
pub fn write(
    vault: &UnlockedVault,
    items: &[EncryptedItem],
    attachments: &[EncryptedAttachment],
    created_at: u64,
) -> Result<Vec<u8>> {
    let item_ids: HashSet<_> = items.iter().map(|item| item.id).collect();
    let mut seen = HashSet::new();
    let mut kept = Vec::with_capacity(attachments.len());
    for attachment in attachments {
        if !item_ids.contains(&attachment.item_id) {
            continue;
        }
        if !seen.insert((attachment.item_id, attachment.id)) {
            return Err(Error::InvalidInput("duplicate attachment"));
        }
        kept.push(attachment.clone());
    }

    let file_key = Key::generate()?;
    let stream_nonce = random_array::<STREAM_NONCE_LEN>()?;
    let header = BackupHeader {
        format_version: FORMAT_VERSION,
        created_at,
        vault: vault.header().clone(),
        stream_nonce,
        wrapped_file_key: crypto::wrap_key(
            vault.vault_key(),
            &file_key,
            &file_key_aad(vault.vault_id(), &stream_nonce),
        )?,
    };
    let header_json = serde_json::to_vec(&header)
        .map_err(|_| Error::InvalidInput("header is not serializable"))?;
    let header_len = u32::try_from(header_json.len()).expect("header is small");

    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&header_len.to_le_bytes());
    out.extend_from_slice(&header_json);
    let aad = body_aad(&out);

    let body = serde_json::to_vec(&Body {
        items: items.to_vec(),
        attachments: kept,
    })
    .map_err(|_| Error::InvalidInput("items are not serializable"))?;
    out.extend_from_slice(&stream::encrypt(&file_key, &stream_nonce, &body, &aad));
    if out.len() > MAX_FILE_LEN {
        return Err(Error::InvalidInput("backup too large"));
    }
    Ok(out)
}

fn parse(bytes: &[u8]) -> Result<Parsed<'_>> {
    if bytes.len() > MAX_FILE_LEN {
        return Err(Error::Malformed("file too large"));
    }
    let fixed = MAGIC.len() + 4;
    if bytes.len() < fixed || !bytes.starts_with(b"OPVAULT") {
        return Err(Error::Malformed("not an .opvault file"));
    }
    let version = u32::from(bytes[MAGIC.len() - 1]);
    if !(MIN_FORMAT_VERSION..=FORMAT_VERSION).contains(&version) {
        return Err(Error::UnsupportedVersion(version));
    }
    let header_len =
        u32::from_le_bytes(bytes[MAGIC.len()..fixed].try_into().expect("4 bytes")) as usize;
    if header_len > MAX_HEADER_LEN || bytes.len() < fixed + header_len {
        return Err(Error::Malformed("header length"));
    }
    let header: BackupHeader = serde_json::from_slice(&bytes[fixed..fixed + header_len])
        .map_err(|_| Error::Malformed("header JSON"))?;
    if header.format_version != version {
        return Err(Error::Malformed("format version mismatch"));
    }
    header.vault.kdf.check_bounds()?;
    Ok(Parsed {
        header,
        header_region: &bytes[..fixed + header_len],
        body: &bytes[fixed + header_len..],
    })
}

/// Reads the header without any key. Safe to show: it contains no user data.
pub fn read_header(bytes: &[u8]) -> Result<BackupHeader> {
    parse(bytes).map(|p| p.header)
}

/// Opens a backup with the master password and secret key.
pub fn open(
    bytes: &[u8],
    password: &str,
    secret_key: &SecretKey,
) -> Result<(UnlockedVault, Vec<EncryptedItem>, Vec<EncryptedAttachment>)> {
    let parsed = parse(bytes)?;
    let vault = UnlockedVault::unlock(&parsed.header.vault, password, secret_key)?;
    let (items, attachments) = decrypt_body(&parsed, &vault)?;
    Ok((vault, items, attachments))
}

type BodyParts = (Vec<EncryptedItem>, Vec<EncryptedAttachment>);

fn decrypt_body(parsed: &Parsed<'_>, vault: &UnlockedVault) -> Result<BodyParts> {
    let header = &parsed.header;
    let file_key = crypto::unwrap_key(
        vault.vault_key(),
        &header.wrapped_file_key,
        &file_key_aad(vault.vault_id(), &header.stream_nonce),
    )?;
    let plain = stream::decrypt(
        &file_key,
        &header.stream_nonce,
        parsed.body,
        &body_aad(parsed.header_region),
    )?;
    let body: Body = serde_json::from_slice(&plain).map_err(|_| Error::Malformed("body JSON"))?;
    if header.format_version == 1 && !body.attachments.is_empty() {
        return Err(Error::Malformed("attachments in a v1 backup"));
    }

    let item_ids: HashSet<_> = body.items.iter().map(|item| item.id).collect();
    let mut seen = HashSet::new();
    let mut attachments = Vec::with_capacity(body.attachments.len());
    for attachment in body.attachments {
        if attachment.data.len() > MAX_SEALED_ATTACHMENT_LEN {
            return Err(Error::Malformed("attachment too large"));
        }
        if !seen.insert((attachment.item_id, attachment.id)) {
            return Err(Error::Malformed("duplicate attachment"));
        }
        // An orphan could only come from a writer bug; keeping the rest of the backup is
        // more useful for recovery than rejecting the whole file.
        if item_ids.contains(&attachment.item_id) {
            attachments.push(attachment);
        }
    }
    Ok((body.items, attachments))
}

/// Fuzzing hooks, compiled only with `--cfg fuzzing` (see `crate::fuzzing`).
#[cfg(fuzzing)]
pub mod fuzzing {
    use super::*;

    /// File key of [`seal_backup`]. A public constant, for tests only.
    const TEST_FILE_KEY: [u8; 32] = [4; 32];
    const TEST_NONCE: [u8; STREAM_NONCE_LEN] = [6; STREAM_NONCE_LEN];

    /// A backup of `vault` with format `version` whose body is `body` (any bytes), sealed
    /// with the STREAM cipher and fixed keys, so that opening it reaches the JSON of the
    /// body. No KDF runs.
    pub fn seal_backup(vault: &UnlockedVault, body: &[u8], version: u32) -> Vec<u8> {
        let file_key = Key::from_bytes(TEST_FILE_KEY);
        let header = BackupHeader {
            format_version: version,
            created_at: 0,
            vault: vault.header().clone(),
            stream_nonce: TEST_NONCE,
            wrapped_file_key: crypto::seal_with_nonce(
                vault.vault_key(),
                &[8; crypto::NONCE_LEN],
                file_key.expose(),
                &file_key_aad(vault.vault_id(), &TEST_NONCE),
            ),
        };
        let header_json = serde_json::to_vec(&header).expect("header serializes");
        let mut out = Vec::new();
        out.extend_from_slice(b"OPVAULT");
        out.push(u8::try_from(version).unwrap_or(0));
        out.extend_from_slice(
            &u32::try_from(header_json.len())
                .expect("small")
                .to_le_bytes(),
        );
        out.extend_from_slice(&header_json);
        let aad = body_aad(&out);
        out.extend_from_slice(&stream::encrypt(&file_key, &TEST_NONCE, body, &aad));
        out
    }

    /// [`open`] with an already unlocked vault, skipping the KDF.
    pub fn open_with_vault(bytes: &[u8], vault: &UnlockedVault) -> Result<BodyParts> {
        decrypt_body(&parse(bytes)?, vault)
    }
}
