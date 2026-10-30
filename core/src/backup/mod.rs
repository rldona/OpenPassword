//! The `.opvault` backup file (docs/opvault-format.md).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::stream::{self, STREAM_NONCE_LEN};
use crate::crypto::{self, DOMAIN_WRAP, Key, SecretKey, aad, random_array};
use crate::encoding::hex_bytes;
use crate::vault::{EncryptedItem, UnlockedVault, VaultHeader, VaultId};
use crate::{Error, Result};

/// `"OPVAULT"` followed by the major format version.
pub const MAGIC: &[u8; 8] = b"OPVAULT\x01";
pub const FORMAT_VERSION: u32 = 1;
pub const MAX_HEADER_LEN: usize = 64 * 1024;

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

/// Serializes `items` into an encrypted backup of `vault`.
pub fn write(vault: &UnlockedVault, items: &[EncryptedItem], created_at: u64) -> Result<Vec<u8>> {
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
    })
    .map_err(|_| Error::InvalidInput("items are not serializable"))?;
    out.extend_from_slice(&stream::encrypt(&file_key, &stream_nonce, &body, &aad));
    Ok(out)
}

fn parse(bytes: &[u8]) -> Result<Parsed<'_>> {
    let fixed = MAGIC.len() + 4;
    if bytes.len() < fixed || !bytes.starts_with(b"OPVAULT") {
        return Err(Error::Malformed("not an .opvault file"));
    }
    if bytes[..MAGIC.len()] != MAGIC[..] {
        return Err(Error::UnsupportedVersion(u32::from(bytes[MAGIC.len() - 1])));
    }
    let header_len =
        u32::from_le_bytes(bytes[MAGIC.len()..fixed].try_into().expect("4 bytes")) as usize;
    if header_len > MAX_HEADER_LEN || bytes.len() < fixed + header_len {
        return Err(Error::Malformed("header length"));
    }
    let header: BackupHeader = serde_json::from_slice(&bytes[fixed..fixed + header_len])
        .map_err(|_| Error::Malformed("header JSON"))?;
    if header.format_version != FORMAT_VERSION {
        return Err(Error::UnsupportedVersion(header.format_version));
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
) -> Result<(UnlockedVault, Vec<EncryptedItem>)> {
    let parsed = parse(bytes)?;
    let vault = UnlockedVault::unlock(&parsed.header.vault, password, secret_key)?;
    let items = decrypt_body(&parsed, &vault)?;
    Ok((vault, items))
}

fn decrypt_body(parsed: &Parsed<'_>, vault: &UnlockedVault) -> Result<Vec<EncryptedItem>> {
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
    Ok(body.items)
}

/// Fuzzing hooks, compiled only with `--cfg fuzzing` (see `crate::fuzzing`).
#[cfg(fuzzing)]
pub mod fuzzing {
    use super::*;

    /// File key of [`seal_backup`]. A public constant, for tests only.
    const TEST_FILE_KEY: [u8; 32] = [4; 32];
    const TEST_NONCE: [u8; STREAM_NONCE_LEN] = [6; STREAM_NONCE_LEN];

    /// A backup of `vault` whose body is `body` (any bytes), sealed with the STREAM cipher and
    /// fixed keys, so that opening it reaches the JSON of the body. No KDF runs.
    pub fn seal_backup(vault: &UnlockedVault, body: &[u8]) -> Vec<u8> {
        let file_key = Key::from_bytes(TEST_FILE_KEY);
        let header = BackupHeader {
            format_version: FORMAT_VERSION,
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
        out.extend_from_slice(MAGIC);
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
    pub fn open_with_vault(bytes: &[u8], vault: &UnlockedVault) -> Result<Vec<EncryptedItem>> {
        decrypt_body(&parse(bytes)?, vault)
    }
}
