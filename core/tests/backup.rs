mod common;

use common::*;
use op_core::backup::{self, MAGIC};
use op_core::vault::{Field, FieldKind};
use op_core::{Error, SecretKey};

const CHUNK: usize = 64 * 1024 + 16;

fn sample_backup() -> (Vec<u8>, Vec<op_core::EncryptedItem>) {
    let vault = new_vault();
    let items = vec![
        vault.encrypt_item(&card()).unwrap(),
        vault.encrypt_item(&login()).unwrap(),
    ];
    (backup::write(&vault, &items, 1_793_257_200).unwrap(), items)
}

#[test]
fn roundtrip() {
    let (file, items) = sample_backup();
    let (vault, restored) = backup::open(&file, PASSWORD, &secret_key()).unwrap();
    assert_eq!(restored, items);
    assert_eq!(vault.decrypt_item(&restored[0]).unwrap(), card());
    assert_eq!(vault.decrypt_item(&restored[1]).unwrap(), login());
}

#[test]
fn empty_vault_roundtrip() {
    let vault = new_vault();
    let file = backup::write(&vault, &[], 0).unwrap();
    let (_, restored) = backup::open(&file, PASSWORD, &secret_key()).unwrap();
    assert!(restored.is_empty());
}

#[test]
fn header_has_no_user_data() {
    let (file, _) = sample_backup();
    let header = backup::read_header(&file).unwrap();
    assert_eq!(header.format_version, 1);
    for needle in ["Visa", "Google", "4940192355674821", "raul", "items"] {
        assert!(
            !file.windows(needle.len()).any(|w| w == needle.as_bytes()),
            "{needle}"
        );
    }
}

#[test]
fn wrong_credentials() {
    let (file, _) = sample_backup();
    assert_eq!(
        backup::open(&file, "otra", &secret_key()).unwrap_err(),
        Error::WrongCredentials
    );
    let other = SecretKey::generate().unwrap();
    assert_eq!(
        backup::open(&file, PASSWORD, &other).unwrap_err(),
        Error::WrongSecretKey
    );
}

#[test]
fn header_tampering_is_detected() {
    let (file, _) = sample_backup();
    let header_len = u32::from_le_bytes(file[8..12].try_into().unwrap()) as usize;
    let json = String::from_utf8(file[12..12 + header_len].to_vec()).unwrap();
    // Same length, different value: only authentication can catch it.
    let tampered_json = json.replace("\"created_at\":1793257200", "\"created_at\":1793257201");
    assert_ne!(json, tampered_json);
    let mut tampered = file.clone();
    tampered[12..12 + header_len].copy_from_slice(tampered_json.as_bytes());
    assert_eq!(
        backup::open(&tampered, PASSWORD, &secret_key()).unwrap_err(),
        Error::Decrypt
    );
}

#[test]
fn body_tampering_and_truncation_are_detected() {
    let (file, _) = sample_backup();
    let mut flipped = file.clone();
    *flipped.last_mut().unwrap() ^= 1;
    assert!(backup::open(&flipped, PASSWORD, &secret_key()).is_err());
    assert!(backup::open(&file[..file.len() - 1], PASSWORD, &secret_key()).is_err());
}

#[test]
fn multi_chunk_backup_and_boundary_truncation() {
    let vault = new_vault();
    let mut big = card();
    big.details.fields.push(Field::new(
        "Notas largas",
        FieldKind::Text,
        "x".repeat(300_000),
    ));
    let items = vec![vault.encrypt_item(&big).unwrap()];
    let file = backup::write(&vault, &items, 0).unwrap();
    let (_, restored) = backup::open(&file, PASSWORD, &secret_key()).unwrap();
    assert_eq!(restored, items);

    let header_end = 12 + u32::from_le_bytes(file[8..12].try_into().unwrap()) as usize;
    let cut = header_end + 2 * CHUNK;
    assert!(file.len() > cut + 16);
    assert_eq!(
        backup::open(&file[..cut], PASSWORD, &secret_key()).unwrap_err(),
        Error::Decrypt
    );
}

#[test]
fn rejects_other_files_and_versions() {
    assert!(matches!(
        backup::read_header(b"PK\x03\x04 not a backup"),
        Err(Error::Malformed(_))
    ));
    let (mut file, _) = sample_backup();
    file[MAGIC.len() - 1] = 2;
    assert_eq!(
        backup::read_header(&file).unwrap_err(),
        Error::UnsupportedVersion(2)
    );
}

#[test]
fn oversized_kdf_in_header_is_rejected_before_derivation() {
    let (file, _) = sample_backup();
    let header_len = u32::from_le_bytes(file[8..12].try_into().unwrap()) as usize;
    let json = String::from_utf8(file[12..12 + header_len].to_vec()).unwrap();
    let evil = json.replace("\"m_kib\":256", "\"m_kib\":99999999");
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&(evil.len() as u32).to_le_bytes());
    out.extend_from_slice(evil.as_bytes());
    out.extend_from_slice(&file[12 + header_len..]);
    assert!(matches!(
        backup::read_header(&out),
        Err(Error::KdfParams(_))
    ));
}
