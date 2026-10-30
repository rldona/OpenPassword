//! Golden vectors for format v1 (`tests/vectors/op-v1.json`).
//!
//! They pin every byte of the v1 format. If a code change breaks them, the
//! change is incompatible with existing vaults and backups: bump the format
//! version instead of regenerating. Other implementations (Kotlin, Swift)
//! must pass the same file.
//!
//! Regenerate only when creating a new format version:
//! `cargo test -p op-core --test vectors -- --ignored regenerate`

mod common;

use common::*;
use op_core::crypto::{aad, derive_kek};
use op_core::{EncryptedItem, Item, KdfParams, SecretKey, UnlockedVault, VaultHeader, backup};
use serde_json::{Value, json};

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/op-v1.json");

fn load() -> Value {
    serde_json::from_str(&std::fs::read_to_string(PATH).expect("vector file")).unwrap()
}

fn unhex(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn aad_cases() -> Vec<(&'static str, Vec<Vec<u8>>)> {
    vec![
        ("op/wrap/v1", vec![b"vault_key".to_vec(), vec![0xAA; 16]]),
        (
            "op/item/v1",
            vec![
                b"overview".to_vec(),
                vec![1; 16],
                vec![2; 16],
                7u64.to_le_bytes().to_vec(),
            ],
        ),
        ("op/empty", vec![]),
        ("op/empty-part", vec![vec![]]),
    ]
}

fn secret_key_cases() -> Vec<[u8; 16]> {
    vec![[0; 16], [0xFF; 16], *secret_key().expose()]
}

fn kek_cases() -> Vec<(&'static str, KdfParams)> {
    vec![
        (PASSWORD, FAST),
        ("Contrase\u{00f1}a de 2026", FAST),
        ("🔐 emoji y espacios  ", FAST),
        (PASSWORD, KdfParams::MINIMUM),
    ]
}

#[test]
fn aad_encoding() {
    let v = load();
    let expected = v["aad"].as_array().unwrap();
    for (case, (domain, parts)) in expected.iter().zip(aad_cases()) {
        let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        assert_eq!(case["domain"], domain);
        assert_eq!(aad(domain, &refs), unhex(&case["expected"]), "{domain}");
    }
}

#[test]
fn secret_key_encoding() {
    let v = load();
    for (case, bytes) in v["secret_keys"]
        .as_array()
        .unwrap()
        .iter()
        .zip(secret_key_cases())
    {
        let key = SecretKey::from_bytes(bytes);
        assert_eq!(unhex(&case["bytes"]), bytes);
        assert_eq!(key.to_display().as_str(), case["display"].as_str().unwrap());
        assert_eq!(key.id().to_vec(), unhex(&case["id"]));
        assert_eq!(
            SecretKey::parse(case["display"].as_str().unwrap()).unwrap(),
            key
        );
    }
}

#[test]
fn kek_derivation() {
    let v = load();
    for case in v["kek"].as_array().unwrap() {
        let sk = SecretKey::parse(case["secret_key"].as_str().unwrap()).unwrap();
        let salt: [u8; 32] = unhex(&case["salt"]).try_into().unwrap();
        let kdf: KdfParams = serde_json::from_value(case["kdf"].clone()).unwrap();
        let kek = derive_kek(case["password"].as_str().unwrap(), &sk, &salt, &kdf).unwrap();
        assert_eq!(kek.expose().to_vec(), unhex(&case["kek"]));
    }
}

#[test]
fn stored_items_decrypt() {
    let v = load();
    let case = &v["vault"];
    let sk = SecretKey::parse(case["secret_key"].as_str().unwrap()).unwrap();
    let header: VaultHeader = serde_json::from_value(case["header"].clone()).unwrap();
    let vault = UnlockedVault::unlock(&header, case["password"].as_str().unwrap(), &sk).unwrap();
    for entry in case["items"].as_array().unwrap() {
        let encrypted: EncryptedItem = serde_json::from_value(entry["encrypted"].clone()).unwrap();
        let expected: Item = serde_json::from_value(entry["plaintext"].clone()).unwrap();
        assert_eq!(vault.decrypt_item(&encrypted).unwrap(), expected);
    }
}

#[test]
fn stored_backup_opens() {
    let v = load();
    let case = &v["backup"];
    let sk = SecretKey::parse(case["secret_key"].as_str().unwrap()).unwrap();
    let file = unhex(&case["file"]);
    let (vault, items, attachments) = backup::open(&file, case["password"].as_str().unwrap(), &sk).unwrap();
    assert!(attachments.is_empty());
    let titles: Vec<String> = items
        .iter()
        .map(|i| vault.decrypt_overview(i).unwrap().title.clone())
        .collect();
    assert_eq!(serde_json::to_value(&titles).unwrap(), case["titles"]);
}

#[test]
#[ignore = "v1 is frozen: the writer only emits v2"]
fn regenerate() {
    let aad_json: Vec<Value> = aad_cases()
        .into_iter()
        .map(|(domain, parts)| {
            let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
            json!({
                "domain": domain,
                "parts": parts.iter().map(hex::encode).collect::<Vec<_>>(),
                "expected": hex::encode(aad(domain, &refs)),
            })
        })
        .collect();

    let sk_json: Vec<Value> = secret_key_cases()
        .into_iter()
        .map(|bytes| {
            let key = SecretKey::from_bytes(bytes);
            json!({
                "bytes": hex::encode(bytes),
                "display": key.to_display().as_str(),
                "id": hex::encode(key.id()),
            })
        })
        .collect();

    let sk = secret_key();
    let kek_json: Vec<Value> = kek_cases()
        .into_iter()
        .enumerate()
        .map(|(i, (password, kdf))| {
            let salt = [i as u8 + 1; 32];
            let kek = derive_kek(password, &sk, &salt, &kdf).unwrap();
            json!({
                "password": password,
                "secret_key": sk.to_display().as_str(),
                "salt": hex::encode(salt),
                "kdf": kdf,
                "kek": hex::encode(kek.expose()),
            })
        })
        .collect();

    let vault = new_vault();
    let card_v1 = vault.encrypt_item(&card()).unwrap();
    let mut edited = card();
    edited.overview.updated_at += 60;
    edited.details.notes = "Renovada en agosto.".into();
    let card_v2 = vault.update_item(&card_v1, &edited).unwrap();
    let login_v1 = vault.encrypt_item(&login()).unwrap();
    let items_json: Vec<Value> = [(&card_v2, &edited), (&login_v1, &login())]
        .into_iter()
        .map(|(enc, plain)| json!({ "encrypted": enc, "plaintext": plain }))
        .collect();

    // v1 is frozen: the writer only emits v2 now, so the stored v1 backup stays as it is.
    let file = unhex(&load()["backup"]["file"]);

    let out = json!({
        "format": "op-v1",
        "description": "Golden vectors for OpenPassword format v1. See docs/crypto-spec.md. Test data only: these keys protect nothing.",
        "aad": aad_json,
        "secret_keys": sk_json,
        "kek": kek_json,
        "vault": {
            "password": PASSWORD,
            "secret_key": sk.to_display().as_str(),
            "header": vault.header(),
            "items": items_json,
        },
        "backup": {
            "password": PASSWORD,
            "secret_key": sk.to_display().as_str(),
            "titles": ["Visa BBVA", "Google"],
            "file": hex::encode(file),
        },
    });
    std::fs::write(PATH, serde_json::to_string_pretty(&out).unwrap() + "\n").unwrap();
}
