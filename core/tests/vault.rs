mod common;

use common::*;
use op_core::{Error, KdfParams, SecretKey, UnlockedVault};

#[test]
fn create_and_unlock() {
    let vault = new_vault();
    let reopened = UnlockedVault::unlock(vault.header(), PASSWORD, &secret_key()).unwrap();
    assert_eq!(reopened.vault_key().expose(), vault.vault_key().expose());
}

#[test]
fn wrong_password_is_rejected() {
    let vault = new_vault();
    let err = UnlockedVault::unlock(vault.header(), "correct horse battery stapl", &secret_key());
    assert_eq!(err.unwrap_err(), Error::WrongCredentials);
}

#[test]
fn wrong_secret_key_is_detected_before_kdf() {
    let vault = new_vault();
    let other = SecretKey::generate().unwrap();
    let err = UnlockedVault::unlock(vault.header(), PASSWORD, &other);
    assert_eq!(err.unwrap_err(), Error::WrongSecretKey);
}

#[test]
fn password_is_nfkd_normalized() {
    let composed = "Contrase\u{00f1}a";
    let decomposed = "Contrasen\u{0303}a";
    let vault = UnlockedVault::create(composed, &secret_key(), FAST).unwrap();
    assert!(UnlockedVault::unlock(vault.header(), decomposed, &secret_key()).is_ok());
}

#[test]
fn empty_password_is_rejected() {
    let err = UnlockedVault::create("", &secret_key(), FAST).unwrap_err();
    assert_eq!(
        err,
        Error::InvalidInput("the master password must not be empty")
    );
}

#[test]
fn kdf_cost_above_maximum_is_rejected() {
    let mut vault = new_vault();
    let mut header = vault.header().clone();
    header.kdf = KdfParams::argon2id(KdfParams::MAXIMUM.m_kib * 2, 3, 4);
    assert!(matches!(
        UnlockedVault::unlock(&header, PASSWORD, &secret_key()),
        Err(Error::KdfParams(_))
    ));
    assert!(vault.rekey(PASSWORD, &secret_key(), header.kdf).is_err());
}

#[test]
fn item_roundtrip() {
    let vault = new_vault();
    let encrypted = vault.encrypt_item(&card()).unwrap();
    assert_eq!(encrypted.revision, 1);
    assert_eq!(vault.decrypt_item(&encrypted).unwrap(), card());
    assert_eq!(vault.decrypt_overview(&encrypted).unwrap(), card().overview);
}

#[test]
fn ciphertext_does_not_contain_plaintext() {
    let vault = new_vault();
    let encrypted = vault.encrypt_item(&card()).unwrap();
    // Search the raw ciphertext bytes, not their hex form, where short digit
    // strings would appear by chance.
    let stored = [
        encrypted.wrapped_item_key.as_slice(),
        &encrypted.overview,
        &encrypted.details,
    ]
    .concat();
    for needle in ["Visa BBVA", "4940192355674821", "RAÚL LÓPEZ", "card_number"] {
        assert!(
            !stored.windows(needle.len()).any(|w| w == needle.as_bytes()),
            "{needle}"
        );
    }
}

#[test]
fn update_keeps_id_and_bumps_revision() {
    let vault = new_vault();
    let v1 = vault.encrypt_item(&card()).unwrap();
    let mut edited = card();
    edited.overview.title = "Visa BBVA (nueva)".into();
    let v2 = vault.update_item(&v1, &edited).unwrap();
    assert_eq!(v2.id, v1.id);
    assert_eq!(v2.revision, 2);
    assert_eq!(v2.wrapped_item_key, v1.wrapped_item_key);
    assert_ne!(v2.overview, v1.overview);
    assert_eq!(vault.decrypt_item(&v2).unwrap(), edited);
}

#[test]
fn rekey_keeps_items_readable() {
    let mut vault = new_vault();
    let encrypted = vault.encrypt_item(&login()).unwrap();
    let new_sk = SecretKey::generate().unwrap();
    vault
        .rekey("una frase de paso nueva", &new_sk, FAST)
        .unwrap();

    let reopened =
        UnlockedVault::unlock(vault.header(), "una frase de paso nueva", &new_sk).unwrap();
    assert_eq!(reopened.decrypt_item(&encrypted).unwrap(), login());
    assert_eq!(
        UnlockedVault::unlock(vault.header(), PASSWORD, &secret_key()).unwrap_err(),
        Error::WrongSecretKey
    );
}

#[test]
fn biometric_unlock_with_vault_key() {
    let vault = new_vault();
    let encrypted = vault.encrypt_item(&card()).unwrap();
    let released = op_core::Key::from_bytes(*vault.vault_key().expose());
    let reopened = UnlockedVault::unlock_with_vault_key(vault.header(), released);
    assert_eq!(reopened.decrypt_item(&encrypted).unwrap(), card());

    let wrong =
        UnlockedVault::unlock_with_vault_key(vault.header(), op_core::Key::generate().unwrap());
    assert_eq!(wrong.decrypt_item(&encrypted).unwrap_err(), Error::Decrypt);
}

#[test]
fn flipping_any_byte_is_detected() {
    let vault = new_vault();
    let encrypted = vault.encrypt_item(&card()).unwrap();
    for field in 0..3 {
        let len = [
            &encrypted.wrapped_item_key,
            &encrypted.overview,
            &encrypted.details,
        ][field]
            .len();
        for i in (0..len).step_by(7) {
            let mut tampered = encrypted.clone();
            let target = match field {
                0 => &mut tampered.wrapped_item_key,
                1 => &mut tampered.overview,
                _ => &mut tampered.details,
            };
            target[i] ^= 0x01;
            assert!(
                vault.decrypt_item(&tampered).is_err(),
                "field {field} byte {i}"
            );
        }
    }
}

#[test]
fn parts_cannot_be_swapped_between_items() {
    let vault = new_vault();
    let a = vault.encrypt_item(&card()).unwrap();
    let b = vault.encrypt_item(&login()).unwrap();

    let mut mixed = a.clone();
    mixed.details = b.details.clone();
    assert_eq!(vault.decrypt_details(&mixed).unwrap_err(), Error::Decrypt);

    let mut stolen_key = b.clone();
    stolen_key.wrapped_item_key = a.wrapped_item_key.clone();
    assert_eq!(
        vault.decrypt_overview(&stolen_key).unwrap_err(),
        Error::Decrypt
    );
}

#[test]
fn parts_cannot_be_mixed_across_revisions() {
    let vault = new_vault();
    let v1 = vault.encrypt_item(&card()).unwrap();
    let v2 = vault.update_item(&v1, &login()).unwrap();

    let mut mixed = v2.clone();
    mixed.details = v1.details.clone();
    assert_eq!(vault.decrypt_details(&mixed).unwrap_err(), Error::Decrypt);

    let mut relabeled = v1.clone();
    relabeled.revision = 2;
    assert_eq!(
        vault.decrypt_overview(&relabeled).unwrap_err(),
        Error::Decrypt
    );
}

#[test]
fn overview_and_details_cannot_be_swapped() {
    let vault = new_vault();
    let mut item = vault.encrypt_item(&card()).unwrap();
    core::mem::swap(&mut item.overview, &mut item.details);
    assert!(vault.decrypt_overview(&item).is_err());
}

#[test]
fn items_from_another_vault_do_not_open() {
    let a = new_vault();
    let b = new_vault();
    let item = a.encrypt_item(&card()).unwrap();
    assert!(b.decrypt_item(&item).is_err());
}

#[test]
fn debug_output_is_redacted() {
    let vault = new_vault();
    let shown = format!("{vault:?} {:?} {:?}", card(), vault.vault_key());
    assert!(!shown.contains("Visa") && !shown.contains("4821"));
    assert!(shown.contains("<redacted>"));
}
