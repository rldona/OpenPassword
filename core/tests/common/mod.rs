#![allow(dead_code)]

use op_core::vault::{Field, FieldKind, Item, ItemDetails, ItemKind, ItemOverview};
use op_core::{KdfParams, SecretKey, UnlockedVault};

/// Cheap Argon2id cost so tests run fast. Below the minimum: tests only.
pub const FAST: KdfParams = KdfParams::argon2id(256, 1, 1);
pub const PASSWORD: &str = "correct horse battery staple";

pub fn secret_key() -> SecretKey {
    SecretKey::from_bytes(*b"\x10\x32\x54\x76\x98\xba\xdc\xfe\x01\x23\x45\x67\x89\xab\xcd\xef")
}

pub fn new_vault() -> UnlockedVault {
    UnlockedVault::create(PASSWORD, &secret_key(), FAST).unwrap()
}

pub fn card() -> Item {
    Item {
        overview: ItemOverview {
            kind: ItemKind::Card,
            title: "Visa BBVA".into(),
            subtitle: Some("Débito · •••• 4821".into()),
            urls: vec![],
            tags: vec!["banco".into()],
            favorite: true,
            created_at: 1_793_257_200,
            updated_at: 1_793_257_200,
        },
        details: ItemDetails {
            fields: vec![
                Field::new("Titular", FieldKind::Text, "RAÚL LÓPEZ"),
                Field::new("Número", FieldKind::CardNumber, "4940192355674821"),
                Field::new("Caducidad", FieldKind::Date, "2029-08"),
                Field::new("CVV", FieldKind::Concealed, "317"),
                Field::new("PIN", FieldKind::Pin, "2958"),
            ],
            notes: String::new(),
        },
    }
}

pub fn login() -> Item {
    Item {
        overview: ItemOverview {
            kind: ItemKind::Login,
            title: "Google".into(),
            subtitle: Some("raul@ejemplo.com".into()),
            urls: vec!["https://accounts.google.com".into()],
            tags: vec![],
            favorite: false,
            created_at: 1_793_257_300,
            updated_at: 1_793_257_300,
        },
        details: ItemDetails {
            fields: vec![
                Field::new("Usuario", FieldKind::Email, "raul@ejemplo.com"),
                Field::new("Contraseña", FieldKind::Concealed, "v9#Qe!2mZp7&Lk4x"),
                Field::new(
                    "TOTP",
                    FieldKind::Totp,
                    "otpauth://totp/Google?secret=JBSWY3DPEHPK3PXP",
                ),
            ],
            notes: "Códigos de recuperación en la caja fuerte.".into(),
        },
    }
}
