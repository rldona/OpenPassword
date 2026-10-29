//! Plaintext item model. Serialized as JSON before padding and sealing.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    Login,
    Card,
    Pin,
    SecureNote,
    Secret,
    BankAccount,
    Identity,
    Wifi,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    Text,
    Concealed,
    Pin,
    CardNumber,
    Totp,
    Date,
    Url,
    Email,
}

/// What the vault list and search need. Decrypted for every item on unlock.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ItemOverview {
    #[zeroize(skip)]
    pub kind: ItemKind,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subtitle: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub urls: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default)]
    pub favorite: bool,
    /// Unix seconds.
    pub created_at: u64,
    /// Unix seconds.
    pub updated_at: u64,
}

/// The secret part of an item. Decrypted only when the item is opened.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ItemDetails {
    #[serde(default)]
    pub fields: Vec<Field>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notes: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Field {
    pub label: String,
    #[zeroize(skip)]
    pub kind: FieldKind,
    pub value: String,
}

impl Field {
    pub fn new(label: impl Into<String>, kind: FieldKind, value: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            kind,
            value: value.into(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Item {
    pub overview: ItemOverview,
    pub details: ItemDetails,
}

// Debug never prints titles or values: logs must not leak vault contents.
macro_rules! redacted_debug {
    ($($t:ty),*) => {$(
        impl core::fmt::Debug for $t {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($t), "(<redacted>)"))
            }
        }
    )*};
}
redacted_debug!(ItemOverview, ItemDetails, Field, Item);
