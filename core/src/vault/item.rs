//! Plaintext item model. Serialized as JSON before padding and sealing.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::attachment::{AttachmentId, parse_id as parse_attachment_id};
use crate::{Error, Result};

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
    Image,
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
    /// Previous passwords, newest first. Filled by [`ItemDetails::record_changes`] on update.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<PasswordChange>,
}

/// A password an item used to have, kept so a change can be undone (spec 7).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PasswordChange {
    pub label: String,
    pub value: String,
    /// Unix seconds when it stopped being the current value.
    pub changed_at: u64,
}

impl ItemDetails {
    /// Previous passwords kept per item; older ones are dropped.
    pub const MAX_HISTORY: usize = 10;

    /// Ids of every image field, in field order.
    ///
    /// The field list is the source of truth for which images an item has. The value is the
    /// canonical lowercase hex id of the sealed attachment.
    pub fn image_ids(&self) -> Result<Vec<AttachmentId>> {
        let mut ids = Vec::new();
        for field in self.fields.iter().filter(|f| f.kind == FieldKind::Image) {
            let id = parse_attachment_id(&field.value)?;
            if ids.contains(&id) {
                return Err(Error::InvalidInput("duplicate image id"));
            }
            ids.push(id);
        }
        Ok(ids)
    }

    /// Sets `self.history` to `previous.history` plus every concealed value of `previous`
    /// that `self` no longer has under the same label. Only for kinds whose concealed fields
    /// are passwords (logins, Wi-Fi, secrets): old CVVs are not worth keeping around.
    pub fn record_changes(&mut self, previous: &ItemDetails, kind: ItemKind, now: u64) {
        let mut history = previous.history.clone();
        if matches!(kind, ItemKind::Login | ItemKind::Wifi | ItemKind::Secret) {
            for old in previous
                .fields
                .iter()
                .filter(|f| f.kind == FieldKind::Concealed && !f.value.is_empty())
            {
                let kept = self.fields.iter().any(|f| {
                    f.kind == FieldKind::Concealed && f.label == old.label && f.value == old.value
                });
                if !kept {
                    history.insert(
                        0,
                        PasswordChange {
                            label: old.label.clone(),
                            value: old.value.clone(),
                            changed_at: now,
                        },
                    );
                }
            }
        }
        history.truncate(Self::MAX_HISTORY);
        self.history = history;
    }
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
redacted_debug!(ItemOverview, ItemDetails, Field, PasswordChange, Item);
