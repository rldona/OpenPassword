//! Cryptographic primitives and the key hierarchy (spec sections 2–6).

mod aead;
mod kdf;
mod keys;
mod rng;
mod secret_key;
pub(crate) mod stream;

pub use aead::{NONCE_LEN, TAG_LEN, open, seal, seal_with_nonce, unwrap_key, wrap_key};
pub use kdf::{KdfAlg, KdfParams, derive_kek};
pub use keys::{KEY_LEN, Key};
pub(crate) use rng::random_array;
pub use secret_key::{SECRET_KEY_LEN, SecretKey};

/// Domain for every wrapped key (VK, IK, FK).
pub const DOMAIN_WRAP: &str = "op/wrap/v1";
/// Domain for item overview and details.
pub const DOMAIN_ITEM: &str = "op/item/v1";
/// Domain for item attachments (images).
pub const DOMAIN_ATTACHMENT: &str = "op/attachment/v1";

/// Encodes associated data unambiguously (spec 6.2):
/// `domain ‖ 0x00 ‖ (u32_le(len) ‖ part)*`.
pub fn aad(domain: &str, parts: &[&[u8]]) -> Vec<u8> {
    let len = domain.len() + 1 + parts.iter().map(|p| 4 + p.len()).sum::<usize>();
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(domain.as_bytes());
    out.push(0);
    for part in parts {
        let part_len = u32::try_from(part.len()).expect("AAD part longer than 4 GiB");
        out.extend_from_slice(&part_len.to_le_bytes());
        out.extend_from_slice(part);
    }
    out
}
