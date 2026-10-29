//! XChaCha20-Poly1305 with a random 192-bit nonce (spec 6.1).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key as CipherKey, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use super::keys::{KEY_LEN, Key};
use super::rng::random_array;
use crate::{Error, Result};

pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;

fn cipher(key: &Key) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(CipherKey::from_slice(key.expose()))
}

/// Encrypts `plaintext` with a fresh random nonce. Output: `nonce ‖ ciphertext ‖ tag`.
pub fn seal(key: &Key, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let nonce = random_array::<NONCE_LEN>()?;
    Ok(seal_with_nonce(key, &nonce, plaintext, aad))
}

/// Encrypts with a caller-supplied nonce. Exists for known-answer tests:
/// production code must use [`seal`], which never reuses a nonce.
#[doc(hidden)]
pub fn seal_with_nonce(
    key: &Key,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    let ciphertext = cipher(key)
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("XChaCha20-Poly1305 encryption of an in-memory buffer cannot fail");
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ciphertext);
    out
}

/// Decrypts and authenticates the output of [`seal`].
pub fn open(key: &Key, sealed: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(Error::Decrypt);
    }
    let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
    cipher(key)
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::Decrypt)
}

/// Seals `key` under `wrapping_key`.
pub fn wrap_key(wrapping_key: &Key, key: &Key, aad: &[u8]) -> Result<Vec<u8>> {
    seal(wrapping_key, key.expose(), aad)
}

/// Opens a key sealed with [`wrap_key`].
pub fn unwrap_key(wrapping_key: &Key, wrapped: &[u8], aad: &[u8]) -> Result<Key> {
    let plain = open(wrapping_key, wrapped, aad)?;
    let bytes: [u8; KEY_LEN] = plain
        .as_slice()
        .try_into()
        .map_err(|_| Error::Malformed("wrapped key has the wrong length"))?;
    Ok(Key::from_bytes(bytes))
}
