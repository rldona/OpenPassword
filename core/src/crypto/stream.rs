//! STREAM-BE32 over XChaCha20-Poly1305 for backup bodies (format: "Cuerpo").

use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::stream::{DecryptorBE32, EncryptorBE32};
use chacha20poly1305::aead::{KeyInit, Payload};
use chacha20poly1305::{Key as CipherKey, XChaCha20Poly1305};
use zeroize::Zeroizing;

use super::aead::TAG_LEN;
use super::keys::Key;
use crate::{Error, Result};

/// Plaintext bytes per chunk.
pub const CHUNK_LEN: usize = 64 * 1024;
/// 24-byte XChaCha nonce minus 4 counter bytes and 1 last-chunk flag.
pub const STREAM_NONCE_LEN: usize = 19;

fn cipher(key: &Key) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(CipherKey::from_slice(key.expose()))
}

pub fn encrypt(key: &Key, nonce: &[u8; STREAM_NONCE_LEN], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let mut encryptor = EncryptorBE32::from_aead(cipher(key), GenericArray::from_slice(nonce));
    let mut chunks: Vec<&[u8]> = plaintext.chunks(CHUNK_LEN).collect();
    let last = chunks.pop().unwrap_or(&[]);

    let mut out = Vec::with_capacity(plaintext.len() + (chunks.len() + 1) * TAG_LEN);
    for chunk in chunks {
        let sealed = encryptor
            .encrypt_next(Payload { msg: chunk, aad })
            .expect("stream encryption of an in-memory buffer cannot fail");
        out.extend_from_slice(&sealed);
    }
    let sealed = encryptor
        .encrypt_last(Payload { msg: last, aad })
        .expect("stream encryption of an in-memory buffer cannot fail");
    out.extend_from_slice(&sealed);
    out
}

pub fn decrypt(
    key: &Key,
    nonce: &[u8; STREAM_NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if ciphertext.len() < TAG_LEN {
        return Err(Error::Decrypt);
    }
    let mut decryptor = DecryptorBE32::from_aead(cipher(key), GenericArray::from_slice(nonce));
    let mut chunks: Vec<&[u8]> = ciphertext.chunks(CHUNK_LEN + TAG_LEN).collect();
    let last = chunks.pop().expect("ciphertext is not empty");

    let mut out = Zeroizing::new(Vec::with_capacity(ciphertext.len()));
    for chunk in chunks {
        let plain = Zeroizing::new(
            decryptor
                .decrypt_next(Payload { msg: chunk, aad })
                .map_err(|_| Error::Decrypt)?,
        );
        out.extend_from_slice(&plain);
    }
    let plain = Zeroizing::new(
        decryptor
            .decrypt_last(Payload { msg: last, aad })
            .map_err(|_| Error::Decrypt)?,
    );
    out.extend_from_slice(&plain);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Key {
        Key::from_bytes([7u8; 32])
    }

    #[test]
    fn roundtrip_at_chunk_boundaries() {
        let nonce = [9u8; STREAM_NONCE_LEN];
        for len in [0, 1, CHUNK_LEN - 1, CHUNK_LEN, CHUNK_LEN + 1, 3 * CHUNK_LEN] {
            let plain: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let sealed = encrypt(&key(), &nonce, &plain, b"aad");
            assert_eq!(
                *decrypt(&key(), &nonce, &sealed, b"aad").unwrap(),
                plain,
                "len {len}"
            );
        }
    }

    #[test]
    fn truncation_at_a_chunk_boundary_is_detected() {
        let nonce = [9u8; STREAM_NONCE_LEN];
        let plain = vec![1u8; 2 * CHUNK_LEN + 10];
        let sealed = encrypt(&key(), &nonce, &plain, b"");
        let truncated = &sealed[..2 * (CHUNK_LEN + TAG_LEN)];
        assert_eq!(decrypt(&key(), &nonce, truncated, b""), Err(Error::Decrypt));
    }

    #[test]
    fn reordered_chunks_are_detected() {
        let nonce = [9u8; STREAM_NONCE_LEN];
        let plain = vec![1u8; 2 * CHUNK_LEN + 10];
        let sealed = encrypt(&key(), &nonce, &plain, b"");
        let size = CHUNK_LEN + TAG_LEN;
        let mut swapped = sealed[size..2 * size].to_vec();
        swapped.extend_from_slice(&sealed[..size]);
        swapped.extend_from_slice(&sealed[2 * size..]);
        assert_eq!(decrypt(&key(), &nonce, &swapped, b""), Err(Error::Decrypt));
    }

    #[test]
    fn wrong_aad_is_detected() {
        let nonce = [9u8; STREAM_NONCE_LEN];
        let sealed = encrypt(&key(), &nonce, b"hola", b"a");
        assert_eq!(decrypt(&key(), &nonce, &sealed, b"b"), Err(Error::Decrypt));
    }
}
