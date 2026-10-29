//! The 128-bit secret key and its printable form (spec 4).

use core::fmt;

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::rng::fill_random;
use crate::{Error, Result};

pub const SECRET_KEY_LEN: usize = 16;

const PREFIX: &str = "OP1";
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const DATA_CHARS: usize = 26; // 128 bits + 2 zero bits
const CHECK_CHARS: usize = 4; // 20 bits
const GROUP: usize = 6;

/// Second factor mixed into the KEK. Lives on the device and in the emergency kit.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; SECRET_KEY_LEN]);

impl SecretKey {
    pub fn generate() -> Result<Self> {
        let mut key = SecretKey([0u8; SECRET_KEY_LEN]);
        fill_random(&mut key.0)?;
        Ok(key)
    }

    pub fn from_bytes(bytes: [u8; SECRET_KEY_LEN]) -> Self {
        SecretKey(bytes)
    }

    pub fn expose(&self) -> &[u8; SECRET_KEY_LEN] {
        &self.0
    }

    /// Public 4-byte identifier, used to detect the wrong secret key before running Argon2id.
    pub fn id(&self) -> [u8; 4] {
        let mut id = [0u8; 4];
        Hkdf::<Sha256>::new(None, &self.0)
            .expand(b"op/sk-id/v1", &mut id)
            .expect("4 bytes is a valid HKDF output length");
        id
    }

    /// `OP1-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX`, for the emergency kit and display.
    pub fn to_display(&self) -> Zeroizing<String> {
        let mut chars = Zeroizing::new(encode_base32(&self.0, DATA_CHARS));
        chars.push_str(&encode_base32(&checksum(&self.0), CHECK_CHARS));

        let mut out = Zeroizing::new(String::with_capacity(PREFIX.len() + 35));
        out.push_str(PREFIX);
        for group in chars.as_bytes().chunks(GROUP) {
            out.push('-');
            out.push_str(core::str::from_utf8(group).expect("base32 output is ASCII"));
        }
        out
    }

    /// Parses user input. Ignores dashes, spaces and case; maps `O→0` and `I, L→1`.
    pub fn parse(input: &str) -> Result<Self> {
        let cleaned: Zeroizing<String> = Zeroizing::new(
            input
                .chars()
                .filter(|c| !c.is_whitespace() && *c != '-')
                .map(|c| c.to_ascii_uppercase())
                .collect(),
        );
        let body = cleaned
            .strip_prefix(PREFIX)
            .ok_or(Error::InvalidSecretKey("must start with OP1"))?;
        if body.len() != DATA_CHARS + CHECK_CHARS {
            return Err(Error::InvalidSecretKey("wrong length"));
        }
        let values = Zeroizing::new(
            body.bytes()
                .map(decode_char)
                .collect::<Option<Vec<u8>>>()
                .ok_or(Error::InvalidSecretKey("invalid character"))?,
        );
        let (data, check) = values.split_at(DATA_CHARS);

        // 26 chars carry 130 bits: the last 2 bits are padding and must be zero.
        if data[DATA_CHARS - 1] & 0b11 != 0 {
            return Err(Error::InvalidSecretKey("invalid padding"));
        }
        let mut bytes = [0u8; SECRET_KEY_LEN];
        decode_base32(data, &mut bytes);
        let key = SecretKey(bytes);
        bytes.zeroize();

        if encode_base32(&checksum(&key.0), CHECK_CHARS).as_bytes()
            != check
                .iter()
                .map(|&v| ALPHABET[v as usize])
                .collect::<Vec<u8>>()
        {
            return Err(Error::InvalidSecretKey(
                "checksum mismatch, check for typos",
            ));
        }
        Ok(key)
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

fn checksum(raw: &[u8; SECRET_KEY_LEN]) -> [u8; 3] {
    let digest = Sha256::new()
        .chain_update(b"op/sk-check/v1")
        .chain_update(raw)
        .finalize();
    [digest[0], digest[1], digest[2]]
}

/// Big-endian bit stream to `chars` base32 characters, padding with zero bits.
fn encode_base32(bytes: &[u8], chars: usize) -> String {
    let mut out = String::with_capacity(chars);
    for i in 0..chars {
        let mut value = 0u8;
        for bit in 0..5 {
            let pos = i * 5 + bit;
            let set = bytes
                .get(pos / 8)
                .is_some_and(|b| b & (0x80 >> (pos % 8)) != 0);
            value = (value << 1) | u8::from(set);
        }
        out.push(ALPHABET[value as usize] as char);
    }
    out
}

/// Inverse of [`encode_base32`]; fills `out` and drops the trailing padding bits.
fn decode_base32(values: &[u8], out: &mut [u8]) {
    out.fill(0);
    for (i, &value) in values.iter().enumerate() {
        for bit in 0..5 {
            let pos = i * 5 + bit;
            if pos / 8 < out.len() && value & (0x10 >> bit) != 0 {
                out[pos / 8] |= 0x80 >> (pos % 8);
            }
        }
    }
}

fn decode_char(c: u8) -> Option<u8> {
    let c = match c {
        b'O' => b'0',
        b'I' | b'L' => b'1',
        other => other,
    };
    ALPHABET.iter().position(|&a| a == c).map(|p| p as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> SecretKey {
        SecretKey::from_bytes(*b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff")
    }

    #[test]
    fn display_has_expected_shape() {
        let shown = sample().to_display();
        assert_eq!(shown.len(), 3 + 5 * 7);
        let groups: Vec<&str> = shown.split('-').collect();
        assert_eq!(groups[0], "OP1");
        assert!(groups[1..].iter().all(|g| g.len() == 6));
    }

    #[test]
    fn parse_roundtrip_and_lenient_input() {
        let key = sample();
        let shown = key.to_display();
        assert_eq!(SecretKey::parse(&shown).unwrap(), key);

        let sloppy = shown.replace('-', " ").to_lowercase();
        assert_eq!(SecretKey::parse(&sloppy).unwrap(), key);
    }

    #[test]
    fn parse_maps_ambiguous_characters() {
        let key = sample();
        let shown = key.to_display();
        let with_letters = format!("OP1{}", shown[3..].replace('0', "O").replace('1', "l"));
        assert_eq!(SecretKey::parse(&with_letters).unwrap(), key);
    }

    #[test]
    fn parse_detects_a_typo() {
        let shown = sample().to_display().to_string();
        // Change one data character.
        let mut chars: Vec<char> = shown.chars().collect();
        chars[5] = if chars[5] == 'A' { 'B' } else { 'A' };
        let typo: String = chars.into_iter().collect();
        assert_eq!(
            SecretKey::parse(&typo),
            Err(Error::InvalidSecretKey(
                "checksum mismatch, check for typos"
            ))
        );
    }

    #[test]
    fn parse_rejects_bad_input() {
        assert!(SecretKey::parse("").is_err());
        assert!(SecretKey::parse("OP2-AAAAAA-AAAAAA-AAAAAA-AAAAAA-AAAAAA").is_err());
        assert!(SecretKey::parse("OP1-AAAAAA").is_err());
        assert!(SecretKey::parse("OP1-UUUUUU-AAAAAA-AAAAAA-AAAAAA-AAAAAA").is_err());
    }

    #[test]
    fn generated_keys_roundtrip() {
        for _ in 0..200 {
            let key = SecretKey::generate().unwrap();
            assert_eq!(SecretKey::parse(&key.to_display()).unwrap(), key);
        }
    }

    #[test]
    fn debug_does_not_leak() {
        assert_eq!(format!("{:?}", sample()), "SecretKey(<redacted>)");
    }
}
