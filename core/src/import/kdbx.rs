//! KeePass databases (KDBX 3.1 and 4.x) protected with a password.
//!
//! Unlike the other importers this one decrypts: composite key → KDF (AES-KDF or
//! Argon2d/id) → outer cipher (AES-256-CBC or ChaCha20) → optional gzip → XML, whose
//! protected values are also XOR-ed with an inner stream (Salsa20 or ChaCha20).
//! Key files are supported in every KeePass format; Twofish is not. The recycle bin and
//! entry history are skipped.

use std::io::Read;

use aes::Aes256;
use aes::cipher::{
    BlockDecryptMut, BlockEncrypt, KeyInit, KeyIvInit, StreamCipher, block_padding::Pkcs7,
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use hmac::{Hmac, Mac};
use quick_xml::Reader;
use quick_xml::events::Event;
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

use super::{ImportFormat, Imported, Login, MAX_INPUT, login_item, note_item};
use crate::{Error, Result};

const SIGNATURE: [u8; 8] = [0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5];
const CIPHER_AES256: [u8; 16] = hex16("31c1f2e6bf714350be5805216afc5aff");
const CIPHER_CHACHA20: [u8; 16] = hex16("d6038a2b8b6f4cb5a524339a31dbb59a");
const KDF_AES: [u8; 16] = hex16("c9d9f39a628a4460bf740d08c18a4fea");
const KDF_ARGON2D: [u8; 16] = hex16("ef636ddf8c29444b91f7a9a403e30a0c");
const KDF_ARGON2ID: [u8; 16] = hex16("9e298b1956db4773b23dfc3ec6f0a1e6");
const SALSA20_IV: [u8; 8] = [0xe8, 0x30, 0x09, 0x4b, 0x97, 0x20, 0x5d, 0x2a];

// Refuse databases whose KDF would exhaust a phone: real files stay far below these.
const MAX_AES_ROUNDS: u64 = 200_000_000;
const MAX_ARGON2_BYTES: u64 = 1 << 30;
const MAX_ARGON2_ITERATIONS: u64 = 1_000;

const fn hex16(s: &str) -> [u8; 16] {
    let b = s.as_bytes();
    let mut out = [0u8; 16];
    let mut i = 0;
    while i < 16 {
        out[i] = (nibble(b[2 * i]) << 4) | nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        _ => c - b'a' + 10,
    }
}

pub fn is_kdbx(bytes: &[u8]) -> bool {
    bytes.starts_with(&SIGNATURE)
}

fn bad(msg: &'static str) -> Error {
    Error::InvalidInput(msg)
}

/// Little-endian reads over a byte slice, with bounds checks.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.data.len())
            .ok_or(Error::Malformed("truncated KDBX"))?;
        let out = &self.data[self.pos..end];
        self.pos = end;
        Ok(out)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(
            self.take(2)?.try_into().expect("2 bytes"),
        ))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }
    fn i32(&mut self) -> Result<i32> {
        Ok(i32::from_le_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }
}

#[derive(Default)]
struct Header {
    cipher: Vec<u8>,
    compressed: bool,
    master_seed: Vec<u8>,
    iv: Vec<u8>,
    // KDBX 4
    kdf: Vec<(String, Vec<u8>)>,
    // KDBX 3.1
    transform_seed: Vec<u8>,
    transform_rounds: u64,
    protected_stream_key: Vec<u8>,
    stream_start_bytes: Vec<u8>,
    inner_stream_id: u32,
}

/// KDBX 4 "VariantDictionary": typed key/value pairs. Values are kept as raw bytes.
fn variant_dictionary(data: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    let mut c = Cursor { data, pos: 0 };
    let _version = c.u16()?;
    let mut out = Vec::new();
    loop {
        let kind = c.u8()?;
        if kind == 0 {
            return Ok(out);
        }
        let key_len = c.i32()?;
        let key = String::from_utf8(
            c.take(usize::try_from(key_len).map_err(|_| Error::Malformed("KDBX"))?)?
                .to_vec(),
        )
        .map_err(|_| Error::Malformed("KDBX"))?;
        let value_len = c.i32()?;
        let value = c
            .take(usize::try_from(value_len).map_err(|_| Error::Malformed("KDBX"))?)?
            .to_vec();
        out.push((key, value));
    }
}

fn dict_get<'a>(dict: &'a [(String, Vec<u8>)], key: &str) -> Option<&'a [u8]> {
    dict.iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_slice())
}

fn dict_u64(dict: &[(String, Vec<u8>)], key: &str) -> Option<u64> {
    let v = dict_get(dict, key)?;
    match v.len() {
        4 => Some(u64::from(u32::from_le_bytes(v.try_into().ok()?))),
        8 => Some(u64::from_le_bytes(v.try_into().ok()?)),
        _ => None,
    }
}

/// Decrypts and converts a KDBX database. `now` (Unix seconds) stamps the items.
pub fn parse(
    bytes: &[u8],
    password: Option<&str>,
    key_file: Option<&[u8]>,
    now: u64,
) -> Result<Imported> {
    let mut c = Cursor {
        data: bytes,
        pos: 0,
    };
    c.take(8)?;
    let _minor = c.u16()?;
    let major = c.u16()?;
    if major != 3 && major != 4 {
        return Err(bad(
            "unsupported KeePass version: save the database as KDBX 4",
        ));
    }
    let v4 = major == 4;

    let mut h = Header::default();
    loop {
        let id = c.u8()?;
        let len = if v4 {
            c.u32()? as usize
        } else {
            c.u16()? as usize
        };
        let data = c.take(len)?;
        match id {
            0 => break,
            2 => h.cipher = data.to_vec(),
            3 => {
                h.compressed = data.len() >= 4
                    && u32::from_le_bytes(data[..4].try_into().expect("4 bytes")) == 1
            }
            4 => h.master_seed = data.to_vec(),
            5 => h.transform_seed = data.to_vec(),
            6 if data.len() == 8 => {
                h.transform_rounds = u64::from_le_bytes(data.try_into().expect("8 bytes"))
            }
            7 => h.iv = data.to_vec(),
            8 => h.protected_stream_key = data.to_vec(),
            9 => h.stream_start_bytes = data.to_vec(),
            10 if data.len() == 4 => {
                h.inner_stream_id = u32::from_le_bytes(data.try_into().expect("4 bytes"))
            }
            11 => h.kdf = variant_dictionary(data)?,
            _ => {}
        }
    }
    let header_end = c.pos;
    if h.master_seed.len() != 32 {
        return Err(Error::Malformed("KDBX master seed"));
    }

    // Composite key: SHA-256 of the password hash followed by the key file's key.
    let mut composite = Sha256::new();
    if let Some(p) = password {
        composite.update(Sha256::digest(p.as_bytes()));
    }
    if let Some(k) = key_file {
        composite.update(*key_file_key(k)?);
    }
    let composite = Zeroizing::new(composite.finalize().to_vec());
    let transformed = Zeroizing::new(if v4 {
        kdf_v4(&h.kdf, &composite)?
    } else {
        aes_kdf(&composite, &h.transform_seed, h.transform_rounds)?
    });

    let mut hasher = Sha256::new();
    hasher.update(&h.master_seed);
    hasher.update(&*transformed);
    let cipher_key = Zeroizing::new(hasher.finalize().to_vec());

    let ciphertext: Vec<u8> = if v4 {
        let stored_hash = c.take(32)?;
        if Sha256::digest(&bytes[..header_end]).as_slice() != stored_hash {
            return Err(Error::Malformed("KDBX header checksum"));
        }
        let mut hmac_base = Sha512::new();
        hmac_base.update(&h.master_seed);
        hmac_base.update(&*transformed);
        hmac_base.update([1u8]);
        let hmac_base = Zeroizing::new(hmac_base.finalize().to_vec());
        let block_key = |index: u64| -> Zeroizing<Vec<u8>> {
            let mut k = Sha512::new();
            k.update(index.to_le_bytes());
            k.update(&*hmac_base);
            Zeroizing::new(k.finalize().to_vec())
        };
        // A wrong password shows up here, before any decryption.
        let stored_hmac = c.take(32)?;
        let mut mac = hmac_sha256(&block_key(u64::MAX));
        mac.update(&bytes[..header_end]);
        if mac.verify_slice(stored_hmac).is_err() {
            return Err(Error::WrongCredentials);
        }
        let mut out = Vec::new();
        for index in 0u64.. {
            let block_hmac = c.take(32)?;
            let size = c.i32()?;
            let data =
                c.take(usize::try_from(size).map_err(|_| Error::Malformed("KDBX block"))?)?;
            let mut mac = hmac_sha256(&block_key(index));
            mac.update(&index.to_le_bytes());
            mac.update(&size.to_le_bytes());
            mac.update(data);
            mac.verify_slice(block_hmac)
                .map_err(|_| Error::Malformed("KDBX block HMAC"))?;
            if size == 0 {
                break;
            }
            out.extend_from_slice(data);
        }
        out
    } else {
        bytes[header_end..].to_vec()
    };

    let mut plain = Zeroizing::new(match h.cipher.as_slice() {
        x if x == CIPHER_AES256 => cbc::Decryptor::<Aes256>::new_from_slices(&cipher_key, &h.iv)
            .map_err(|_| Error::Malformed("KDBX IV"))?
            .decrypt_padded_vec_mut::<Pkcs7>(&ciphertext)
            // KDBX 3.1 has no HMAC: a wrong password usually ends as bad padding.
            .map_err(|_| {
                if v4 {
                    Error::Malformed("KDBX padding")
                } else {
                    Error::WrongCredentials
                }
            })?,
        x if x == CIPHER_CHACHA20 => {
            let mut data = ciphertext;
            chacha20::ChaCha20::new_from_slices(&cipher_key, &h.iv)
                .map_err(|_| Error::Malformed("KDBX IV"))?
                .apply_keystream(&mut data);
            data
        }
        _ => return Err(bad("unsupported KeePass cipher: use AES-256 or ChaCha20")),
    });

    if !v4 {
        // KDBX 3.1: known start bytes prove the key, then a SHA-256 hashed block stream.
        if plain.len() < 32 || plain[..32] != h.stream_start_bytes[..] {
            return Err(Error::WrongCredentials);
        }
        let mut c = Cursor {
            data: &plain[32..],
            pos: 0,
        };
        let mut out = Zeroizing::new(Vec::new());
        loop {
            let _index = c.u32()?;
            let hash = c.take(32)?.to_vec();
            let size = c.u32()? as usize;
            if size == 0 {
                break;
            }
            let data = c.take(size)?;
            if Sha256::digest(data).as_slice() != hash {
                return Err(Error::Malformed("KDBX block hash"));
            }
            out.extend_from_slice(data);
        }
        plain = Zeroizing::new(out.to_vec());
    }

    if h.compressed {
        let mut out = Zeroizing::new(Vec::new());
        flate2::read::GzDecoder::new(plain.as_slice())
            .take(MAX_INPUT as u64 + 1)
            .read_to_end(&mut out)
            .map_err(|_| Error::Malformed("KDBX gzip"))?;
        if out.len() > MAX_INPUT {
            return Err(bad("file too large to import"));
        }
        plain = out;
    }

    // KDBX 4 inner header: inner stream cipher and key, attachments (ignored).
    let mut xml_start = 0;
    let (mut stream_id, mut stream_key) = (h.inner_stream_id, h.protected_stream_key.clone());
    if v4 {
        let mut c = Cursor {
            data: &plain,
            pos: 0,
        };
        loop {
            let id = c.u8()?;
            let len = c.u32()? as usize;
            let data = c.take(len)?;
            match id {
                0 => break,
                1 if data.len() == 4 => {
                    stream_id = u32::from_le_bytes(data.try_into().expect("4 bytes"))
                }
                2 => stream_key = data.to_vec(),
                _ => {}
            }
        }
        xml_start = c.pos;
    }
    let mut inner = InnerStream::new(stream_id, &stream_key)?;
    let xml = std::str::from_utf8(&plain[xml_start..]).map_err(|_| Error::Malformed("KDBX XML"))?;
    let entries = read_entries(xml, &mut inner)?;

    let mut items = Vec::new();
    let mut skipped = 0;
    for e in entries {
        match entry_to_item(&e, now) {
            Some(item) => items.push(item),
            None => skipped += 1,
        }
    }
    Ok(Imported {
        format: ImportFormat::Kdbx,
        items,
        skipped,
    })
}

/// The 32-byte key a KeePass key file stands for:
/// XML v2.0 (hex with a check hash), XML v1.0 (base64), 32 raw bytes, 64 hex characters,
/// or, for any other file, its SHA-256.
fn key_file_key(data: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let damaged = || bad("the key file is damaged");
    let to_key = |v: Vec<u8>| -> Result<Zeroizing<[u8; 32]>> {
        Ok(Zeroizing::new(v.try_into().map_err(|_| damaged())?))
    };

    if let Some(xml) = std::str::from_utf8(data)
        .ok()
        .filter(|t| t.contains("<KeyFile>"))
    {
        let (version, data_text, hash) = key_file_xml(xml)?;
        return if version.starts_with("2.") {
            let hex: String = data_text.chars().filter(|c| !c.is_whitespace()).collect();
            let key = to_key(decode_hex(&hex).ok_or_else(damaged)?)?;
            if let Some(expected) = hash {
                let actual: String = Sha256::digest(*key)[..4]
                    .iter()
                    .map(|b| format!("{b:02X}"))
                    .collect();
                if !actual.eq_ignore_ascii_case(expected.trim()) {
                    return Err(damaged());
                }
            }
            Ok(key)
        } else {
            to_key(
                base64::engine::general_purpose::STANDARD
                    .decode(data_text.trim())
                    .map_err(|_| damaged())?,
            )
        };
    }
    if data.len() == 32 {
        return to_key(data.to_vec());
    }
    if data.len() == 64 {
        if let Some(key) = std::str::from_utf8(data).ok().and_then(decode_hex) {
            return to_key(key);
        }
    }
    to_key(Sha256::digest(data).to_vec())
}

/// (Version, Data text, Data@Hash) of a key file.
fn key_file_xml(xml: &str) -> Result<(String, String, Option<String>)> {
    let mut reader = Reader::from_str(xml);
    let (mut version, mut data, mut hash) = (String::new(), String::new(), None);
    let mut current = String::new();
    loop {
        match reader
            .read_event()
            .map_err(|_| bad("the key file is damaged"))?
        {
            Event::Start(e) => {
                current = e.name().as_ref().to_owned();
                if current == "Data" {
                    hash = e
                        .attributes()
                        .flatten()
                        .find(|a| a.key.as_ref() == "Hash")
                        .map(|a| a.value.to_string());
                }
            }
            Event::Text(t) if current == "Version" => version.push_str(t.xml10_content().trim()),
            Event::Text(t) if current == "Data" => data.push_str(&t.xml10_content()),
            Event::End(_) => current.clear(),
            Event::Eof => break,
            _ => {}
        }
    }
    Ok((version, data, hash))
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

fn hmac_sha256(key: &[u8]) -> Hmac<Sha256> {
    <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts keys of any length")
}

fn kdf_v4(dict: &[(String, Vec<u8>)], composite: &[u8]) -> Result<Vec<u8>> {
    let uuid = dict_get(dict, "$UUID").ok_or(Error::Malformed("KDBX KDF"))?;
    if uuid == KDF_AES {
        let seed = dict_get(dict, "S").ok_or(Error::Malformed("KDBX KDF"))?;
        let rounds = dict_u64(dict, "R").ok_or(Error::Malformed("KDBX KDF"))?;
        return aes_kdf(composite, seed, rounds);
    }
    let algorithm = match uuid {
        x if x == KDF_ARGON2D => Algorithm::Argon2d,
        x if x == KDF_ARGON2ID => Algorithm::Argon2id,
        _ => return Err(bad("unsupported KeePass key derivation")),
    };
    let salt = dict_get(dict, "S").ok_or(Error::Malformed("KDBX KDF"))?;
    let memory = dict_u64(dict, "M").ok_or(Error::Malformed("KDBX KDF"))?;
    let iterations = dict_u64(dict, "I").ok_or(Error::Malformed("KDBX KDF"))?;
    let lanes = dict_u64(dict, "P").ok_or(Error::Malformed("KDBX KDF"))?;
    let version = match dict_u64(dict, "V") {
        Some(0x10) => Version::V0x10,
        _ => Version::V0x13,
    };
    if memory > MAX_ARGON2_BYTES || iterations > MAX_ARGON2_ITERATIONS || lanes > 64 {
        return Err(bad(
            "the KeePass key derivation is too costly for this device",
        ));
    }
    let params = Params::new(
        (memory / 1024) as u32,
        iterations as u32,
        lanes as u32,
        Some(32),
    )
    .map_err(|_| Error::Malformed("KDBX Argon2 parameters"))?;
    let mut out = vec![0u8; 32];
    Argon2::new(algorithm, version, params)
        .hash_password_into(composite, salt, &mut out)
        .map_err(|_| Error::Kdf)?;
    Ok(out)
}

/// KeePass AES-KDF: encrypt both halves of the key `rounds` times with AES-256-ECB, then SHA-256.
fn aes_kdf(composite: &[u8], seed: &[u8], rounds: u64) -> Result<Vec<u8>> {
    if rounds > MAX_AES_ROUNDS {
        return Err(bad(
            "the KeePass key derivation is too costly for this device",
        ));
    }
    let aes = Aes256::new_from_slice(seed).map_err(|_| Error::Malformed("KDBX transform seed"))?;
    let mut key =
        Zeroizing::new(<[u8; 32]>::try_from(composite).map_err(|_| Error::Malformed("KDBX key"))?);
    let (left, right) = key.split_at_mut(16);
    let (left, right) = (
        aes::Block::from_mut_slice(left),
        aes::Block::from_mut_slice(right),
    );
    for _ in 0..rounds {
        aes.encrypt_block(left);
        aes.encrypt_block(right);
    }
    Ok(Sha256::digest(key.as_slice()).to_vec())
}

/// Keystream that un-XORs protected values, in document order.
enum InnerStream {
    Salsa20(salsa20::Salsa20),
    ChaCha20(chacha20::ChaCha20),
    None,
}

impl InnerStream {
    fn new(id: u32, key: &[u8]) -> Result<Self> {
        Ok(match id {
            0 => InnerStream::None,
            2 => InnerStream::Salsa20(salsa20::Salsa20::new(
                Sha256::digest(key).as_slice().into(),
                (&SALSA20_IV).into(),
            )),
            3 => {
                let h = Sha512::digest(key);
                InnerStream::ChaCha20(chacha20::ChaCha20::new(h[..32].into(), h[32..44].into()))
            }
            _ => return Err(bad("unsupported KeePass inner stream")),
        })
    }

    fn reveal(&mut self, b64: &str) -> Result<String> {
        let mut data = Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(b64.trim())
                .map_err(|_| Error::Malformed("KDBX protected value"))?,
        );
        match self {
            InnerStream::Salsa20(c) => c.apply_keystream(&mut data),
            InnerStream::ChaCha20(c) => c.apply_keystream(&mut data),
            InnerStream::None => {}
        }
        String::from_utf8(data.to_vec()).map_err(|_| Error::Malformed("KDBX protected value"))
    }
}

#[derive(Default)]
struct Entry {
    strings: Vec<(String, String, bool)>,
}

impl Entry {
    fn get(&self, key: &str) -> &str {
        self.strings
            .iter()
            .find(|s| s.0 == key)
            .map(|s| s.1.as_str())
            .unwrap_or("")
    }
}

/// Resolves `&lt;`, `&#38;`… Since quick-xml 0.38 entities arrive as separate events.
fn resolve_entity(r: &quick_xml::events::BytesRef<'_>) -> Result<char> {
    if let Some(c) = r
        .resolve_char_ref()
        .map_err(|_| Error::Malformed("KDBX XML"))?
    {
        return Ok(c);
    }
    match &**r {
        "lt" => Ok('<'),
        "gt" => Ok('>'),
        "amp" => Ok('&'),
        "quot" => Ok('"'),
        "apos" => Ok('\''),
        _ => Err(Error::Malformed("KDBX XML entity")),
    }
}

/// Walks the XML. Protected values are revealed in document order, including those in
/// history and in the recycle bin, because the inner stream is sequential; those entries
/// are then dropped.
///
/// Text is accumulated per element (text, entity and CDATA events) and never trimmed:
/// a password may start or end with spaces.
/// Entry points for `cargo fuzz` into the parts behind the KDF. Not built otherwise.
#[cfg(fuzzing)]
pub mod fuzzing {
    /// Inner XML with protected values under a ChaCha20 stream, as KDBX 4 writes it.
    pub fn xml(xml: &str) {
        if let Ok(mut inner) = super::InnerStream::new(3, &[7; 64]) {
            if let Ok(entries) = super::read_entries(xml, &mut inner) {
                for e in &entries {
                    let _ = super::entry_to_item(e, 0);
                }
            }
        }
    }

    pub fn key_file(data: &[u8]) {
        let _ = super::key_file_key(data);
    }
}

fn read_entries(xml: &str, inner: &mut InnerStream) -> Result<Vec<Entry>> {
    let mut reader = Reader::from_str(xml);
    let malformed = |_| Error::Malformed("KDBX XML");

    let mut path: Vec<String> = Vec::new();
    let mut text = Zeroizing::new(String::new());
    let mut recycle_bin = String::new();
    // UUID of each open group, innermost last.
    let mut group_uuids: Vec<String> = Vec::new();
    let mut entries: Vec<(Entry, Vec<String>)> = Vec::new();
    let mut current: Option<Entry> = None;
    let mut history_depth = 0;
    let (mut key, mut value, mut protected) = (String::new(), String::new(), false);

    loop {
        match reader.read_event().map_err(malformed)? {
            Event::Start(e) => {
                let name = e.name().as_ref().to_owned();
                text.clear();
                match name.as_str() {
                    "Group" => group_uuids.push(String::new()),
                    "Entry" if history_depth == 0 => current = Some(Entry::default()),
                    "History" => history_depth += 1,
                    "String" => (key, value, protected) = (String::new(), String::new(), false),
                    "Value" => {
                        protected = e.attributes().flatten().any(|a| {
                            a.key.as_ref() == "Protected" && a.value.eq_ignore_ascii_case("true")
                        });
                    }
                    _ => {}
                }
                path.push(name);
            }
            // <Value/>: an empty value.
            Event::Empty(e) if e.name().as_ref() == "Value" => value.clear(),
            Event::Text(t) => text.push_str(&t.xml10_content()),
            Event::CData(c) => text.push_str(&c),
            Event::GeneralRef(r) => text.push(resolve_entity(&r)?),
            Event::End(e) => {
                let parent = path.get(path.len().wrapping_sub(2)).map(String::as_str);
                match (e.name().as_ref(), parent) {
                    ("RecycleBinUUID", Some("Meta")) => recycle_bin = text.trim().to_owned(),
                    ("UUID", Some("Group")) => {
                        if let Some(u) = group_uuids.last_mut() {
                            *u = text.trim().to_owned();
                        }
                    }
                    ("Key", Some("String")) => key = text.to_string(),
                    ("Value", Some("String")) => {
                        value = if protected {
                            inner.reveal(&text)?
                        } else {
                            text.to_string()
                        }
                    }
                    ("Group", _) => {
                        group_uuids.pop();
                    }
                    ("History", _) => history_depth -= 1,
                    ("String", _) => {
                        if let Some(entry) = current.as_mut().filter(|_| history_depth == 0) {
                            entry.strings.push((
                                std::mem::take(&mut key),
                                std::mem::take(&mut value),
                                protected,
                            ));
                        }
                    }
                    ("Entry", _) if history_depth == 0 => {
                        if let Some(entry) = current.take() {
                            entries.push((entry, group_uuids.clone()));
                        }
                    }
                    _ => {}
                }
                text.clear();
                path.pop();
            }
            Event::Eof => break,
            _ => {}
        }
    }
    let in_bin = |groups: &[String]| {
        !recycle_bin.is_empty()
            && recycle_bin != "AAAAAAAAAAAAAAAAAAAAAA=="
            && groups.contains(&recycle_bin)
    };
    Ok(entries
        .into_iter()
        .filter(|(_, groups)| !in_bin(groups))
        .map(|(e, _)| e)
        .collect())
}

/// KeePassXC stores TOTP as an otpauth URI in "otp"; KeePass 2.47+ as TimeOtp-* fields.
fn totp_of(e: &Entry) -> String {
    let otp = e.get("otp");
    if !otp.is_empty() {
        return otp.to_owned();
    }
    let secret = e.get("TimeOtp-Secret-Base32");
    if secret.is_empty() {
        return String::new();
    }
    let mut uri = format!("otpauth://totp/?secret={}", secret.replace(' ', ""));
    for (field, param) in [("TimeOtp-Length", "digits"), ("TimeOtp-Period", "period")] {
        let v = e.get(field);
        if !v.is_empty() {
            uri.push_str(&format!("&{param}={v}"));
        }
    }
    if let Some(alg) = Some(e.get("TimeOtp-Algorithm")).filter(|a| !a.is_empty()) {
        uri.push_str(&format!("&algorithm={}", alg.replace("HMAC-", "")));
    }
    uri
}

const STANDARD: [&str; 5] = ["Title", "UserName", "Password", "URL", "Notes"];

fn entry_to_item(e: &Entry, now: u64) -> Option<crate::vault::Item> {
    let extra = e
        .strings
        .iter()
        .filter(|(k, v, _)| {
            !STANDARD.contains(&k.as_str())
                && k != "otp"
                && !k.starts_with("TimeOtp-")
                && !k.starts_with("KPEX_")
                && !v.trim().is_empty()
        })
        .map(|(k, v, p)| (k.clone(), v.clone(), *p))
        .collect();
    let (username, password) = (e.get("UserName"), e.get("Password"));
    let totp = totp_of(e);
    if username.is_empty() && password.is_empty() {
        return note_item(e.get("Title"), e.get("Notes"), false, now);
    }
    login_item(
        Login {
            title: e.get("Title"),
            url: e.get("URL"),
            username,
            password,
            totp: &totp,
            notes: e.get("Notes"),
            favorite: false,
            extra,
        },
        now,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{FieldKind, Item, ItemKind};

    /// Created by KeePassXC 2.8.0 (`keepassxc-cli import`) from testdata/README.md's XML:
    /// KDBX 3.1, AES-256, AES-KDF, Salsa20 inner stream. Password "prueba-kdbx".
    const KDBX31: &[u8] = include_bytes!("testdata/keepassxc-3.1.kdbx");

    fn value<'a>(item: &'a Item, label: &str) -> &'a str {
        item.details
            .fields
            .iter()
            .find(|f| f.label == label)
            .map(|f| f.value.as_str())
            .unwrap_or("")
    }

    fn find<'a>(items: &'a [Item], title: &str) -> &'a Item {
        items
            .iter()
            .find(|i| i.overview.title == title)
            .unwrap_or_else(|| panic!("{title} not imported"))
    }

    fn check_fixture(out: &Imported) {
        assert_eq!(out.format, ImportFormat::Kdbx);
        let titles: Vec<&str> = out
            .items
            .iter()
            .map(|i| i.overview.title.as_str())
            .collect();
        assert_eq!(out.items.len(), 4, "{titles:?}");
        assert!(!titles.contains(&"Borrado"), "the recycle bin is skipped");

        let gh = find(&out.items, "GitHub");
        assert_eq!(
            value(gh, "Contraseña"),
            "nueva-clave <&>",
            "current password, not the one in history"
        );
        assert_eq!(value(gh, "Usuario"), "raul");
        assert_eq!(gh.overview.urls, vec!["https://github.com"]);
        assert!(
            value(gh, "Código TOTP")
                .starts_with("otpauth://totp/GitHub:raul?secret=JBSWY3DPEHPK3PXP")
        );
        assert_eq!(
            gh.details.notes, "cuenta personal & <trabajo>",
            "XML entities in unprotected values"
        );

        let spaces = find(&out.items, "Espacios & Cía");
        assert_eq!(
            value(spaces, "Contraseña"),
            "  con espacios  ",
            "passwords are not trimmed"
        );
        let pin = gh
            .details
            .fields
            .iter()
            .find(|f| f.label == "PIN de recuperación")
            .expect("custom field");
        assert_eq!(
            (pin.kind, pin.value.as_str()),
            (FieldKind::Concealed, "8841")
        );

        let bbva = find(&out.items, "BBVA");
        assert_eq!(value(bbva, "Contraseña"), "bbva-clave");
        assert_eq!(value(bbva, "Usuario"), "12345678Z");

        let note = find(&out.items, "Códigos de recuperación");
        assert_eq!(note.overview.kind, ItemKind::SecureNote);
        assert_eq!(note.details.notes, "abcd-efgh\nijkl-mnop");
    }

    #[test]
    fn keepassxc_kdbx31() {
        assert!(is_kdbx(KDBX31));
        check_fixture(&parse(KDBX31, Some("prueba-kdbx"), None, 0).unwrap());
    }

    #[test]
    fn wrong_password_is_reported_as_such() {
        assert_eq!(
            parse(KDBX31, Some("otra"), None, 0).unwrap_err(),
            Error::WrongCredentials
        );
    }

    #[test]
    fn the_generic_entry_point_asks_for_the_password() {
        assert!(super::super::needs_password(KDBX31));
        let err = super::super::parse(KDBX31, 0).unwrap_err();
        assert!(err.to_string().contains("needs its password"));
        check_fixture(&super::super::parse_with_password(KDBX31, Some("prueba-kdbx"), 0).unwrap());
    }

    #[test]
    fn truncated_or_tampered_files_fail_cleanly() {
        for cut in [12, 100, KDBX31.len() / 2, KDBX31.len() - 1] {
            assert!(
                parse(&KDBX31[..cut], Some("prueba-kdbx"), None, 0).is_err(),
                "cut at {cut}"
            );
        }
        // Flip bytes across the encrypted payload. (Not the very end: KDBX 3.1 does not hash
        // its end-of-blocks marker, which carries no data.)
        for pos in (300..KDBX31.len() - 64).step_by(150) {
            let mut tampered = KDBX31.to_vec();
            tampered[pos] ^= 1;
            assert!(
                parse(&tampered, Some("prueba-kdbx"), None, 0).is_err(),
                "byte {pos}"
            );
        }
    }

    /// Same XML, created with `keepassxc-cli import -p --set-key-file prueba.keyx` (password
    /// plus key file) and without -p (key file only). prueba.keyx is KeePassXC's XML v2.0.
    const WITH_KEY_FILE: &[u8] = include_bytes!("testdata/keepassxc-keyfile.kdbx");
    const KEY_FILE_ONLY: &[u8] = include_bytes!("testdata/keepassxc-keyfile-only.kdbx");
    const KEY_FILE: &[u8] = include_bytes!("testdata/prueba.keyx");

    #[test]
    fn keepassxc_password_and_key_file() {
        check_fixture(&parse(WITH_KEY_FILE, Some("prueba-kdbx"), Some(KEY_FILE), 0).unwrap());
        assert_eq!(
            parse(WITH_KEY_FILE, Some("prueba-kdbx"), None, 0).unwrap_err(),
            Error::WrongCredentials
        );
        assert_eq!(
            parse(WITH_KEY_FILE, None, Some(KEY_FILE), 0).unwrap_err(),
            Error::WrongCredentials
        );
    }

    #[test]
    fn keepassxc_key_file_only() {
        check_fixture(&parse(KEY_FILE_ONLY, None, Some(KEY_FILE), 0).unwrap());
        // From the generic entry point an empty password with a key file means "no password".
        check_fixture(
            &super::super::parse_with_credentials(KEY_FILE_ONLY, Some(""), Some(KEY_FILE), 0)
                .unwrap(),
        );
        assert_eq!(
            parse(KEY_FILE_ONLY, None, Some(b"otro fichero"), 0).unwrap_err(),
            Error::WrongCredentials
        );
    }

    /// Expected keys computed independently (Python's hashlib/base64) from the KeePass formats.
    #[test]
    fn key_file_formats() {
        let raw: Vec<u8> = (0u8..32).collect();
        assert_eq!(key_file_key(&raw).unwrap().to_vec(), raw, "32 raw bytes");
        assert_eq!(
            key_file_key(hex::encode(&raw).as_bytes()).unwrap().to_vec(),
            raw,
            "64 hex characters"
        );
        let v1 = r#"<?xml version="1.0"?><KeyFile><Meta><Version>1.00</Version></Meta><Key><Data>AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=</Data></Key></KeyFile>"#;
        assert_eq!(
            key_file_key(v1.as_bytes()).unwrap().to_vec(),
            raw,
            "XML v1.0"
        );
        let other = b"cualquier fichero que no sea un formato de clave";
        assert_eq!(
            hex::encode(*key_file_key(other).unwrap()),
            "5ebff97d9a2b92f9568bd36862ead137d15aa0a12afb66ea0be6f46d1b12f984",
            "any other file: SHA-256",
        );
        let v2 = key_file_key(KEY_FILE).unwrap();
        assert_eq!(
            hex::encode_upper(*v2),
            "D9995D963C987AA29E5DE77457997E09466E3EB259CCFF5C03C6D82154E91AD0",
            "XML v2.0"
        );
        let tampered = std::str::from_utf8(KEY_FILE)
            .unwrap()
            .replace("A678D36A", "00000000");
        assert!(
            key_file_key(tampered.as_bytes())
                .unwrap_err()
                .to_string()
                .contains("damaged"),
            "v2 hash is checked"
        );
    }

    #[test]
    fn costly_kdf_is_refused() {
        assert!(
            aes_kdf(&[0; 32], &[0; 32], MAX_AES_ROUNDS + 1)
                .unwrap_err()
                .to_string()
                .contains("too costly")
        );
    }
}
