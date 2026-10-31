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
/// Same ceiling as the platform one (`MOBILE_MAXIMUM` in `op-ffi`: 512 MiB, 6 passes), so a
/// hostile `.kdbx` cannot ask a phone for more than a `.opvault` backup could.
const MAX_ARGON2_BYTES: u64 = 512 << 20;
const MAX_ARGON2_ITERATIONS: u64 = 1_000;
/// Joint Argon2 budget, `memory × iterations` in bytes: 3 GiB·pass, the platform ceiling's
/// 512 MiB × 6. The separate caps above alone allowed 512 MiB × 1000.
const MAX_ARGON2_WORK: u64 = 3 << 30;

// Limits on the decrypted XML. Real databases nest groups a dozen levels deep and hold a
// few thousand entries; a hostile one must not turn that into unbounded work or memory.
/// Open `<Group>` elements at once.
const MAX_GROUP_DEPTH: usize = 100;
/// Open elements at once, of any kind.
const MAX_XML_DEPTH: usize = 256;
/// Entries outside the history.
const MAX_ENTRIES: usize = 100_000;

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
    protected_stream_key: Zeroizing<Vec<u8>>,
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
    let (h, v4, header_end) = read_header(bytes)?;

    // Composite key: SHA-256 of the password hash followed by the key file's key.
    let mut composite = Sha256::new();
    if let Some(p) = password {
        composite.update(Sha256::digest(p.as_bytes()));
    }
    if let Some(k) = key_file {
        composite.update(*key_file_key(k)?);
    }
    let composite = Zeroizing::new(composite.finalize().to_vec());
    let transformed = if v4 {
        kdf_v4(&h.kdf, &composite)?
    } else {
        aes_kdf(&composite, &h.transform_seed, h.transform_rounds)?
    };
    open_payload(bytes, &h, v4, header_end, &transformed, now)
}

/// The outer header: `(fields, is KDBX 4, offset where the header ends)`.
fn read_header(bytes: &[u8]) -> Result<(Header, bool, usize)> {
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
            8 => h.protected_stream_key = Zeroizing::new(data.to_vec()),
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

    Ok((h, v4, header_end))
}

/// Argon2 cost a KDBX 4 file declares in its header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Cost {
    pub memory_kib: u64,
    pub iterations: u64,
    pub lanes: u64,
}

/// The Argon2 cost declared by the header of a KDBX file, or `None` if its key derivation
/// needs no memory worth checking (AES-KDF, KDBX 3.1). Reads only the unauthenticated header:
/// no secret, no KDF. It does not apply the ceiling: [`parse`] refuses what is above it.
pub fn argon2_cost(bytes: &[u8]) -> Result<Option<Argon2Cost>> {
    let (h, v4, _) = read_header(bytes)?;
    if !v4 {
        return Ok(None);
    }
    let uuid = dict_get(&h.kdf, "$UUID").ok_or(Error::Malformed("KDBX KDF"))?;
    if uuid != KDF_ARGON2D && uuid != KDF_ARGON2ID {
        return Ok(None);
    }
    let get = |key: &str| dict_u64(&h.kdf, key).ok_or(Error::Malformed("KDBX KDF"));
    Ok(Some(Argon2Cost {
        memory_kib: get("M")? / 1024,
        iterations: get("I")?,
        lanes: get("P")?,
    }))
}

/// Everything behind the key derivation: checks, blocks, outer cipher, gunzip, XML.
fn open_payload(
    bytes: &[u8],
    h: &Header,
    v4: bool,
    header_end: usize,
    transformed: &[u8],
    now: u64,
) -> Result<Imported> {
    let mut c = Cursor {
        data: bytes,
        pos: header_end,
    };
    let mut hasher = Sha256::new();
    hasher.update(&h.master_seed);
    hasher.update(transformed);
    let cipher_key = Zeroizing::new(hasher.finalize().to_vec());

    let ciphertext: Vec<u8> = if v4 {
        let stored_hash = c.take(32)?;
        if Sha256::digest(&bytes[..header_end]).as_slice() != stored_hash {
            return Err(Error::Malformed("KDBX header checksum"));
        }
        let mut hmac_base = Sha512::new();
        hmac_base.update(&h.master_seed);
        hmac_base.update(transformed);
        hmac_base.update([1u8]);
        let hmac_base = Zeroizing::new(hmac_base.finalize().to_vec());
        let block_key = |index: u64| block_key(&hmac_base, index);
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
                2 => stream_key = Zeroizing::new(data.to_vec()),
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
    let to_key = |v: &[u8]| -> Result<Zeroizing<[u8; 32]>> {
        Ok(Zeroizing::new(v.try_into().map_err(|_| damaged())?))
    };

    if let Some(xml) = std::str::from_utf8(data)
        .ok()
        .filter(|t| t.contains("<KeyFile>"))
    {
        let (version, data_text, hash) = key_file_xml(xml)?;
        return if version.starts_with("2.") {
            let hex: Zeroizing<String> =
                Zeroizing::new(data_text.chars().filter(|c| !c.is_whitespace()).collect());
            let key = to_key(&decode_hex(&hex).ok_or_else(damaged)?)?;
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
            to_key(&Zeroizing::new(
                base64::engine::general_purpose::STANDARD
                    .decode(data_text.trim())
                    .map_err(|_| damaged())?,
            ))
        };
    }
    if data.len() == 32 {
        return to_key(data);
    }
    if data.len() == 64 {
        if let Some(key) = std::str::from_utf8(data).ok().and_then(decode_hex) {
            return to_key(&key);
        }
    }
    to_key(&Sha256::digest(data))
}

/// (Version, Data text, Data@Hash) of a key file.
fn key_file_xml(xml: &str) -> Result<(String, Zeroizing<String>, Option<String>)> {
    let mut reader = Reader::from_str(xml);
    let (mut version, mut data, mut hash) = (String::new(), Zeroizing::new(String::new()), None);
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

fn decode_hex(s: &str) -> Option<Zeroizing<Vec<u8>>> {
    if s.len() % 2 != 0 {
        return None;
    }
    // Pushed into a wiped buffer, so a bad digit halfway does not leave a partial key behind.
    let mut out = Zeroizing::new(Vec::with_capacity(s.len() / 2));
    for i in (0..s.len()).step_by(2) {
        out.push(u8::from_str_radix(s.get(i..i + 2)?, 16).ok()?);
    }
    Some(out)
}

fn block_key(hmac_base: &[u8], index: u64) -> Zeroizing<Vec<u8>> {
    let mut k = Sha512::new();
    k.update(index.to_le_bytes());
    k.update(hmac_base);
    Zeroizing::new(k.finalize().to_vec())
}

fn hmac_sha256(key: &[u8]) -> Hmac<Sha256> {
    <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts keys of any length")
}

fn kdf_v4(dict: &[(String, Vec<u8>)], composite: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
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
    check_argon2_cost(memory, iterations, lanes)?;
    let params = Params::new(
        (memory / 1024) as u32,
        iterations as u32,
        lanes as u32,
        Some(32),
    )
    .map_err(|_| Error::Malformed("KDBX Argon2 parameters"))?;
    let mut out = Zeroizing::new(vec![0u8; 32]);
    Argon2::new(algorithm, version, params)
        .hash_password_into(composite, salt, &mut out)
        .map_err(|_| Error::Kdf)?;
    Ok(out)
}

fn check_argon2_cost(memory: u64, iterations: u64, lanes: u64) -> Result<()> {
    if memory > MAX_ARGON2_BYTES
        || iterations > MAX_ARGON2_ITERATIONS
        || lanes > 64
        || memory * iterations > MAX_ARGON2_WORK
    {
        return Err(bad(
            "this KeePass database cannot be imported: its key derivation is too costly for this device (Argon2 above 512 MiB of memory or 3 GiB·pass of work); lower it in KeePass and export again",
        ));
    }
    Ok(())
}

/// KeePass AES-KDF: encrypt both halves of the key `rounds` times with AES-256-ECB, then SHA-256.
fn aes_kdf(composite: &[u8], seed: &[u8], rounds: u64) -> Result<Zeroizing<Vec<u8>>> {
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
    Ok(Zeroizing::new(Sha256::digest(key.as_slice()).to_vec()))
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

    fn reveal(&mut self, b64: &str) -> Result<Zeroizing<String>> {
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
        // Validated in place: `String::from_utf8` would hand the bytes back unwiped on error.
        std::str::from_utf8(&data)
            .map(|s| Zeroizing::new(s.to_owned()))
            .map_err(|_| Error::Malformed("KDBX protected value"))
    }
}

struct Group {
    uuid: String,
    parent: Option<usize>,
}

#[derive(Default)]
struct Entry {
    strings: Vec<(String, Zeroizing<String>, bool)>,
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

    /// Stands for the output of the KDF. Not secret: it exists so that the code behind the
    /// KDF (whose cost the file sets) can be fuzzed.
    const TRANSFORMED_KEY: [u8; 32] = [9; 32];

    fn open(file: &[u8]) {
        if let Ok((header, v4, end)) = super::read_header(file) {
            if let Ok(imported) = super::open_payload(file, &header, v4, end, &TRANSFORMED_KEY, 0) {
                assert!(imported.items.len() + imported.skipped <= super::MAX_ENTRIES);
            }
        }
    }

    /// Any file that starts like a KDBX: header parsing, then the checks that a file not
    /// made with [`TRANSFORMED_KEY`] fails (header hash and HMAC, or the start bytes).
    pub fn file(data: &[u8]) {
        if super::is_kdbx(data) {
            open(data);
        }
    }

    /// Builds a file that passes those checks, so that the block framing, the outer
    /// cipher, gunzip, the inner header and the XML are reached. The first byte picks the
    /// shape: bit 0 KDBX 4 (else 3.1), bit 1 gzip, bit 2 ChaCha20 (else AES-256), bit 3
    /// ChaCha20 inner stream (else Salsa20), bit 4 (3.1 only) the rest is the whole
    /// hashed-block stream instead of one well-formed block. The rest is the payload.
    pub fn container(data: &[u8]) {
        let Some((&flags, payload)) = data.split_first() else {
            return;
        };
        open(&seal(flags, payload));
    }

    fn field(out: &mut Vec<u8>, v4: bool, id: u8, data: &[u8]) {
        out.push(id);
        if v4 {
            out.extend((data.len() as u32).to_le_bytes());
        } else {
            out.extend((data.len() as u16).to_le_bytes());
        }
        out.extend(data);
    }

    fn encrypt(chacha: bool, key: &[u8], iv: &[u8], plain: &[u8]) -> Vec<u8> {
        use aes::cipher::{BlockEncryptMut, KeyIvInit, StreamCipher, block_padding::Pkcs7};
        if chacha {
            let mut data = plain.to_vec();
            chacha20::ChaCha20::new_from_slices(key, iv)
                .expect("32-byte key, 12-byte IV")
                .apply_keystream(&mut data);
            data
        } else {
            cbc::Encryptor::<aes::Aes256>::new_from_slices(key, iv)
                .expect("32-byte key, 16-byte IV")
                .encrypt_padded_vec_mut::<Pkcs7>(plain)
        }
    }

    fn seal(flags: u8, payload: &[u8]) -> Vec<u8> {
        use hmac::Mac;
        use sha2::{Digest, Sha256, Sha512};

        let (v4, gzip, chacha) = (flags & 1 != 0, flags & 2 != 0, flags & 4 != 0);
        let seed = [1u8; 32];
        let iv = [2u8; 16];
        let iv = if chacha { &iv[..12] } else { &iv[..] };
        let mut header = super::SIGNATURE.to_vec();
        header.extend(0u16.to_le_bytes());
        header.extend(if v4 { 4u16 } else { 3u16 }.to_le_bytes());
        let cipher = if chacha {
            super::CIPHER_CHACHA20
        } else {
            super::CIPHER_AES256
        };
        field(&mut header, v4, 2, &cipher);
        field(&mut header, v4, 3, &u32::from(gzip).to_le_bytes());
        field(&mut header, v4, 4, &seed);
        field(&mut header, v4, 7, iv);
        let start_bytes = [3u8; 32];
        if !v4 {
            field(&mut header, v4, 8, &[4; 32]);
            field(&mut header, v4, 9, &start_bytes);
            let inner = if flags & 8 != 0 { 3u32 } else { 2 };
            field(&mut header, v4, 10, &inner.to_le_bytes());
        }
        field(&mut header, v4, 0, &[]);

        let cipher_key = Sha256::new()
            .chain_update(seed)
            .chain_update(TRANSFORMED_KEY)
            .finalize();
        let mut file = header.clone();
        if v4 {
            let hmac_base = Sha512::new()
                .chain_update(seed)
                .chain_update(TRANSFORMED_KEY)
                .chain_update([1u8])
                .finalize();
            file.extend(Sha256::digest(&header));
            let mut mac = super::hmac_sha256(&super::block_key(&hmac_base, u64::MAX));
            mac.update(&header);
            file.extend(mac.finalize().into_bytes());
            let body = encrypt(chacha, &cipher_key, iv, payload);
            for (index, data) in [(0u64, body.as_slice()), (1, &[][..])] {
                let size = (data.len() as i32).to_le_bytes();
                let mut mac = super::hmac_sha256(&super::block_key(&hmac_base, index));
                mac.update(&index.to_le_bytes());
                mac.update(&size);
                mac.update(data);
                file.extend(mac.finalize().into_bytes());
                file.extend(size);
                file.extend(data);
            }
        } else {
            let mut plain = start_bytes.to_vec();
            if flags & 16 != 0 {
                plain.extend(payload);
            } else {
                plain.extend(0u32.to_le_bytes());
                plain.extend(Sha256::digest(payload));
                plain.extend((payload.len() as u32).to_le_bytes());
                plain.extend(payload);
                plain.extend(1u32.to_le_bytes());
                plain.extend([0; 32]);
                plain.extend(0u32.to_le_bytes());
            }
            file.extend(encrypt(chacha, &cipher_key, iv, &plain));
        }
        file
    }
}

fn read_entries(xml: &str, inner: &mut InnerStream) -> Result<Vec<Entry>> {
    let mut reader = Reader::from_str(xml);
    let malformed = |_| Error::Malformed("KDBX XML");

    let mut path: Vec<String> = Vec::new();
    let mut text = Zeroizing::new(String::new());
    let mut recycle_bin = String::new();
    // Every group seen, once; `open` holds the indices of the currently open ones, innermost
    // last. An entry keeps only the index of its group, so memory is linear in the input.
    let mut groups: Vec<Group> = Vec::new();
    let mut open: Vec<usize> = Vec::new();
    let mut entries: Vec<(Entry, Option<usize>)> = Vec::new();
    let mut current: Option<Entry> = None;
    let mut history_depth = 0;
    let (mut key, mut value, mut protected) = (String::new(), Zeroizing::new(String::new()), false);

    loop {
        match reader.read_event().map_err(malformed)? {
            Event::Start(e) => {
                let name = e.name().as_ref().to_owned();
                text.clear();
                if path.len() >= MAX_XML_DEPTH {
                    return Err(bad(
                        "this KeePass database cannot be imported: its XML nests too deeply",
                    ));
                }
                match name.as_str() {
                    "Group" => {
                        if open.len() >= MAX_GROUP_DEPTH {
                            return Err(bad(
                                "this KeePass database cannot be imported: its groups nest too deeply",
                            ));
                        }
                        groups.push(Group {
                            uuid: String::new(),
                            parent: open.last().copied(),
                        });
                        open.push(groups.len() - 1);
                    }
                    "Entry" if history_depth == 0 => current = Some(Entry::default()),
                    "History" => history_depth += 1,
                    "String" => {
                        (key, value, protected) =
                            (String::new(), Zeroizing::new(String::new()), false)
                    }
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
                        if let Some(&g) = open.last() {
                            groups[g].uuid = text.trim().to_owned();
                        }
                    }
                    ("Key", Some("String")) => key = text.to_string(),
                    ("Value", Some("String")) => {
                        value = if protected {
                            inner.reveal(&text)?
                        } else {
                            Zeroizing::new(text.to_string())
                        }
                    }
                    ("Group", _) => {
                        open.pop();
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
                            if entries.len() >= MAX_ENTRIES {
                                return Err(bad(
                                    "this KeePass database cannot be imported: it has too many entries",
                                ));
                            }
                            entries.push((entry, open.last().copied()));
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
    let bin_enabled = !recycle_bin.is_empty() && recycle_bin != "AAAAAAAAAAAAAAAAAAAAAA==";
    // An entry is in the bin when its group or any ancestor is the bin group.
    let in_bin = |group: Option<usize>| {
        bin_enabled
            && std::iter::successors(group, |&g| groups[g].parent)
                .any(|g| groups[g].uuid == recycle_bin)
    };
    Ok(entries
        .into_iter()
        .filter(|(_, group)| !in_bin(*group))
        .map(|(e, _)| e)
        .collect())
}

/// KeePassXC stores TOTP as an otpauth URI in "otp"; KeePass 2.47+ as TimeOtp-* fields.
fn totp_of(e: &Entry) -> Zeroizing<String> {
    let otp = e.get("otp");
    if !otp.is_empty() {
        return Zeroizing::new(otp.to_owned());
    }
    let secret = e.get("TimeOtp-Secret-Base32");
    if secret.is_empty() {
        return Zeroizing::new(String::new());
    }
    let mut uri = Zeroizing::new(format!(
        "otpauth://totp/?secret={}",
        secret.replace(' ', "")
    ));
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

    /// Same XML, created with `keepassxc-cli import -p --set-key-file sample.keyx` (password
    /// plus key file) and without -p (key file only). sample.keyx is KeePassXC's XML v2.0.
    const WITH_KEY_FILE: &[u8] = include_bytes!("testdata/keepassxc-keyfile.kdbx");
    const KEY_FILE_ONLY: &[u8] = include_bytes!("testdata/keepassxc-keyfile-only.kdbx");
    const KEY_FILE: &[u8] = include_bytes!("testdata/sample.keyx");

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
    fn decode_hex_rejects_odd_and_bad_digits() {
        assert_eq!(decode_hex("0aFF").unwrap().as_slice(), [0x0a, 0xff]);
        assert!(decode_hex("abc").is_none(), "odd length");
        assert!(decode_hex("0aZZ").is_none(), "not hex");
        assert!(decode_hex("").unwrap().is_empty());
    }

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

    fn kdbx4_header(kdf: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut dict = vec![0x00, 0x01];
        for (key, value) in kdf {
            dict.push(0x42);
            dict.extend((key.len() as i32).to_le_bytes());
            dict.extend(key.as_bytes());
            dict.extend((value.len() as i32).to_le_bytes());
            dict.extend(value);
        }
        dict.push(0);
        let mut out = SIGNATURE.to_vec();
        out.extend([1, 0, 4, 0]);
        for (id, data) in [(4u8, vec![5u8; 32]), (11, dict), (0, vec![])] {
            out.push(id);
            out.extend((data.len() as u32).to_le_bytes());
            out.extend(data);
        }
        out
    }

    #[test]
    fn argon2_cost_is_read_from_the_header_without_running_the_kdf() {
        let argon = |uuid: [u8; 16], m: u64, t: u64, p: u32| {
            kdbx4_header(&[
                ("$UUID", uuid.to_vec()),
                ("S", vec![3; 32]),
                ("M", m.to_le_bytes().to_vec()),
                ("I", t.to_le_bytes().to_vec()),
                ("P", p.to_le_bytes().to_vec()),
            ])
        };
        let cost = |m_kib, iterations, lanes| {
            Some(Argon2Cost {
                memory_kib: m_kib,
                iterations,
                lanes,
            })
        };
        assert_eq!(
            argon2_cost(&argon(KDF_ARGON2D, 64 << 20, 2, 2)).unwrap(),
            cost(65_536, 2, 2)
        );
        // The edge of the ceiling, and a header above it: reported as is, `parse` refuses it.
        assert_eq!(
            argon2_cost(&argon(KDF_ARGON2ID, MAX_ARGON2_BYTES, 6, 4)).unwrap(),
            cost(524_288, 6, 4)
        );
        assert_eq!(
            argon2_cost(&argon(KDF_ARGON2ID, 4 << 30, 1, 1)).unwrap(),
            cost(4_194_304, 1, 1)
        );
        let too_big = argon(KDF_ARGON2ID, 4 << 30, 1, 1);
        assert!(
            parse(&too_big, Some("x"), None, 0)
                .unwrap_err()
                .to_string()
                .contains("cannot be imported")
        );
    }

    #[test]
    fn argon2_cost_is_none_without_argon2_and_errors_on_damaged_headers() {
        assert_eq!(argon2_cost(KDBX31).unwrap(), None, "KDBX 3.1 uses AES-KDF");
        let aes = kdbx4_header(&[
            ("$UUID", KDF_AES.to_vec()),
            ("S", vec![1; 32]),
            ("R", 6000u64.to_le_bytes().to_vec()),
        ]);
        assert_eq!(argon2_cost(&aes).unwrap(), None);
        let no_params = kdbx4_header(&[("$UUID", KDF_ARGON2ID.to_vec())]);
        assert!(argon2_cost(&no_params).is_err());
        assert!(argon2_cost(&kdbx4_header(&[])).is_err(), "no $UUID");
        assert!(argon2_cost(&SIGNATURE).is_err(), "truncated");
        assert_eq!(super::super::kdbx_argon2_cost(b"a,b\n1,2").unwrap(), None);
    }

    #[test]
    fn argon2_budget_accepts_the_edge_and_refuses_above_it() {
        const MIB: u64 = 1 << 20;
        // 512 MiB × 6 and 64 MiB × 48 sit exactly on the 3 GiB·pass budget.
        assert!(check_argon2_cost(512 * MIB, 6, 4).is_ok());
        assert!(check_argon2_cost(64 * MIB, 48, 4).is_ok());
        // Typical KeePass defaults stay far below it.
        assert!(check_argon2_cost(64 * MIB, 2, 2).is_ok());
        // One step above the budget, and the old 1 GiB budget.
        for (m, t) in [
            (512 * MIB, 7),
            (64 * MIB, 49),
            (1024 * MIB, 1),
            (512 * MIB, 1000),
        ] {
            assert!(
                check_argon2_cost(m, t, 4)
                    .unwrap_err()
                    .to_string()
                    .contains("cannot be imported"),
                "{m} × {t}"
            );
        }
        // The individual caps still apply.
        assert!(check_argon2_cost(512 * MIB + 1, 1, 1).is_err());
        assert!(check_argon2_cost(MIB, 1001, 1).is_err());
        assert!(check_argon2_cost(MIB, 1, 65).is_err());
    }

    fn nested_xml(groups: usize, entries: usize) -> String {
        let mut xml = String::from("<KeePassFile><Root>");
        xml.push_str(&"<Group>".repeat(groups));
        xml.push_str(&"<Entry></Entry>".repeat(entries));
        xml.push_str(&"</Group>".repeat(groups));
        xml.push_str("</Root></KeePassFile>");
        xml
    }

    fn read(xml: &str) -> Result<Vec<Entry>> {
        read_entries(xml, &mut InnerStream::new(3, &[7; 64]).unwrap())
    }

    #[test]
    fn deep_group_nesting_is_refused_before_it_costs_memory() {
        // 180 KB of XML: 5000 nested groups and 7000 entries. Cloning the stack of open
        // groups per entry took ~900 MB of RSS for this file.
        let xml = nested_xml(5000, 7000);
        assert!(xml.len() < 200_000);
        let err = read(&xml).err().expect("refused");
        assert!(err.to_string().contains("nest too deeply"), "{err}");
        let deep = format!(
            "{}{}",
            "<a>".repeat(MAX_XML_DEPTH + 1),
            "</a>".repeat(MAX_XML_DEPTH + 1)
        );
        assert!(
            read(&deep)
                .err()
                .expect("refused")
                .to_string()
                .contains("nests too deeply")
        );
    }

    #[test]
    fn nesting_and_entry_limits_accept_their_edge() {
        assert_eq!(read(&nested_xml(MAX_GROUP_DEPTH, 10)).unwrap().len(), 10);
        assert!(read(&nested_xml(MAX_GROUP_DEPTH + 1, 10)).is_err());
        assert_eq!(
            read(&nested_xml(MAX_GROUP_DEPTH, MAX_ENTRIES))
                .unwrap()
                .len(),
            MAX_ENTRIES
        );
        let err = read(&nested_xml(MAX_GROUP_DEPTH, MAX_ENTRIES + 1))
            .err()
            .expect("refused");
        assert!(err.to_string().contains("too many entries"), "{err}");
    }

    #[test]
    fn recycle_bin_applies_to_every_descendant_group() {
        let xml = "<KeePassFile><Meta><RecycleBinUUID>BIN</RecycleBinUUID></Meta><Root>\
            <Group><UUID>ROOT</UUID>\
              <Entry><String><Key>Title</Key><Value>kept</Value></String></Entry>\
              <Group><UUID>BIN</UUID>\
                <Entry><String><Key>Title</Key><Value>in bin</Value></String></Entry>\
                <Group><UUID>SUB</UUID>\
                  <Entry><String><Key>Title</Key><Value>deeper in bin</Value></String></Entry>\
                </Group>\
              </Group>\
              <Group><UUID>OTHER</UUID>\
                <Entry><String><Key>Title</Key><Value>sibling</Value></String></Entry>\
              </Group>\
            </Group></Root></KeePassFile>";
        let titles: Vec<_> = read(xml)
            .unwrap()
            .iter()
            .map(|e| e.get("Title").to_owned())
            .collect();
        assert_eq!(titles, ["kept", "sibling"]);
    }
}
