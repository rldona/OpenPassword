//! Import from other password managers' plaintext exports.
//!
//! Supported: CSV from Chrome / Google Password Manager, Firefox, Bitwarden and 1Password
//! (columns are matched by name, so similar CSVs work too), Bitwarden's unencrypted JSON
//! 1Password's `.1pux` export (a ZIP with `export.data` in JSON) and password-protected
//! KeePass databases (KDBX 3.1 and 4.x, see [`kdbx`]).
//! The input is plaintext secrets: callers should offer to delete the file afterwards.
//!
//! Secrets in memory (docs/threat-model.md, A15). Every buffer that holds a password while
//! importing is a [`Zeroizing`] value or is wiped by hand: the input copy of a `.1pux`, the CSV
//! fields, the parsed JSON tree ([`WipedJson`]), the values of KeePass entries and key files,
//! and the keys derived from the KeePass password. Accepted leftovers, which this crate cannot
//! reach:
//! - the bytes a growing `String`/`Vec` leaves behind when it reallocates (CSV field, XML text,
//!   JSON strings while `serde_json` builds them) and `serde_json`'s own scratch buffers;
//! - the object keys of the JSON tree (field names, not values) and numbers;
//! - the stack temporaries of the hash functions (`sha2` is built without its `zeroize` feature);
//! - the files' own non-secret header data (KDBX seeds, salts);
//! - what happens after the items cross the FFI: the `String`s of `ImportedItemRecord`, the
//!   `RustBuffer` UniFFI frees without wiping, and everything on the JVM side.

mod kdbx;
pub use kdbx::Argon2Cost;
#[cfg(fuzzing)]
pub use kdbx::fuzzing as kdbx_fuzzing;

use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

use crate::vault::{Field, FieldKind, Item, ItemDetails, ItemKind, ItemOverview};
use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportFormat {
    Csv,
    BitwardenJson,
    OnePassword1pux,
    Kdbx,
}

#[derive(Debug)]
pub struct Imported {
    pub format: ImportFormat,
    pub items: Vec<Item>,
    /// Entries of a kind OpenPassword does not import yet (identities, SSH keys…) or empty rows.
    pub skipped: usize,
}

const MAX_INPUT: usize = 32 * 1024 * 1024;

/// True for formats that are encrypted and need the source manager's password (KeePass).
pub fn needs_password(bytes: &[u8]) -> bool {
    kdbx::is_kdbx(bytes)
}

/// The Argon2 cost a KeePass file declares, so the app can compare it with the device's
/// memory **before** [`parse_with_credentials`] runs the KDF. `None` if `bytes` is not KDBX or
/// its key derivation needs no memory worth checking (AES-KDF). Carries no secret.
pub fn kdbx_argon2_cost(bytes: &[u8]) -> Result<Option<Argon2Cost>> {
    if !kdbx::is_kdbx(bytes) {
        return Ok(None);
    }
    kdbx::argon2_cost(bytes)
}

/// Detects the format and converts every entry. `now` (Unix seconds) stamps the items.
pub fn parse(bytes: &[u8], now: u64) -> Result<Imported> {
    parse_with_password(bytes, None, now)
}

/// Like [`parse`], with the password for encrypted formats (see [`needs_password`]).
pub fn parse_with_password(bytes: &[u8], password: Option<&str>, now: u64) -> Result<Imported> {
    parse_with_credentials(bytes, password, None, now)
}

/// Like [`parse_with_password`], also with a KeePass key file. With a key file an empty
/// password means "no password", as in KeePass.
pub fn parse_with_credentials(
    bytes: &[u8],
    password: Option<&str>,
    key_file: Option<&[u8]>,
    now: u64,
) -> Result<Imported> {
    if bytes.len() > MAX_INPUT {
        return Err(Error::InvalidInput("file too large to import"));
    }
    if kdbx::is_kdbx(bytes) {
        let password = match (password, key_file) {
            (Some(""), Some(_)) => None,
            (p, _) => p,
        };
        if password.is_none() && key_file.is_none() {
            return Err(Error::InvalidInput(
                "this KeePass database needs its password",
            ));
        }
        return kdbx::parse(bytes, password, key_file, now);
    }
    if bytes.starts_with(b"PK\x03\x04") {
        return parse_1pux(bytes, now);
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error::InvalidInput("the file is not UTF-8 text"))?;
    let text = text.trim_start_matches('\u{feff}');
    if text.trim_start().starts_with('{') {
        parse_bitwarden_json(text, now)
    } else {
        parse_csv(text, now)
    }
}

// ---------------------------------------------------------------- items

struct Login<'a> {
    title: &'a str,
    url: &'a str,
    username: &'a str,
    password: &'a str,
    totp: &'a str,
    notes: &'a str,
    favorite: bool,
    extra: Vec<(String, Zeroizing<String>, bool)>,
}

fn overview(
    kind: ItemKind,
    title: &str,
    subtitle: Option<String>,
    urls: Vec<String>,
    favorite: bool,
    now: u64,
) -> ItemOverview {
    ItemOverview {
        kind,
        title: if title.trim().is_empty() {
            default_title(kind).into()
        } else {
            title.trim().into()
        },
        subtitle,
        urls,
        tags: vec!["importado".into()],
        favorite,
        created_at: now,
        updated_at: now,
    }
}

fn default_title(kind: ItemKind) -> &'static str {
    match kind {
        ItemKind::Card => "Tarjeta",
        ItemKind::SecureNote => "Nota",
        _ => "Sin nombre",
    }
}

/// Secrets are kept byte for byte: a password may start or end with spaces. Other values
/// (usernames, names, dates) are trimmed. Blank values are dropped.
fn field(label: &str, kind: FieldKind, value: &str) -> Option<Field> {
    if value.trim().is_empty() {
        return None;
    }
    let keep_exact = matches!(kind, FieldKind::Concealed | FieldKind::Pin);
    Some(Field::new(
        label,
        kind,
        if keep_exact { value } else { value.trim() },
    ))
}

fn login_item(l: Login<'_>, now: u64) -> Option<Item> {
    if l.username.trim().is_empty() && l.password.trim().is_empty() && l.notes.trim().is_empty() {
        return None;
    }
    let title = if l.title.trim().is_empty() {
        host_of(l.url).unwrap_or_default()
    } else {
        l.title.to_owned()
    };
    let username_kind = if l.username.contains('@') {
        FieldKind::Email
    } else {
        FieldKind::Text
    };
    let mut fields: Vec<Field> = [
        field("Usuario", username_kind, l.username),
        field("Contraseña", FieldKind::Concealed, l.password),
        field("Código TOTP", FieldKind::Totp, l.totp),
    ]
    .into_iter()
    .flatten()
    .collect();
    fields.extend(l.extra.into_iter().filter_map(|(label, value, hidden)| {
        field(
            &label,
            if hidden {
                FieldKind::Concealed
            } else {
                FieldKind::Text
            },
            &value,
        )
    }));
    let subtitle = Some(l.username.trim().to_owned()).filter(|s| !s.is_empty());
    let urls = Some(l.url.trim().to_owned())
        .filter(|s| !s.is_empty())
        .into_iter()
        .collect();
    Some(Item {
        overview: overview(ItemKind::Login, &title, subtitle, urls, l.favorite, now),
        details: ItemDetails {
            fields,
            notes: l.notes.trim().to_owned(),
            history: Vec::new(),
        },
    })
}

fn note_item(title: &str, notes: &str, favorite: bool, now: u64) -> Option<Item> {
    if notes.trim().is_empty() {
        return None;
    }
    Some(Item {
        overview: overview(ItemKind::SecureNote, title, None, vec![], favorite, now),
        details: ItemDetails {
            fields: vec![],
            notes: notes.trim().to_owned(),
            history: Vec::new(),
        },
    })
}

fn host_of(url: &str) -> Option<String> {
    let rest = url.trim().split_once("://").map_or(url.trim(), |(_, r)| r);
    let host = rest
        .split(['/', '?', '#', ':'])
        .next()?
        .trim_start_matches("www.");
    (!host.is_empty()).then(|| host.to_owned())
}

fn truthy(v: &str) -> bool {
    matches!(
        v.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "sí" | "si"
    )
}

// ---------------------------------------------------------------- CSV

/// RFC 4180: quoted fields may contain commas, quotes ("") and line breaks.
fn csv_records(text: &str) -> Result<Vec<Vec<Zeroizing<String>>>> {
    let mut records = Vec::new();
    let mut record = Vec::new();
    let mut field = Zeroizing::new(String::new());
    let mut quoted = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match (quoted, c) {
            (true, '"') if chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            (true, '"') => quoted = false,
            (true, c) => field.push(c),
            (false, '"') if field.is_empty() => quoted = true,
            (false, ',') => record.push(std::mem::take(&mut field)),
            (false, '\r') => {}
            (false, '\n') => {
                record.push(std::mem::take(&mut field));
                records.push(std::mem::take(&mut record));
            }
            (false, c) => field.push(c),
        }
    }
    if quoted {
        return Err(Error::InvalidInput("the CSV has an unclosed quote"));
    }
    if !field.is_empty() || !record.is_empty() {
        record.push(field);
        records.push(record);
    }
    // `retain` drops the discarded rows, and each field wipes itself.
    records.retain(|r| r.iter().any(|f| !f.trim().is_empty()));
    Ok(records)
}

fn parse_csv(text: &str, now: u64) -> Result<Imported> {
    let mut records = csv_records(text)?.into_iter();
    let header: Vec<String> = records
        .next()
        .ok_or(Error::InvalidInput("the file is empty"))?
        .iter()
        .map(|h| h.trim().to_ascii_lowercase())
        .collect();
    let col = |names: &[&str]| header.iter().position(|h| names.contains(&h.as_str()));

    let title = col(&["name", "title", "nombre", "título"]);
    let url = col(&["url", "login_uri", "website", "web site", "uri"]);
    let username = col(&[
        "username",
        "login_username",
        "user name",
        "user",
        "email",
        "usuario",
    ]);
    let password = col(&["password", "login_password", "contraseña"]);
    let totp = col(&["login_totp", "otpauth", "totp", "one-time password"]);
    let notes = col(&["note", "notes", "extra", "comments", "notas"]);
    let favorite = col(&["favorite", "fav"]);
    let kind = col(&["type"]);
    if password.is_none() && notes.is_none() {
        return Err(Error::InvalidInput(
            "not a recognised password export: no password column",
        ));
    }

    let mut items = Vec::new();
    let mut skipped = 0;
    for r in records {
        let get = |c: Option<usize>| c.and_then(|i| r.get(i)).map(|f| f.as_str()).unwrap_or("");
        let item = match get(kind).trim().to_ascii_lowercase().as_str() {
            "" | "login" => login_item(
                Login {
                    title: get(title),
                    url: get(url),
                    username: get(username),
                    password: get(password),
                    totp: get(totp),
                    notes: get(notes),
                    favorite: truthy(get(favorite)),
                    extra: vec![],
                },
                now,
            ),
            "note" | "securenote" => note_item(get(title), get(notes), truthy(get(favorite)), now),
            _ => None,
        };
        match item {
            Some(i) => items.push(i),
            None => skipped += 1,
        }
    }
    Ok(Imported {
        format: ImportFormat::Csv,
        items,
        skipped,
    })
}

// ---------------------------------------------------------------- Bitwarden JSON

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

/// A parsed JSON document whose strings are wiped when it is dropped, whichever path leaves
/// the parser (including the `?` returns). Object keys are not wiped: they are field names.
struct WipedJson(Value);

impl std::ops::Deref for WipedJson {
    type Target = Value;
    fn deref(&self) -> &Value {
        &self.0
    }
}

impl Drop for WipedJson {
    fn drop(&mut self) {
        wipe_json(&mut self.0);
    }
}

fn wipe_json(v: &mut Value) {
    match v {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(wipe_json),
        Value::Object(o) => o.values_mut().for_each(wipe_json),
        _ => {}
    }
}

fn parse_bitwarden_json(text: &str, now: u64) -> Result<Imported> {
    let root = WipedJson(
        serde_json::from_str(text)
            .map_err(|_| Error::InvalidInput("the JSON file is not valid"))?,
    );
    if root.get("encrypted").and_then(Value::as_bool) == Some(true) {
        return Err(Error::InvalidInput(
            "encrypted Bitwarden export: export again choosing the unencrypted JSON format",
        ));
    }
    let entries = root
        .get("items")
        .and_then(Value::as_array)
        .ok_or(Error::InvalidInput("not a Bitwarden export: no items"))?;

    let mut items = Vec::new();
    let mut skipped = 0;
    for e in entries {
        let name = s(e, "name");
        let notes = s(e, "notes");
        let favorite = e.get("favorite").and_then(Value::as_bool).unwrap_or(false);
        let custom: Vec<(String, Zeroizing<String>, bool)> = e
            .get("fields")
            .and_then(Value::as_array)
            .map(|fs| {
                fs.iter()
                    // type 0 text, 1 hidden; booleans and links are not secrets worth keeping.
                    .filter(|f| matches!(f.get("type").and_then(Value::as_u64), Some(0 | 1)))
                    .map(|f| {
                        (
                            s(f, "name").to_owned(),
                            Zeroizing::new(s(f, "value").to_owned()),
                            f.get("type").and_then(Value::as_u64) == Some(1),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();

        let item = match e.get("type").and_then(Value::as_u64) {
            Some(1) => {
                let login = e.get("login").unwrap_or(&Value::Null);
                let url = login
                    .get("uris")
                    .and_then(Value::as_array)
                    .and_then(|u| u.first())
                    .map(|u| s(u, "uri"))
                    .unwrap_or("");
                login_item(
                    Login {
                        title: name,
                        url,
                        username: s(login, "username"),
                        password: s(login, "password"),
                        totp: s(login, "totp"),
                        notes,
                        favorite,
                        extra: custom,
                    },
                    now,
                )
            }
            Some(2) => note_item(name, notes, favorite, now),
            Some(3) => card_item(
                name,
                e.get("card").unwrap_or(&Value::Null),
                notes,
                favorite,
                now,
            ),
            _ => None,
        };
        match item {
            Some(i) => items.push(i),
            None => skipped += 1,
        }
    }
    Ok(Imported {
        format: ImportFormat::BitwardenJson,
        items,
        skipped,
    })
}

fn card_item(name: &str, bw: &Value, notes: &str, favorite: bool, now: u64) -> Option<Item> {
    let (month, year) = (s(bw, "expMonth"), s(bw, "expYear"));
    let expiry = match (month.parse::<u32>(), year.trim()) {
        (Ok(m), y) if (1..=12).contains(&m) && y.len() >= 2 => {
            format!("{m:02}/{}", &y[y.len() - 2..])
        }
        _ => String::new(),
    };
    let title = if name.trim().is_empty() {
        s(bw, "brand")
    } else {
        name
    };
    card(
        Card {
            title,
            holder: s(bw, "cardholderName"),
            number: s(bw, "number"),
            expiry: &expiry,
            cvv: s(bw, "code"),
            pin: "",
        },
        notes,
        favorite,
        now,
    )
}

struct Card<'a> {
    title: &'a str,
    holder: &'a str,
    number: &'a str,
    /// Already "MM/AA".
    expiry: &'a str,
    cvv: &'a str,
    pin: &'a str,
}

fn card(c: Card<'_>, notes: &str, favorite: bool, now: u64) -> Option<Item> {
    let number: Zeroizing<String> =
        Zeroizing::new(c.number.chars().filter(char::is_ascii_digit).collect());
    let fields: Vec<Field> = [
        field("Titular", FieldKind::Text, c.holder),
        field("Número", FieldKind::CardNumber, &number),
        field("Caducidad (MM/AA)", FieldKind::Date, c.expiry),
        field("CVV", FieldKind::Concealed, c.cvv),
        field("PIN", FieldKind::Pin, c.pin),
    ]
    .into_iter()
    .flatten()
    .collect();
    if fields.is_empty() && notes.trim().is_empty() {
        return None;
    }
    let subtitle = (number.len() >= 4).then(|| format!("•••• {}", &number[number.len() - 4..]));
    Some(Item {
        overview: overview(ItemKind::Card, c.title, subtitle, vec![], favorite, now),
        details: ItemDetails {
            fields,
            notes: notes.trim().to_owned(),
            history: Vec::new(),
        },
    })
}

// ---------------------------------------------------------------- 1Password .1pux

/// A section field's value: 1Password stores it as `{"<kind>": value}`.
fn onepux_value(v: &Value) -> Option<(&str, Zeroizing<String>)> {
    let (kind, inner) = v.as_object()?.iter().next()?;
    let text = Zeroizing::new(match inner {
        Value::String(s) => s.clone(),
        // monthYear: 202908 → "08/29".
        Value::Number(n) if kind == "monthYear" => {
            let ym = n.as_u64()?;
            format!("{:02}/{:02}", ym % 100, (ym / 100) % 100)
        }
        Value::Number(n) => n.to_string(),
        Value::Object(o) => o.values().find_map(Value::as_str)?.to_owned(),
        _ => return None,
    });
    Some((kind.as_str(), text))
}

fn parse_1pux(bytes: &[u8], now: u64) -> Result<Imported> {
    use std::io::Read;
    let damaged = || Error::InvalidInput("the ZIP file is damaged");
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).map_err(|_| damaged())?;
    let mut data = Zeroizing::new(Vec::new());
    {
        let entry = archive
            .by_name("export.data")
            .map_err(|_| Error::InvalidInput("not a 1Password export: no export.data"))?;
        // Bounded read: a crafted ZIP cannot inflate past the import limit.
        entry
            .take(MAX_INPUT as u64 + 1)
            .read_to_end(&mut data)
            .map_err(|_| damaged())?;
    }
    if data.len() > MAX_INPUT {
        return Err(Error::InvalidInput("file too large to import"));
    }
    let root = WipedJson(
        serde_json::from_slice(&data)
            .map_err(|_| Error::InvalidInput("the JSON file is not valid"))?,
    );
    drop(data);

    let mut items = Vec::new();
    let mut skipped = 0;
    let accounts = root
        .get("accounts")
        .and_then(Value::as_array)
        .ok_or(Error::InvalidInput("not a 1Password export: no accounts"))?;
    let all = accounts
        .iter()
        .flat_map(|a| {
            a.get("vaults")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .flat_map(|v| {
            v.get("items")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        });

    for e in all {
        if e.get("state")
            .and_then(Value::as_str)
            .is_some_and(|st| st != "active")
        {
            skipped += 1;
            continue;
        }
        let o = e.get("overview").unwrap_or(&Value::Null);
        let d = e.get("details").unwrap_or(&Value::Null);
        let title = s(o, "title");
        let notes = s(d, "notesPlain");
        let favorite = e.get("favIndex").and_then(Value::as_u64).unwrap_or(0) > 0;
        // (id, title, kind, value). Card fields are found by id ("ccnum", "cvv"…); custom
        // fields have random ids, so their title is what the user named them.
        let section_fields: Vec<(&str, &str, &str, Zeroizing<String>)> = d
            .get("sections")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .flat_map(|sec| {
                sec.get("fields")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
            })
            .filter_map(|f| {
                let (kind, value) = onepux_value(f.get("value")?)?;
                Some((s(f, "id"), s(f, "title"), kind, value))
            })
            .collect();
        let by_id = |id: &str| {
            section_fields
                .iter()
                .find(|f| f.0 == id)
                .map(|f| f.3.as_str())
                .unwrap_or("")
        };

        let item = match s(e, "categoryUuid") {
            // Login and standalone Password.
            "001" | "005" => {
                let login_fields = d.get("loginFields").and_then(Value::as_array);
                let designated = |which: &str| {
                    login_fields
                        .into_iter()
                        .flatten()
                        .find(|f| s(f, "designation") == which)
                        .map(|f| s(f, "value"))
                        .unwrap_or("")
                };
                let url = if s(o, "url").is_empty() {
                    o.get("urls")
                        .and_then(Value::as_array)
                        .and_then(|u| u.first())
                        .map(|u| s(u, "url"))
                        .unwrap_or("")
                } else {
                    s(o, "url")
                };
                let password = if designated("password").is_empty() {
                    s(d, "password")
                } else {
                    designated("password")
                };
                let totp = section_fields
                    .iter()
                    .find(|f| f.2 == "totp")
                    .map(|f| f.3.as_str())
                    .unwrap_or("");
                let extra = section_fields
                    .iter()
                    .filter(|f| f.2 != "totp")
                    .map(|f| {
                        let label = if f.1.trim().is_empty() { "Campo" } else { f.1 };
                        (label.to_owned(), f.3.clone(), f.2 == "concealed")
                    })
                    .collect();
                login_item(
                    Login {
                        title,
                        url,
                        username: designated("username"),
                        password,
                        totp,
                        notes,
                        favorite,
                        extra,
                    },
                    now,
                )
            }
            "002" => card(
                Card {
                    title,
                    holder: by_id("cardholder"),
                    number: by_id("ccnum"),
                    expiry: by_id("expiry"),
                    cvv: by_id("cvv"),
                    pin: by_id("pin"),
                },
                notes,
                favorite,
                now,
            ),
            "003" => note_item(title, notes, favorite, now),
            _ => None,
        };
        match item {
            Some(i) => items.push(i),
            None => skipped += 1,
        }
    }
    Ok(Imported {
        format: ImportFormat::OnePassword1pux,
        items,
        skipped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value<'a>(item: &'a Item, label: &str) -> &'a str {
        item.details
            .fields
            .iter()
            .find(|f| f.label == label)
            .map(|f| f.value.as_str())
            .unwrap_or("")
    }

    #[test]
    fn chrome_csv() {
        let csv = "name,url,username,password,note\n\
                   accounts.google.com,https://accounts.google.com/,raul@ejemplo.com,s3cret!,\n\
                   ,https://www.bbva.es/login,12345678Z,\"con,coma \"\"y comillas\"\"\",\"línea 1\nlínea 2\"\n";
        let out = parse(csv.as_bytes(), 7).unwrap();
        assert_eq!(out.format, ImportFormat::Csv);
        assert_eq!(out.items.len(), 2);
        let g = &out.items[0];
        assert_eq!(g.overview.kind, ItemKind::Login);
        assert_eq!(g.overview.title, "accounts.google.com");
        assert_eq!(g.overview.subtitle.as_deref(), Some("raul@ejemplo.com"));
        assert_eq!(g.overview.urls, vec!["https://accounts.google.com/"]);
        assert_eq!(value(g, "Contraseña"), "s3cret!");
        assert_eq!(g.details.fields[0].kind, FieldKind::Email);
        assert_eq!(g.overview.created_at, 7);
        let b = &out.items[1];
        assert_eq!(
            b.overview.title, "bbva.es",
            "without a name, the host is used"
        );
        assert_eq!(value(b, "Contraseña"), "con,coma \"y comillas\"");
        assert_eq!(b.details.notes, "línea 1\nlínea 2");
        assert_eq!(b.details.fields[0].kind, FieldKind::Text);
    }

    #[test]
    fn passwords_keep_their_spaces() {
        let csv = "name,url,username,password\nX,https://x.com,  raul  ,\"  con espacios  \"\n";
        let out = parse(csv.as_bytes(), 0).unwrap();
        assert_eq!(value(&out.items[0], "Contraseña"), "  con espacios  ");
        assert_eq!(
            value(&out.items[0], "Usuario"),
            "raul",
            "usernames are trimmed"
        );
    }

    #[test]
    fn firefox_csv_with_bom_and_crlf() {
        let csv = "\u{feff}\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\"timeCreated\",\"timeLastUsed\",\"timePasswordChanged\"\r\n\
                   \"https://github.com\",\"raul\",\"gh-pass\",,\"https://github.com\",\"{abc}\",\"1\",\"2\",\"3\"\r\n";
        let out = parse(csv.as_bytes(), 0).unwrap();
        assert_eq!(out.items.len(), 1);
        assert_eq!(out.items[0].overview.title, "github.com");
        assert_eq!(value(&out.items[0], "Contraseña"), "gh-pass");
    }

    #[test]
    fn bitwarden_csv_with_notes_and_totp() {
        let csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
                   ,1,login,GitHub,,,0,https://github.com,raul,pw,otpauth://totp/GitHub:raul?secret=JBSWY3DPEHPK3PXP\n\
                   ,,note,Códigos de recuperación,abcd-efgh,,0,,,,\n\
                   ,,identity,Yo,,,0,,,,\n";
        let out = parse(csv.as_bytes(), 0).unwrap();
        assert_eq!(out.items.len(), 2);
        assert_eq!(out.skipped, 1, "identities are skipped");
        assert!(out.items[0].overview.favorite);
        assert!(value(&out.items[0], "Código TOTP").starts_with("otpauth://"));
        assert_eq!(out.items[1].overview.kind, ItemKind::SecureNote);
        assert_eq!(out.items[1].details.notes, "abcd-efgh");
    }

    #[test]
    fn onepassword_csv() {
        let csv = "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\n\
                   Netflix,https://netflix.com,raul@ejemplo.com,nf-pass,,false,false,,cuenta familiar\n";
        let out = parse(csv.as_bytes(), 0).unwrap();
        assert_eq!(out.items[0].overview.title, "Netflix");
        assert_eq!(out.items[0].details.notes, "cuenta familiar");
        assert!(!out.items[0].overview.favorite);
    }

    #[test]
    fn empty_rows_are_skipped_not_imported() {
        let csv = "name,url,username,password\nx,https://x.com,,\n\n,,,\n";
        let out = parse(csv.as_bytes(), 0).unwrap();
        assert!(out.items.is_empty());
        assert_eq!(out.skipped, 1);
    }

    #[test]
    fn bitwarden_json() {
        let json = r#"{"encrypted":false,"folders":[],"items":[
          {"type":1,"name":"Google","favorite":true,"notes":"","login":{"username":"raul@ejemplo.com","password":"g-pass","totp":null,
            "uris":[{"match":null,"uri":"https://accounts.google.com"}]},
            "fields":[{"name":"PIN app","value":"1234","type":1},{"name":"Recordar","value":"true","type":2}]},
          {"type":3,"name":"Visa BBVA","notes":null,"card":{"cardholderName":"RAUL","brand":"Visa","number":"4940 1923 5567 4821","expMonth":"8","expYear":"2029","code":"317"}},
          {"type":2,"name":"Nota","notes":"secreto","secureNote":{"type":0}},
          {"type":4,"name":"Identidad","identity":{}},
          {"type":5,"name":"SSH","sshKey":{}}
        ]}"#;
        let out = parse(json.as_bytes(), 0).unwrap();
        assert_eq!(out.format, ImportFormat::BitwardenJson);
        assert_eq!(out.items.len(), 3);
        assert_eq!(out.skipped, 2);

        let g = &out.items[0];
        assert!(g.overview.favorite);
        assert_eq!(value(g, "Contraseña"), "g-pass");
        let pin = g
            .details
            .fields
            .iter()
            .find(|f| f.label == "PIN app")
            .unwrap();
        assert_eq!(pin.kind, FieldKind::Concealed);
        assert!(
            g.details.fields.iter().all(|f| f.label != "Recordar"),
            "boolean fields are dropped"
        );

        let card = &out.items[1];
        assert_eq!(card.overview.kind, ItemKind::Card);
        assert_eq!(card.overview.subtitle.as_deref(), Some("•••• 4821"));
        assert_eq!(value(card, "Número"), "4940192355674821");
        assert_eq!(value(card, "Caducidad (MM/AA)"), "08/29");
        assert_eq!(value(card, "CVV"), "317");
    }

    fn onepux(export_data: &str) -> Vec<u8> {
        use std::io::Write;
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        zip.start_file("export.attributes", opts).unwrap();
        zip.write_all(br#"{"version":3}"#).unwrap();
        zip.start_file("export.data", opts).unwrap();
        zip.write_all(export_data.as_bytes()).unwrap();
        zip.finish().unwrap().into_inner()
    }

    #[test]
    fn onepassword_1pux() {
        let data = r#"{"accounts":[{"attrs":{"name":"Personal"},"vaults":[{"attrs":{"name":"Privado"},"items":[
          {"uuid":"a","favIndex":1,"state":"active","categoryUuid":"001",
           "overview":{"title":"GitHub","url":"https://github.com","tags":[]},
           "details":{"loginFields":[
              {"value":"raul","name":"login","fieldType":"T","designation":"username"},
              {"value":"gh-pass","name":"password","fieldType":"P","designation":"password"}],
            "notesPlain":"cuenta personal",
            "sections":[{"title":"","fields":[
              {"title":"one-time password","id":"TOTP_x","value":{"totp":"otpauth://totp/GitHub:raul?secret=JBSWY3DPEHPK3PXP"}},
              {"title":"PIN de recuperación","id":"k3j4h5g6","value":{"concealed":"8841"}},
              {"title":"Pregunta","id":"q9w8e7","value":{"string":"Mi perro"}}]}]}},
          {"uuid":"b","favIndex":0,"state":"active","categoryUuid":"002","overview":{"title":"Visa"},
           "details":{"sections":[{"title":"","fields":[
              {"title":"cardholder name","id":"cardholder","value":{"string":"RAUL"}},
              {"title":"number","id":"ccnum","value":{"creditCardNumber":"4242 4242 4242 4242"}},
              {"title":"verification number","id":"cvv","value":{"concealed":"123"}},
              {"title":"expiry date","id":"expiry","value":{"monthYear":202908}},
              {"title":"PIN","id":"pin","value":{"concealed":"0000"}}]}]}},
          {"uuid":"c","state":"active","categoryUuid":"003","overview":{"title":"Nota"},"details":{"notesPlain":"texto"}},
          {"uuid":"d","state":"active","categoryUuid":"005","overview":{"title":"Wi-Fi casa"},"details":{"password":"wifi-pass"}},
          {"uuid":"e","state":"archived","categoryUuid":"001","overview":{"title":"Vieja"},"details":{"loginFields":[{"designation":"password","value":"x"}]}},
          {"uuid":"f","state":"active","categoryUuid":"004","overview":{"title":"Identidad"},"details":{}}
        ]}]}]}"#;
        let out = parse(&onepux(data), 0).unwrap();
        assert_eq!(out.format, ImportFormat::OnePassword1pux);
        assert_eq!(out.items.len(), 4);
        assert_eq!(out.skipped, 2, "archived item and identity");

        let gh = &out.items[0];
        assert!(gh.overview.favorite);
        assert_eq!(gh.overview.urls, vec!["https://github.com"]);
        assert_eq!(value(gh, "Usuario"), "raul");
        assert_eq!(value(gh, "Contraseña"), "gh-pass");
        assert!(value(gh, "Código TOTP").starts_with("otpauth://totp/"));
        assert_eq!(gh.details.notes, "cuenta personal");
        let pin = gh
            .details
            .fields
            .iter()
            .find(|f| f.label == "PIN de recuperación")
            .expect("labelled by title, not by id");
        assert_eq!(
            (pin.kind, pin.value.as_str()),
            (FieldKind::Concealed, "8841")
        );
        assert_eq!(value(gh, "Pregunta"), "Mi perro");

        let visa = &out.items[1];
        assert_eq!(visa.overview.kind, ItemKind::Card);
        assert_eq!(value(visa, "Número"), "4242424242424242");
        assert_eq!(value(visa, "Caducidad (MM/AA)"), "08/29");
        assert_eq!(value(visa, "CVV"), "123");
        assert_eq!(value(visa, "PIN"), "0000");

        assert_eq!(out.items[2].overview.kind, ItemKind::SecureNote);
        assert_eq!(value(&out.items[3], "Contraseña"), "wifi-pass");
    }

    #[test]
    fn onepux_errors_and_zip_bombs() {
        assert!(parse(b"PK\x03\x04 not a zip", 0).is_err());
        let no_data = {
            use std::io::Write;
            let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
            zip.start_file("otra.txt", zip::write::SimpleFileOptions::default())
                .unwrap();
            zip.write_all(b"x").unwrap();
            zip.finish().unwrap().into_inner()
        };
        assert!(
            parse(&no_data, 0)
                .unwrap_err()
                .to_string()
                .contains("export.data")
        );
        // 40 MiB of spaces compress to a few KiB: must be refused, not inflated into memory.
        let bomb = onepux(&" ".repeat(40 * 1024 * 1024));
        assert!(bomb.len() < 1024 * 1024);
        assert!(
            parse(&bomb, 0)
                .unwrap_err()
                .to_string()
                .contains("too large")
        );
    }

    #[test]
    fn rejects_what_it_cannot_import() {
        assert!(
            parse(br#"{"encrypted":true,"data":"..."}"#, 0)
                .unwrap_err()
                .to_string()
                .contains("unencrypted")
        );
        assert!(parse(b"a,b,c\n1,2,3\n", 0).is_err(), "no password column");
        assert!(
            parse(b"name,password\n\"x,1\n", 0).is_err(),
            "unclosed quote"
        );
        assert!(parse(b"", 0).is_err());
        assert!(parse(&[0xff, 0xfe, 0x00], 0).is_err(), "not UTF-8");
        assert!(parse(b"{not json", 0).is_err());
    }

    /// Reading memory after a drop is undefined behaviour (and this crate forbids `unsafe`), so
    /// the drop itself cannot be observed: what is checked is the function `WipedJson::drop` runs.
    #[test]
    fn wipe_json_clears_every_string_at_any_depth() {
        let mut v: Value = serde_json::from_str(
            r#"{"k":"s3cret","a":["x",{"p":"hunter2","n":7,"b":true,"z":null}],"o":{"deep":{"p":"y"}}}"#,
        )
        .unwrap();
        wipe_json(&mut v);
        let mut strings = 0;
        let mut stack = vec![&v];
        while let Some(v) = stack.pop() {
            match v {
                Value::String(s) => {
                    strings += 1;
                    assert!(s.is_empty());
                }
                Value::Array(a) => stack.extend(a),
                Value::Object(o) => stack.extend(o.values()),
                _ => {}
            }
        }
        assert_eq!(strings, 4);
        assert_eq!(v["a"][1]["n"], 7, "non-strings are left as they are");
    }

    #[test]
    fn json_parsers_still_read_values_through_the_guard() {
        let out = parse(
            br#"{"items":[{"type":1,"name":"a","login":{"username":"u","password":"  pw  "},"fields":[{"type":1,"name":"PIN","value":"1234"}]}]}"#,
            0,
        )
        .unwrap();
        assert_eq!(value(&out.items[0], "Contrase\u{f1}a"), "  pw  ");
        assert_eq!(value(&out.items[0], "PIN"), "1234");
    }
}
