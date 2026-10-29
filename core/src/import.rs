//! Import from other password managers' plaintext exports.
//!
//! Supported: CSV from Chrome / Google Password Manager, Firefox, Bitwarden and 1Password
//! (columns are matched by name, so similar CSVs work too) and Bitwarden's unencrypted JSON.
//! The input is plaintext secrets: callers should offer to delete the file afterwards.

use serde_json::Value;

use crate::vault::{Field, FieldKind, Item, ItemDetails, ItemKind, ItemOverview};
use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportFormat {
    Csv,
    BitwardenJson,
}

#[derive(Debug)]
pub struct Imported {
    pub format: ImportFormat,
    pub items: Vec<Item>,
    /// Entries of a kind OpenPassword does not import yet (identities, SSH keys…) or empty rows.
    pub skipped: usize,
}

const MAX_INPUT: usize = 32 * 1024 * 1024;

/// Detects the format and converts every entry. `now` (Unix seconds) stamps the items.
pub fn parse(bytes: &[u8], now: u64) -> Result<Imported> {
    if bytes.len() > MAX_INPUT {
        return Err(Error::InvalidInput("file too large to import"));
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
    extra: Vec<(String, String, bool)>,
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

fn field(label: &str, kind: FieldKind, value: &str) -> Option<Field> {
    let v = value.trim();
    (!v.is_empty()).then(|| Field::new(label, kind, v))
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
fn csv_records(text: &str) -> Result<Vec<Vec<String>>> {
    let mut records = Vec::new();
    let mut record = Vec::new();
    let mut field = String::new();
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
        let get = |c: Option<usize>| c.and_then(|i| r.get(i)).map(String::as_str).unwrap_or("");
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

fn parse_bitwarden_json(text: &str, now: u64) -> Result<Imported> {
    let root: Value = serde_json::from_str(text)
        .map_err(|_| Error::InvalidInput("the JSON file is not valid"))?;
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
        let custom: Vec<(String, String, bool)> = e
            .get("fields")
            .and_then(Value::as_array)
            .map(|fs| {
                fs.iter()
                    // type 0 text, 1 hidden; booleans and links are not secrets worth keeping.
                    .filter(|f| matches!(f.get("type").and_then(Value::as_u64), Some(0 | 1)))
                    .map(|f| {
                        (
                            s(f, "name").to_owned(),
                            s(f, "value").to_owned(),
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

fn card_item(name: &str, card: &Value, notes: &str, favorite: bool, now: u64) -> Option<Item> {
    let number: String = s(card, "number")
        .chars()
        .filter(char::is_ascii_digit)
        .collect();
    let (month, year) = (s(card, "expMonth"), s(card, "expYear"));
    let expiry = match (month.parse::<u32>(), year.trim()) {
        (Ok(m), y) if (1..=12).contains(&m) && y.len() >= 2 => {
            format!("{m:02}/{}", &y[y.len() - 2..])
        }
        _ => String::new(),
    };
    let fields: Vec<Field> = [
        field("Titular", FieldKind::Text, s(card, "cardholderName")),
        field("Número", FieldKind::CardNumber, &number),
        field("Caducidad (MM/AA)", FieldKind::Date, &expiry),
        field("CVV", FieldKind::Concealed, s(card, "code")),
    ]
    .into_iter()
    .flatten()
    .collect();
    if fields.is_empty() && notes.trim().is_empty() {
        return None;
    }
    let subtitle = (number.len() >= 4).then(|| format!("•••• {}", &number[number.len() - 4..]));
    let title = if name.trim().is_empty() {
        s(card, "brand")
    } else {
        name
    };
    Some(Item {
        overview: overview(ItemKind::Card, title, subtitle, vec![], favorite, now),
        details: ItemDetails {
            fields,
            notes: notes.trim().to_owned(),
        },
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
}
