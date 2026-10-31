//! `opvault`: inspect and decrypt OpenPassword backups without the app.
//!
//! Its purpose is that users never depend on the app to get their data back.

use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use clap::{Parser, Subcommand};
use op_core::vault::{Item, MediaType};
use op_core::{KdfParams, SecretKey, UnlockedVault, backup};
use serde::Serialize;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "opvault",
    version,
    about = "Inspect and decrypt OpenPassword .opvault backups"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show the backup header. It asks for no credentials and reveals no data.
    Inspect { file: PathBuf },
    /// Decrypt the backup and write the items in the clear as JSON to standard output.
    Decrypt {
        file: PathBuf,
        #[command(flatten)]
        creds: Credentials,
    },
    /// Generate a new secret key.
    NewSecretKey,
    /// Compute the current TOTP code. Reads the otpauth:// link or the secret from standard input.
    Totp,
    /// Create a backup with sample items, to try the tool.
    Sample {
        file: PathBuf,
        #[command(flatten)]
        creds: Credentials,
    },
}

#[derive(clap::Args)]
struct Credentials {
    /// Secret key (OP1-…). If omitted, it is asked for interactively.
    #[arg(long)]
    secret_key: Option<String>,
    /// Read the master password from the first line of standard input.
    #[arg(long)]
    password_stdin: bool,
}

impl Credentials {
    fn read(&self) -> Result<(Zeroizing<String>, SecretKey)> {
        let password = if self.password_stdin {
            let mut line = Zeroizing::new(String::new());
            std::io::stdin().lock().read_line(&mut line)?;
            Zeroizing::new(line.trim_end_matches(['\r', '\n']).to_owned())
        } else {
            Zeroizing::new(rpassword::prompt_password("Master password: ")?)
        };
        let secret_key = match &self.secret_key {
            Some(sk) => SecretKey::parse(sk),
            None => SecretKey::parse(&Zeroizing::new(rpassword::prompt_password(
                "Secret key: ",
            )?)),
        }
        .context("invalid secret key")?;
        Ok((password, secret_key))
    }
}

#[derive(Serialize)]
struct DecryptedBackup {
    format_version: u32,
    vault_id: String,
    created_at: u64,
    items: Vec<DecryptedItem>,
}

#[derive(Serialize)]
struct DecryptedItem {
    id: String,
    revision: u64,
    #[serde(flatten)]
    item: Item,
    attachments: Vec<DecryptedAttachment>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    missing_attachments: Vec<String>,
}

#[derive(Serialize)]
struct DecryptedAttachment {
    id: String,
    media_type: &'static str,
    /// Base64 so the whole recovery stays in one readable JSON file.
    data: String,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Inspect { file } => inspect(&file),
        Command::Decrypt { file, creds } => decrypt(&file, &creds),
        Command::NewSecretKey => {
            println!("{}", SecretKey::generate()?.to_display().as_str());
            Ok(())
        }
        Command::Sample { file, creds } => sample(&file, &creds),
        Command::Totp => totp(),
    }
}

fn read_file(file: &PathBuf) -> Result<Vec<u8>> {
    std::fs::read(file).with_context(|| format!("cannot read {}", file.display()))
}

fn inspect(file: &PathBuf) -> Result<()> {
    let header = backup::read_header(&read_file(file)?)?;
    println!("{}", serde_json::to_string_pretty(&header)?);
    Ok(())
}

fn decrypt(file: &PathBuf, creds: &Credentials) -> Result<()> {
    let bytes = read_file(file)?;
    let header = backup::read_header(&bytes)?;
    let (password, secret_key) = creds.read()?;
    let (vault, items, attachments) = backup::open(&bytes, &password, &secret_key)?;

    let items = items
        .iter()
        .map(|enc| {
            let item = vault.decrypt_item(enc)?;
            let mut present = Vec::new();
            let mut missing = Vec::new();
            for id in item.details.image_ids()? {
                match attachments
                    .iter()
                    .find(|a| a.item_id == enc.id && a.id == id)
                {
                    Some(attachment) => {
                        let image = vault.decrypt_image(enc, attachment)?;
                        present.push(DecryptedAttachment {
                            id: hex::encode(id),
                            media_type: match image.media_type {
                                MediaType::Jpeg => "image/jpeg",
                            },
                            data: STANDARD.encode(&image.jpeg),
                        });
                    }
                    None => missing.push(hex::encode(id)),
                }
            }
            Ok(DecryptedItem {
                id: hex::encode(enc.id),
                revision: enc.revision,
                item,
                attachments: present,
                missing_attachments: missing,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let out = DecryptedBackup {
        format_version: header.format_version,
        vault_id: hex::encode(vault.vault_id()),
        created_at: header.created_at,
        items,
    };

    let stdout = std::io::stdout();
    if stdout.is_terminal() {
        eprintln!(
            "Warning: the following is your secrets in the clear. Redirect the output to a safe file if you do not want to see them on screen."
        );
    }
    let json = Zeroizing::new(serde_json::to_string_pretty(&out)?);
    writeln!(stdout.lock(), "{}", json.as_str())?;
    Ok(())
}

fn totp() -> Result<()> {
    let mut line = Zeroizing::new(String::new());
    std::io::stdin().lock().read_line(&mut line)?;
    let totp = op_core::totp::Totp::parse(&line).context("invalid TOTP secret")?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    println!(
        "{} (changes in {} s)",
        totp.code_at(now),
        totp.seconds_remaining(now)
    );
    Ok(())
}

fn sample(file: &PathBuf, creds: &Credentials) -> Result<()> {
    if file.exists() {
        bail!("{} already exists; not overwriting it", file.display());
    }
    let (password, secret_key) = creds.read()?;
    let vault = UnlockedVault::create(&password, &secret_key, KdfParams::RECOMMENDED)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let items = sample_items(now)
        .iter()
        .map(|item| vault.encrypt_item(item))
        .collect::<op_core::Result<Vec<_>>>()?;
    std::fs::write(file, backup::write(&vault, &items, &[], now)?)?;
    eprintln!(
        "Created {} with {} sample items.",
        file.display(),
        items.len()
    );
    Ok(())
}

fn sample_items(now: u64) -> Vec<Item> {
    use op_core::vault::{Field, FieldKind as F, ItemDetails, ItemKind, ItemOverview};
    let item = |kind, title: &str, subtitle: &str, fields: Vec<Field>| Item {
        overview: ItemOverview {
            kind,
            title: title.into(),
            subtitle: Some(subtitle.into()),
            urls: vec![],
            tags: vec!["ejemplo".into()],
            favorite: false,
            created_at: now,
            updated_at: now,
        },
        details: ItemDetails {
            fields,
            notes: String::new(),
            history: Vec::new(),
        },
    };
    vec![
        item(
            ItemKind::Card,
            "Visa de ejemplo",
            "Débito · •••• 4242",
            vec![
                Field::new("Número", F::CardNumber, "4242424242424242"),
                Field::new("Caducidad", F::Date, "2030-12"),
                Field::new("CVV", F::Concealed, "123"),
            ],
        ),
        item(
            ItemKind::Login,
            "Cuenta de ejemplo",
            "usuario@ejemplo.com",
            vec![
                Field::new("Usuario", F::Email, "usuario@ejemplo.com"),
                Field::new("Contraseña", F::Concealed, "no-es-una-contraseña-real"),
            ],
        ),
        item(
            ItemKind::Pin,
            "Alarma de ejemplo",
            "PIN · 4 dígitos",
            vec![Field::new("PIN", F::Pin, "0000")],
        ),
    ]
}
