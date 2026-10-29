//! `opvault`: inspect and decrypt OpenPassword backups without the app.
//!
//! Its purpose is that users never depend on the app to get their data back.

use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use op_core::vault::Item;
use op_core::{KdfParams, SecretKey, UnlockedVault, backup};
use serde::Serialize;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "opvault",
    version,
    about = "Inspecciona y descifra respaldos .opvault de OpenPassword"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Muestra la cabecera del respaldo. No pide credenciales ni revela datos.
    Inspect { file: PathBuf },
    /// Descifra el respaldo y escribe los elementos en claro como JSON en la salida estándar.
    Decrypt {
        file: PathBuf,
        #[command(flatten)]
        creds: Credentials,
    },
    /// Genera una clave secreta nueva.
    NewSecretKey,
    /// Crea un respaldo con elementos de ejemplo, para probar la herramienta.
    Sample {
        file: PathBuf,
        #[command(flatten)]
        creds: Credentials,
    },
}

#[derive(clap::Args)]
struct Credentials {
    /// Clave secreta (OP1-…). Si no se indica, se pide de forma interactiva.
    #[arg(long)]
    secret_key: Option<String>,
    /// Lee la contraseña maestra de la primera línea de la entrada estándar.
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
            Zeroizing::new(rpassword::prompt_password("Contraseña maestra: ")?)
        };
        let secret_key = match &self.secret_key {
            Some(sk) => SecretKey::parse(sk),
            None => SecretKey::parse(&Zeroizing::new(rpassword::prompt_password(
                "Clave secreta: ",
            )?)),
        }
        .context("clave secreta no válida")?;
        Ok((password, secret_key))
    }
}

#[derive(Serialize)]
struct DecryptedBackup {
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
    }
}

fn read_file(file: &PathBuf) -> Result<Vec<u8>> {
    std::fs::read(file).with_context(|| format!("no se puede leer {}", file.display()))
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
    let (vault, items) = backup::open(&bytes, &password, &secret_key)?;

    let items = items
        .iter()
        .map(|enc| {
            Ok(DecryptedItem {
                id: hex::encode(enc.id),
                revision: enc.revision,
                item: vault.decrypt_item(enc)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let out = DecryptedBackup {
        vault_id: hex::encode(vault.vault_id()),
        created_at: header.created_at,
        items,
    };

    let stdout = std::io::stdout();
    if stdout.is_terminal() {
        eprintln!(
            "Aviso: lo siguiente son tus secretos en claro. Redirige la salida a un fichero seguro si no quieres verlos en pantalla."
        );
    }
    let json = Zeroizing::new(serde_json::to_string_pretty(&out)?);
    writeln!(stdout.lock(), "{}", json.as_str())?;
    Ok(())
}

fn sample(file: &PathBuf, creds: &Credentials) -> Result<()> {
    if file.exists() {
        bail!("{} ya existe; no lo sobrescribo", file.display());
    }
    let (password, secret_key) = creds.read()?;
    let vault = UnlockedVault::create(&password, &secret_key, KdfParams::RECOMMENDED)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let items = sample_items(now)
        .iter()
        .map(|item| vault.encrypt_item(item))
        .collect::<op_core::Result<Vec<_>>>()?;
    std::fs::write(file, backup::write(&vault, &items, now)?)?;
    eprintln!(
        "Creado {} con {} elementos de ejemplo.",
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
