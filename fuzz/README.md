# Fuzzing

Objetivos de [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) para todo lo que lee datos no confiables. Necesitan nightly:

| Objetivo | Qué recibe |
|---|---|
| `import` | Cualquier fichero que se importa: CSV, JSON de Bitwarden, `.1pux` de 1Password y la cabecera de KDBX. Lo que pide contraseña se detiene antes de la derivación de claves |
| `kdbx_xml` | El XML de KeePass ya descifrado, con valores protegidos |
| `key_file` | Archivos de clave de KeePass |
| `backup_header` | La parte en claro de una copia `.opvault`, que se lee antes de pedir la contraseña |
| `totp` | Enlaces `otpauth://` y secretos sueltos |

Las derivaciones de claves no se fuzzean: su coste lo fija el fichero y está acotado (Argon2 ≤ 1 GiB y 1000 pasadas en KDBX, `KdfParams::MAXIMUM` en `.opvault`, AES-KDF ≤ 200 millones de rondas).

```sh
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz
cd fuzz
mkdir -p corpus/import && cp seeds/import/* corpus/import/
cargo +nightly fuzz run -O import corpus/import -- -max_len=65536 -rss_limit_mb=2048 -timeout=10
```

`seeds/` son las entradas iniciales de cada objetivo. `corpus/` y `artifacts/` (los fallos encontrados) no se suben. La CI ejecuta cada objetivo 60 s en cada push.
