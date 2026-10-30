# Fuzzing

Once objetivos de [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) para todo lo que lee datos no confiables. Necesitan nightly:

| Objetivo | Qué recibe |
|---|---|
| `import` | Cualquier fichero que se importa: CSV, JSON de Bitwarden, `.1pux` de 1Password y KDBX. Para KDBX recorre `kdbx::parse` sin la derivación de claves (clave fija, `kdbx_fuzzing::file`): cabecera, comprobación del HMAC o de los bytes iniciales |
| `kdbx_container` | KDBX 3.1/4 sellado con la clave fija: troceado en bloques, cifrado externo, gunzip, cabecera interna y XML. El primer byte elige la forma |
| `kdbx_xml` | El XML de KeePass ya descifrado, con valores protegidos; incluye semillas de anidamiento profundo y de muchas entradas |
| `key_file` | Archivos de clave de KeePass |
| `backup_header` | La parte en claro de una copia `.opvault`, que se lee antes de pedir la contraseña |
| `totp` | Enlaces `otpauth://` y secretos sueltos |
| `vault_json` | `VaultHeader` y `EncryptedItem` como JSON (el `serde` de `encoding::hex_bytes`) |
| `item_open` | Un `EncryptedItem` arbitrario descifrado con la bóveda fija de pruebas: desenvoltura de la clave, longitudes y AAD |
| `item_plaintext` | Bytes que se sellan con clave fija como `overview` y `details` y se descifran: `padding::unpad` y el JSON de los elementos |
| `backup_body` | Bytes que se sellan con STREAM como cuerpo de una copia y se abren sin KDF: troceado y JSON del `Body` |
| `ffi_records` | `op-ffi`: cabecera arbitraria y `EncryptedItemRecord` arbitrario (o sellado con la clave fija) |

## Ganchos `cfg(fuzzing)`

Con entradas aleatorias el AEAD no deja pasar nada, así que los cuatro últimos objetivos (y `kdbx_container`, con `import::kdbx_fuzzing`) usan el módulo `op_core::fuzzing` (`core/src/lib.rs`, más `vault::fuzzing` y `backup::fuzzing`), que sella la entrada con una **clave fija y pública, solo para pruebas** (`TEST_VAULT_KEY`). Solo existe con `--cfg fuzzing`, que pone `cargo fuzz` y nada más en este repositorio: no entra en ninguna compilación normal ni de release. Además, `core/src/lib.rs` rechaza con `compile_error!` una compilación `release` con `--cfg fuzzing` (`cargo fuzz build` las mantiene; con `-O` hay que añadir `-a`, y por eso todos los comandos de aquí y de la CI usan `-O -a`).

### Comprobar que no están en lo que se distribuye

`scripts/check-no-fuzzing-hooks.sh <libop_ffi.so>...` busca en la biblioteca nativa final, no en el `.rlib`: con `lto = true` el `.rlib` guarda *bitcode* y `strings` no encuentra nada ni siquiera con los ganchos dentro (un `! strings … | grep seal_backup` sobre él siempre «pasa»). Tampoco sirve buscar los nombres de los ganchos (`seal_backup`, `seal_item_part`, `TEST_VAULT_KEY`) en el `.so`: el enlazado elimina lo que nadie usa, así que **tampoco aparecen en una compilación con los ganchos**. Por eso `op_core::fuzzing::HOOKS_MARKER` es una cadena `#[used]` (`OPENPASSWORD_FUZZING_HOOKS`) que solo existe con `--cfg fuzzing` y sobrevive al enlazado. El script falla si la encuentra y también si no encuentra una cadena de control que siempre está (`cost above the accepted maximum`): así un fichero ilegible o vacío no pasa por «limpio».

```sh
# Control negativo: la biblioteca de release no los tiene (salida 0).
cargo build -p op-ffi --release --locked
scripts/check-no-fuzzing-hooks.sh target/release/libop_ffi.so      # (.dylib en macOS)

# Control positivo: una compilación con los ganchos TIENE que fallar la comprobación.
scripts/check-no-fuzzing-hooks.sh --self-test
# Hecho a mano: el `release` normal rechaza --cfg fuzzing, así que se activan las aserciones.
RUSTFLAGS="--cfg fuzzing" CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true CARGO_TARGET_DIR=/tmp/fz \
  cargo build -p op-ffi --release --locked
strings -a /tmp/fz/release/libop_ffi.so | grep -c OPENPASSWORD_FUZZING_HOOKS   # 1
```

La CI ejecuta el control negativo sobre `libop_ffi.so` de Linux, el `--self-test` y la comprobación sobre las bibliotecas del APK de release (`lib/*/libop_ffi.so`).

Las derivaciones de claves no se fuzzean: su coste lo fija el fichero y está acotado (en KDBX, Argon2 ≤ 512 MiB, 1000 pasadas y 64 carriles con `memoria × pasadas ≤ 3 GiB·pasada`, y AES-KDF ≤ 200 millones de rondas; en `.opvault`, `KdfParams::MAXIMUM`).

```sh
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz
cd fuzz
mkdir -p corpus/import && cp seeds/import/* corpus/import/
cargo +nightly fuzz run -O -a import corpus/import -- -max_len=65536 -rss_limit_mb=2048 -timeout=10
```

`seeds/` son las entradas iniciales de cada objetivo. `corpus/` y `artifacts/` (los fallos encontrados) no se suben. La CI ejecuta cada objetivo 30 s en cada push (`-max_total_time=30`). `.github/workflows/fuzz-nightly.yml` los ejecuta 10 min cada noche (y a mano con `workflow_dispatch`), con el corpus en `actions/cache` y minimizado con `cargo fuzz cmin` los domingos; si un objetivo falla, sube sus artefactos.

Los seeds de los objetivos nuevos están hechos a mano (con un generador temporal que usa los ganchos), no minimizados.
