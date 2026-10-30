# OpenPassword

Gestor de contraseñas, tarjetas, PINs y secretos, de código abierto, offline y sin servidor. Android primero.

> **Estado: Fase 2 terminada, pendiente de publicar en F-Droid.** La app Android ya es de uso diario (autorrelleno, TOTP, copias automáticas, importadores), pero no ha pasado ninguna auditoría externa. No guardes datos reales todavía. Para avisar de un fallo de seguridad, ver [SECURITY.md](SECURITY.md).

## Qué hay en el repositorio

| Ruta | Contenido |
|---|---|
| [`core/`](core) | `op-core`, el núcleo en Rust: derivación de claves, cifrado por elemento y formato `.opvault` |
| [`ffi/`](ffi) | `op-ffi`, bindings UniFFI de `op-core` para Kotlin (y en el futuro Swift) |
| [`cli/`](cli) | `opvault`, herramienta para inspeccionar y descifrar respaldos sin la app |
| [`fuzz/`](fuzz) | Objetivos de `cargo-fuzz` para los parsers que leen datos no confiables. Ver [fuzz/README.md](fuzz/README.md) |
| [`android/`](android) | App Android: Kotlin + Jetpack Compose. Ver [android/README.md](android/README.md) |
| [`docs/crypto-spec.md`](docs/crypto-spec.md) | Especificación criptográfica v1 (normativa) |
| [`docs/opvault-format.md`](docs/opvault-format.md) | Formato del fichero de respaldo |
| [`docs/threat-model.md`](docs/threat-model.md) | Modelo de amenazas |
| [`docs/propuesta.html`](docs/propuesta.html) | Propuesta funcional y técnica con prototipos |

## Resumen del diseño

- La contraseña maestra (Argon2id, 256 MiB) se combina con una **clave secreta** de 128 bits. Un respaldo robado no se puede atacar por fuerza bruta sin ella.
- Cada elemento tiene su propia clave. Todo va cifrado con XChaCha20-Poly1305, metadatos incluidos.
- Cada bloque cifrado está ligado a su contexto (baúl, elemento, revisión, parte) mediante datos asociados.
- La app Android no tendrá permiso de Internet. Los respaldos se escriben cifrados en la carpeta que elija el usuario.

## Desarrollo

Usa la versión de Rust fijada en [`rust-toolchain.toml`](rust-toolchain.toml); rustup la instala sola.

```sh
cargo test --workspace          # tests unitarios, vectores oficiales y vectores dorados v1
cargo clippy --workspace --all-targets
cargo build --release -p opvault-cli
```

### Probar la CLI

```sh
SK=$(./target/release/opvault new-secret-key)
./target/release/opvault sample demo.opvault --secret-key "$SK"
./target/release/opvault inspect demo.opvault
./target/release/opvault decrypt demo.opvault --secret-key "$SK"
```

### Vectores de prueba

`core/tests/vectors/op-v1.json` fija cada byte del formato v1. Si un cambio los rompe, es incompatible con los baúles existentes: hay que crear una versión nueva del formato, no regenerarlos. Cualquier otra implementación (Kotlin, Swift) debe pasar el mismo fichero.

## Licencia

OpenPassword es software libre bajo la [GNU General Public License v3.0 o posterior](LICENSE) (`GPL-3.0-or-later`). Puedes usarlo, estudiarlo, modificarlo y redistribuirlo, pero cualquier versión modificada que distribuyas debe publicarse con la misma licencia y su código fuente. Así nadie puede cerrar un fork de un gestor de contraseñas que debe poder auditarse.

### Componentes de terceros

- Lista de palabras para frases de paso: [EFF Large Wordlist](https://www.eff.org/dice) de la Electronic Frontier Foundation, bajo [CC BY 3.0 US](https://creativecommons.org/licenses/by/3.0/us/). Se incluye solo la columna de palabras, sin otros cambios (`android/app/src/main/assets/eff_large_wordlist.txt`).
- Lista de sufijos públicos: [Public Suffix List](https://publicsuffix.org/list/public_suffix_list.dat) de Mozilla y colaboradores, bajo [MPL 2.0](https://mozilla.org/MPL/2.0/). Se incluye sin modificar (`android/app/src/main/resources/public_suffix_list.dat`) y el autorrelleno la usa para no ofrecer una credencial de `github.io` o `co.uk` a cualquier subdominio.
