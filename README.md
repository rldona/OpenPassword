# OpenPassword

Gestor de contraseñas, tarjetas, PINs y secretos, de código abierto, offline y sin servidor. Android primero.

> **Estado: Fase 1 en curso.** La app Android ya crea, desbloquea y gestiona el baúl, pero no ha pasado ninguna auditoría. No guardes datos reales todavía.

## Qué hay en el repositorio

| Ruta | Contenido |
|---|---|
| [`core/`](core) | `op-core`, el núcleo en Rust: derivación de claves, cifrado por elemento y formato `.opvault` |
| [`ffi/`](ffi) | `op-ffi`, bindings UniFFI de `op-core` para Kotlin (y en el futuro Swift) |
| [`cli/`](cli) | `opvault`, herramienta para inspeccionar y descifrar respaldos sin la app |
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

Requiere Rust 1.85 o posterior.

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
