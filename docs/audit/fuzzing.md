# Fuzzing

Qué se fuzzea, cómo, con qué ganchos, qué falta y por qué se pospone. La guía de uso está en
[`fuzz/README.md`](../../fuzz/README.md); la decisión, en [`decisions.md`](decisions.md) (ADR-AUD-05).

Estado verificado el 2026-10-30 sobre `HEAD` `2bd56ce`. Los seis objetivos nuevos (`vault_json`,
`item_open`, `item_plaintext`, `backup_body`, `ffi_records` y `kdbx_container`), los ganchos `cfg(fuzzing)`,
el workflow nocturno y la bajada de la CI a 30 s están confirmados en ese commit; los cinco primeros
objetivos están en `8063fd1`. Las cifras de corpus local son de la máquina de desarrollo.

## 1. Cobertura actual: once objetivos

Todos son `cargo-fuzz` (libFuzzer con AddressSanitizer por defecto), registrados en `fuzz/Cargo.toml`
(espacio de trabajo aparte, necesita nightly). Parámetros comunes de la CI:
`-O --target x86_64-unknown-linux-gnu … -max_len=65536 -rss_limit_mb=2048 -timeout=10`.

| Objetivo | Origen | Qué recibe | Qué recorre | Semillas (`fuzz/seeds/<objetivo>/`) | Corpus local (ficheros, no versionado) |
|---|---|---|---|---|---|
| `import` | `8063fd1` | Fichero | `import::needs_password` y `import::parse(data, now)`: CSV, Bitwarden JSON y `.1pux`; y, desde `2bd56ce`, `kdbx_fuzzing::file`: cabecera de KDBX y comprobaciones previas a la KDF con una clave fija ([ID-INT-25](internal-review.md#id-int-25), corregido) | 6 (9 521 B) | 27 888 |
| `kdbx_xml` | `8063fd1` | XML UTF-8 | `kdbx_fuzzing::xml`: `read_entries` (grupos, papelera, historial, valores protegidos con flujo ChaCha20 fijo, límites de profundidad y de entradas) y `entry_to_item` | 3 (64 944 B; las dos nuevas son de anidamiento profundo y del límite) | 5 334 |
| `key_file` | `8063fd1` | Bytes | `kdbx_fuzzing::key_file` (`key_file_key`) | 2 (342 B) | 4 918 |
| `backup_header` | `8063fd1` | Bytes | `backup::read_header` y `kdf.check_bounds()`. **No** llama a `check_within(MOBILE_MAXIMUM)` (ADR-AUD-07 lo pedía; `fuzz/fuzz_targets/backup_header.rs:7-9`) | 1 (3 953 B) | 2 861 |
| `totp` | `8063fd1` | UTF-8 | `Totp::parse`, `code_at(u64::MAX)`, `seconds_remaining` | 2 (157 B) | 1 868 |
| `vault_json` | nuevo | Bytes | `serde_json` de `VaultHeader` y de `EncryptedItem` (`hex_bytes`), con ida y vuelta | 2 (1 142 B) | 4 513 |
| `item_open` | nuevo | `EncryptedItem` en JSON | `vault.decrypt_overview`, `decrypt_details`, `decrypt_item` con la bóveda de prueba | 1 (919 B) | 3 276 |
| `item_plaintext` | nuevo | Bytes | `seal_item_part` (relleno + sellado con clave fija) → `decrypt_details` y `decrypt_overview`: `padding::unpad` y el JSON de los elementos | 3 (178 B) | 2 228 |
| `backup_body` | nuevo | Bytes | `seal_backup` (STREAM con clave fija) → `open_with_vault`: troceado y `Body` JSON, **sin KDF**; también los bytes crudos | 3 (2 391 B) | 936 |
| `kdbx_container` | `2bd56ce` | Bytes (el primero elige la forma) | `kdbx_fuzzing::container`: KDBX 3.1/4 sellado con una clave transformada fija; `read_header`, `open_payload`: bloques con HMAC o hash, cifrado externo (AES o ChaCha20), gunzip, cabecera interna y XML | 5 (9 415 B) | 0 (sin corpus local) |
| `ffi_records` | nuevo | Bytes (`Unstructured`) | `op_ffi::Vault::unlock_with_vault_key` con cabecera arbitraria y fija, y `decrypt_overview`/`decrypt_details` con `EncryptedItemRecord` arbitrario o sellado | 1 (98 B) | 1 755 |

- **Total**: 29 semillas, unos 93 000 B (`for t in seeds/*; do ls $t | wc -l; done`); el corpus local son ficheros del equipo de desarrollo y no
  entra en el repositorio (`fuzz/.gitignore`: `corpus/`, `artifacts/`).
- **Resultados**: `fuzz/artifacts/<objetivo>/` está **vacío** en los once objetivos en esta máquina
  (`ls fuzz/artifacts/*`): ningún fallo guardado. El mensaje del commit `8063fd1` da «unos 48 millones
  de ejecuciones en local sin fallos» **para los cinco primeros objetivos**. **No hay ninguna cifra de
  ejecuciones registrada para los seis nuevos**: el tamaño del corpus local de cinco de ellos demuestra que se
  ejecutaron, no cuánto; `kdbx_container` no tiene corpus local. Cualquier cifra de ejecuciones por objetivo nuevo sería una estimación.
- **Hallazgos que ha producido hasta ahora**: ninguno. Los dos defectos de `op-core` que el fuzzing
  **no** encontró —y que la revisión interna sí— están en `internal-review.md` y ya están corregidos en `2bd56ce`:
  [ID-INT-01](internal-review.md#id-int-01) (memoria cuadrática del XML, que `kdbx_xml` no encontraba
  porque exige anidamiento profundo **y** muchas entradas; ahora hay límites y semillas) y
  [ID-INT-25](internal-review.md#id-int-25) (el hueco de cobertura de la cabecera de KDBX; ahora lo
  cubren `import` y `kdbx_container`).

## 2. Ganchos `cfg(fuzzing)`

`cargo fuzz` compila con `--cfg fuzzing`; nada más en el repositorio lo activa. Lo declara
`[workspace.lints.rust] unexpected_cfgs … check-cfg = ["cfg(fuzzing)"]` (`Cargo.toml:15`).

| Módulo | Fichero y línea | Qué expone |
|---|---|---|
| `op_core::fuzzing` | `core/src/lib.rs:26` | `TEST_VAULT_KEY` (`[7; 32]`), `header()` (cabecera bien formada, clave envuelta vacía), `vault()` (baúl abierto con `unlock_with_vault_key`); reexporta los dos siguientes |
| `vault::fuzzing` | `core/src/vault/mod.rs:273` | `seal_item_part(vault, plaintext)`: clave de elemento `[9; 32]`, nonce `[5; …]`, id `[2; 16]`, relleno y sellado, para llegar a `unpad` y al JSON |
| `backup::fuzzing` | `core/src/backup/mod.rs:144` | `seal_backup(vault, body)` (clave de fichero `[4; 32]`, nonce `[6; …]`) y `open_with_vault(bytes, vault)` (`decrypt_body` sin KDF) |
| `import::kdbx_fuzzing` | `core/src/import/mod.rs:11` → `core/src/import/kdbx.rs:661` | `xml(&str)`, `key_file(&[u8])`, `file(&[u8])` (cabecera y comprobaciones previas a la KDF con una clave transformada fija, no secreta) y `container(&[u8])` (sella un KDBX con esa clave y llega hasta el XML) |

**Claves y nonces constantes y públicos.** Por eso el módulo no puede entrar en un binario de
producción. Se comprueba así:

- **Comprobación válida**: `strings -a android/app/build/rust/jniLibs/arm64-v8a/libop_ffi.so | grep -cE
  'seal_backup|seal_item_part|TEST_VAULT_KEY'` → **0**, con un control positivo
  (`… | grep -c "cost above the accepted maximum"` → 1, una cadena que sí existe). El `.so` se
  compiló a las 10:14 del 30/10 con el árbol que incluye `check_within`.
- **Comprobación del README: no sirve** ([ID-INT-21](internal-review.md#id-int-21)): sobre
  `target/release/libop_core.rlib` el mismo control positivo da 0, porque con LTO el `.rlib` es
  *bitcode*. El auditor no debería fiarse de ella.
- `cargo build --release` no define `fuzzing`, así que los módulos no se compilan: la ausencia en
  `libop_ffi.so` lo confirma.

El riesgo que queda ([`decisions.md`](decisions.md), «Riesgos que quedan abiertos»): código que solo
existe en fuzzing y que el auditor tiene que leer; se pide revisarlo y se propone un paso de CI con la
comprobación válida.

## 3. Corpus y semillas

- **Semillas**: `fuzz/seeds/<objetivo>/`, hechas a mano o con un generador temporal que usa los
  ganchos y los vectores de `core/tests/vectors/op-v1.json` (los de los objetivos nuevos, según
  `fuzz/README.md`). No están minimizadas.
- **PR y *push*** (`ci.yml`, job `fuzz`): corpus vacío más las semillas, **30 s por objetivo**
  (`-max_total_time=30`), once objetivos en serie, sin caché. Si falla, sube `fuzz/artifacts`.
- **Nocturno** (`.github/workflows/fuzz-nightly.yml`): `cron: '17 3 * * *'` (UTC) y
  `workflow_dispatch`. Matriz de once trabajos en paralelo, uno por objetivo, `timeout-minutes: 150`,
  `-max_total_time=600` (**10 min**), `concurrency` de un solo grupo sin cancelación.
  - **Corpus en caché**: `actions/cache` con clave `fuzz-corpus-<objetivo>-<run_id>` y
    `restore-keys: fuzz-corpus-<objetivo>-`: cada noche restaura el más reciente y guarda uno nuevo.
  - **Minimización**: `cargo fuzz cmin` solo el domingo (`date -u +%u = 7`).
  - **Si un objetivo falla**: sube `fuzz/artifacts/<objetivo>` y el trabajo queda en rojo. `fail-fast:
    false`, así que los otros diez terminan.
- **Nunca ejecutado**: el fichero se confirmó en `2bd56ce` y no hay constancia de ninguna ejecución de
  GitHub Actions (ni manual ni programada) en este repositorio. El paso 12 del plan pide una ejecución
  `workflow_dispatch` en verde.
- **Caducidad**: la caché de Actions caduca a los 7 días sin uso (ADR-AUD-05). Con `actions/cache`, el
  guardado se hace al acabar con éxito: si un objetivo falla esa noche, **ese día no se guarda el
  corpus** (comportamiento por defecto de la acción; sin verificar en este repositorio).

### Tiempos (estimaciones, no medidas)

| Qué | Estimación | Base |
|---|---|---|
| Job `fuzz` de PR | ≈ 5,5 min de fuzzing (11 × 30 s) más compilación de 11 binarios | Aritmética del `ci.yml`; ADR-AUD-05 dice «unos 5 min». **No hay una duración de ejecución real registrada** |
| Nocturno | ≈ 110 min de CPU (11 × 10 min), ≈ 10–20 min de reloj en paralelo más compilación | Aritmética del workflow; sin medir |
| Ejecuciones por objetivo y por minuto | **Sin medir** | No hay `exec/s` en el repositorio |

## 4. Qué falta y por qué se pospone

| Hueco | Estado | Motivo |
|---|---|---|
| **`backup_header` sin `check_within(MOBILE_MAXIMUM)`** | Pedido por ADR-AUD-07, no hecho | El techo vive en `op-ffi`; `fuzz` ya depende de `op-ffi` (`ffi_records`) |
| **`open_backup` y `parse_import` completos** (con `check_mobile_kdf` y KDF) | Sin cobertura | El coste de la KDF y la contraseña; `ffi_records` solo cubre cabecera y registros |
| **KDF de KDBX** | Sin cobertura (deliberado) | Su coste lo fija el fichero; la cabecera, los bloques, el gunzip y el XML sí se cubren con clave fija (`import`, `kdbx_container`) |
| **Memoria del XML bajo `-rss_limit_mb=2048`** | Abierto | Hay límites y semillas de anidamiento (ID-INT-01 corregido), pero 2048 MB sigue siendo más de lo que aguanta un teléfono |
| **Diccionarios y estructura** (`-dict`, `Arbitrary` para JSON y XML) | No hay | Los objetivos de JSON parten de bytes crudos; los diccionarios acelerarían llegar a campos válidos |
| **Medición de cobertura** (`cargo fuzz coverage`) | No hay informe | No hay `exec/s`, ni cobertura por objetivo, ni dato sobre qué ramas no alcanza ninguno |
| **Jazzer para el Kotlin del autorrelleno** (`StructureParser`, `FieldClassifier`, `LoginMatcher`, `PublicSuffix`) | **Pospuesto** (decisión nº 9) | `StructureParser` depende de `AssistStructure` y Jazzer no lo alcanza sin Robolectric; `LoginMatcher` y `FieldClassifier` son funciones puras con tests de invariantes deterministas (`LoginMatcherTest`: 29 tests, generadores `Random(20260630)` y `Random(7)`, líneas 75 y 87); Jazzer exigiría pasar a JUnit 5 y añadir dependencias a la verificación de Gradle |
| **`StructureParser`** | Sin fuzzing | Refactorizar a una abstracción de nodos sin Android; es el criterio para reconsiderar Jazzer. Candidato real: [ID-INT-18](internal-review.md#id-int-18) (recursión sin tope) |
| **ClusterFuzzLite** | **Pospuesto** | Persistir el corpus necesita un repositorio o rama y un token (otro secreto) y un Dockerfile; el nocturno da lo esencial con las mismas herramientas. Criterio para reconsiderar: que la caché se pierda a menudo |
| **OSS-Fuzz** | **Descartado** | Exige base de usuarios y su calendario de divulgación no encaja antes de la auditoría |
| **Imágenes y QR** (descodificadores de imagen del sistema y ZXing) | Sin fuzzing | Código nativo del sistema fuera de alcance; ZXing sin UI se podría fuzzear con Jazzer más adelante |
| **Pruebas diferenciales** contra otra implementación (KeePassXC, `openssl`) | No hay | Los vectores dorados (`core/tests/vectors/op-v1.json`) cubren el formato propio |

## 5. Cómo reproducir una ejecución local

```sh
rustup toolchain install nightly --profile minimal && cargo install cargo-fuzz
cd fuzz
mkdir -p corpus/kdbx_xml && cp seeds/kdbx_xml/* corpus/kdbx_xml/
cargo +nightly fuzz run -O kdbx_xml corpus/kdbx_xml -- -max_total_time=60 -max_len=65536 -rss_limit_mb=2048 -timeout=10
```

El XML de [ID-INT-01](internal-review.md#id-int-01) ya no se reproduce: lo cubre el test
`deep_group_nesting_is_refused_before_it_costs_memory` (`cargo test -p op-core deep_group`) y las semillas
de `fuzz/seeds/kdbx_xml/`.

## 6. Qué no se ha podido comprobar

- Ninguna ejecución de `cargo fuzz` en esta revisión (solo la comprobación de símbolos y, antes de
  `2bd56ce`, los programas de prueba de ID-INT-01 e ID-INT-25).
- Las cifras de ejecuciones, `exec/s`, cobertura y duración de los trabajos de CI.
- Que el workflow nocturno funcione en GitHub (corpus restaurado y guardado, artefactos en un
  fallo).
