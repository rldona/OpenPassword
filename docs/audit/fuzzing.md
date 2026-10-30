# Fuzzing

Qué se fuzzea, cómo, con qué ganchos, qué falta y por qué se pospone. La guía de uso está en
[`fuzz/README.md`](../../fuzz/README.md); la decisión, en [`decisions.md`](decisions.md) (ADR-AUD-05).

Estado verificado el 2026-10-30 sobre el árbol de trabajo (`HEAD` `3725741` más cambios sin confirmar).
**Los cinco objetivos nuevos, los ganchos `cfg(fuzzing)`, el workflow nocturno y la bajada de la CI a 30 s
no están confirmados en `git`** (`git status`: `fuzz/fuzz_targets/{backup_body,ffi_records,item_open,item_plaintext,vault_json}.rs`,
`fuzz/seeds/…` y `.github/workflows/fuzz-nightly.yml` sin seguimiento). Los cinco primeros objetivos sí
están en `8063fd1`.

## 1. Cobertura actual: diez objetivos

Todos son `cargo-fuzz` (libFuzzer con AddressSanitizer por defecto), registrados en `fuzz/Cargo.toml`
(espacio de trabajo aparte, necesita nightly). Parámetros comunes de la CI:
`-O --target x86_64-unknown-linux-gnu … -max_len=65536 -rss_limit_mb=2048 -timeout=10`.

| Objetivo | Origen | Qué recibe | Qué recorre | Semillas (`fuzz/seeds/<objetivo>/`) | Corpus local (ficheros, no versionado) |
|---|---|---|---|---|---|
| `import` | `8063fd1` | Fichero | `import::needs_password` y `import::parse(data, now)`: CSV, Bitwarden JSON y `.1pux`. **No** llega a `kdbx::parse` ([ID-INT-25](internal-review.md#id-int-25)) | 6 (9 521 B) | 27 888 |
| `kdbx_xml` | `8063fd1` | XML UTF-8 | `kdbx_fuzzing::xml`: `read_entries` (grupos, papelera, historial, valores protegidos con flujo ChaCha20 fijo) y `entry_to_item` | 1 (2 614 B) | 5 334 |
| `key_file` | `8063fd1` | Bytes | `kdbx_fuzzing::key_file` (`key_file_key`) | 2 (342 B) | 4 918 |
| `backup_header` | `8063fd1` | Bytes | `backup::read_header` y `kdf.check_bounds()`. **No** llama a `check_within(MOBILE_MAXIMUM)` (ADR-AUD-07 lo pedía; `fuzz/fuzz_targets/backup_header.rs:7-9`) | 1 (3 953 B) | 2 861 |
| `totp` | `8063fd1` | UTF-8 | `Totp::parse`, `code_at(u64::MAX)`, `seconds_remaining` | 2 (157 B) | 1 868 |
| `vault_json` | nuevo | Bytes | `serde_json` de `VaultHeader` y de `EncryptedItem` (`hex_bytes`), con ida y vuelta | 2 (1 142 B) | 4 513 |
| `item_open` | nuevo | `EncryptedItem` en JSON | `vault.decrypt_overview`, `decrypt_details`, `decrypt_item` con la bóveda de prueba | 1 (919 B) | 3 276 |
| `item_plaintext` | nuevo | Bytes | `seal_item_part` (relleno + sellado con clave fija) → `decrypt_details` y `decrypt_overview`: `padding::unpad` y el JSON de los elementos | 3 (178 B) | 2 228 |
| `backup_body` | nuevo | Bytes | `seal_backup` (STREAM con clave fija) → `open_with_vault`: troceado y `Body` JSON, **sin KDF**; también los bytes crudos | 3 (2 391 B) | 936 |
| `ffi_records` | nuevo | Bytes (`Unstructured`) | `op_ffi::Vault::unlock_with_vault_key` con cabecera arbitraria y fija, y `decrypt_overview`/`decrypt_details` con `EncryptedItemRecord` arbitrario o sellado | 1 (98 B) | 1 755 |

- **Total**: 22 semillas, unos 21 000 B; el corpus local son ficheros del equipo de desarrollo y no
  entra en el repositorio (`fuzz/.gitignore`: `corpus/`, `artifacts/`).
- **Resultados**: `fuzz/artifacts/<objetivo>/` está **vacío** en los diez objetivos en esta máquina
  (`ls fuzz/artifacts/*`): ningún fallo guardado. El mensaje del commit `8063fd1` da «unos 48 millones
  de ejecuciones en local sin fallos» **para los cinco primeros objetivos**. **No hay ninguna cifra de
  ejecuciones registrada para los cinco nuevos**: el tamaño de su corpus local demuestra que se
  ejecutaron, no cuánto. Cualquier cifra de ejecuciones por objetivo nuevo sería una estimación.
- **Hallazgos que ha producido hasta ahora**: ninguno. Los dos defectos de `op-core` que el fuzzing
  **no** ha encontrado —y que esta revisión sí— están en `internal-review.md`:
  [ID-INT-01](internal-review.md#id-int-01) (memoria cuadrática del XML, que `kdbx_xml` no encuentra
  porque exige anidamiento profundo **y** muchas entradas) y [ID-INT-25](internal-review.md#id-int-25)
  (el hueco de cobertura de la cabecera de KDBX).

## 2. Ganchos `cfg(fuzzing)`

`cargo fuzz` compila con `--cfg fuzzing`; nada más en el repositorio lo activa. Lo declara
`[workspace.lints.rust] unexpected_cfgs … check-cfg = ["cfg(fuzzing)"]` (`Cargo.toml:15`).

| Módulo | Fichero y línea | Qué expone |
|---|---|---|
| `op_core::fuzzing` | `core/src/lib.rs:26` | `TEST_VAULT_KEY` (`[7; 32]`), `header()` (cabecera bien formada, clave envuelta vacía), `vault()` (baúl abierto con `unlock_with_vault_key`); reexporta los dos siguientes |
| `vault::fuzzing` | `core/src/vault/mod.rs:273` | `seal_item_part(vault, plaintext)`: clave de elemento `[9; 32]`, nonce `[5; …]`, id `[2; 16]`, relleno y sellado, para llegar a `unpad` y al JSON |
| `backup::fuzzing` | `core/src/backup/mod.rs:144` | `seal_backup(vault, body)` (clave de fichero `[4; 32]`, nonce `[6; …]`) y `open_with_vault(bytes, vault)` (`decrypt_body` sin KDF) |
| `import::kdbx_fuzzing` | `core/src/import/mod.rs:10-11` → `core/src/import/kdbx.rs:622` | `xml(&str)` y `key_file(&[u8])` |

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
  ganchos y los vectores de `core/tests/vectors/op-v1.json` (los de los cinco nuevos, según
  `fuzz/README.md`). No están minimizadas.
- **PR y *push*** (`ci.yml`, job `fuzz`): corpus vacío más las semillas, **30 s por objetivo**
  (`-max_total_time=30`), diez objetivos en serie, sin caché. Si falla, sube `fuzz/artifacts`.
- **Nocturno** (`.github/workflows/fuzz-nightly.yml`): `cron: '17 3 * * *'` (UTC) y
  `workflow_dispatch`. Matriz de diez trabajos en paralelo, uno por objetivo, `timeout-minutes: 150`,
  `-max_total_time=600` (**10 min**), `concurrency` de un solo grupo sin cancelación.
  - **Corpus en caché**: `actions/cache` con clave `fuzz-corpus-<objetivo>-<run_id>` y
    `restore-keys: fuzz-corpus-<objetivo>-`: cada noche restaura el más reciente y guarda uno nuevo.
  - **Minimización**: `cargo fuzz cmin` solo el domingo (`date -u +%u = 7`).
  - **Si un objetivo falla**: sube `fuzz/artifacts/<objetivo>` y el trabajo queda en rojo. `fail-fast:
    false`, así que los otros nueve terminan.
- **Nunca ejecutado**: el fichero no está confirmado ni en `git`, así que **no existe ninguna ejecución
  de GitHub Actions** (ni manual ni programada). El paso 12 del plan pide una ejecución
  `workflow_dispatch` en verde.
- **Caducidad**: la caché de Actions caduca a los 7 días sin uso (ADR-AUD-05). Con `actions/cache`, el
  guardado se hace al acabar con éxito: si un objetivo falla esa noche, **ese día no se guarda el
  corpus** (comportamiento por defecto de la acción; sin verificar en este repositorio).

### Tiempos (estimaciones, no medidas)

| Qué | Estimación | Base |
|---|---|---|
| Job `fuzz` de PR | ≈ 5 min de fuzzing (10 × 30 s) más compilación de 10 binarios | Aritmética del `ci.yml`; ADR-AUD-05 dice «unos 5 min». **No hay una duración de ejecución real registrada** |
| Nocturno | ≈ 100 min de CPU (10 × 10 min), ≈ 10–20 min de reloj en paralelo más compilación | Aritmética del workflow; sin medir |
| Ejecuciones por objetivo y por minuto | **Sin medir** | No hay `exec/s` en el repositorio |

## 4. Qué falta y por qué se pospone

| Hueco | Estado | Motivo |
|---|---|---|
| **Cabecera externa de KDBX, `variant_dictionary`, flujos de bloques (HMAC y hash), gunzip y cabecera interna** | **Sin cobertura** ([ID-INT-25](internal-review.md#id-int-25)) | `import` se detiene antes de `kdbx::parse`. Cerrarlo necesita un gancho que fije contraseña y KDF mínima. **Es el hueco más barato de cerrar y el de mayor valor** |
| **`backup_header` sin `check_within(MOBILE_MAXIMUM)`** | Pedido por ADR-AUD-07, no hecho | El techo vive en `op-ffi`; `fuzz` ya depende de `op-ffi` (`ffi_records`) |
| **`open_backup` y `parse_import` completos** (con `check_mobile_kdf` y KDF) | Sin cobertura | El coste de la KDF y la contraseña; `ffi_records` solo cubre cabecera y registros |
| **Dependencia de la anidación del XML** (ID-INT-01) | Sin semilla ni test | Falta una semilla con grupos anidados y muchas entradas, y un límite de memoria más bajo: `-rss_limit_mb=2048` es mucho más de lo que aguanta un teléfono |
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

Para reproducir [ID-INT-01](internal-review.md#id-int-01) sin libFuzzer: un crate de prueba fuera del
repositorio que dependa de `op-core` con `RUSTFLAGS="--cfg fuzzing"` y llame a
`op_core::import::kdbx_fuzzing::xml` con el XML de la tabla de ese hallazgo.

## 6. Qué no se ha podido comprobar

- Ninguna ejecución de `cargo fuzz` en esta revisión (solo la comprobación de símbolos y el programa
  de prueba de ID-INT-01 e ID-INT-25).
- Las cifras de ejecuciones, `exec/s`, cobertura y duración de los trabajos de CI.
- Que el workflow nocturno funcione en GitHub (corpus restaurado y guardado, artefactos en un
  fallo).
