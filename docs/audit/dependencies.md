# Dependencias

Inventario de lo que entra en el producto y en su cadena de compilación, con los números reales del
árbol, qué se enlaza en `libop_ffi.so`, duplicados, avisos, licencias frente a GPL-3.0, pines y
propuestas. Complementa ADR-AUD-04 en [`decisions.md`](decisions.md).

Estado verificado el 2026-10-30 sobre el árbol de trabajo (`HEAD` `3725741` más cambios sin confirmar).
**`deny.toml`, `.github/dependabot.yml`, `android/gradle/verification-metadata.xml`, las Actions fijadas
por SHA y el job `release` están en el árbol de trabajo y no confirmados** ([`hardening.md`](hardening.md)).
Cada cifra lleva el comando que la produce (sección 8).

## 1. Cifras

| Medida | Valor | Cómo se obtiene |
|---|---|---|
| Paquetes en `Cargo.lock` (raíz) | **139** (136 de crates.io + 3 propios: `op-core`, `op-ffi`, `opvault-cli`) | `grep -c '^\[\[package\]\]' Cargo.lock`; `cargo metadata` |
| Paquetes en `fuzz/Cargo.lock` | 132 | Idem. Espacio de trabajo aparte (`fuzz/Cargo.toml`) |
| Orígenes distintos de crates.io | **0** | `cargo metadata`: ningún paquete con `source` ajeno; `deny.toml` `[sources]` deniega registros y `git` desconocidos |
| Unidades de biblioteca compiladas para `aarch64-linux-android` (`op-ffi`, release) | **73** (71 de terceros + `op-core` + `op-ffi`) | `cargo +nightly build -p op-ffi --lib --release --target aarch64-linux-android --locked -Z unstable-options --unit-graph`, unidades con plataforma y modo `build`, sin `proc-macro` ni `custom-build` |
| *Crates* con ruta visible en `libop_ffi.so` (arm64) | **23** | `strings -a …/libop_ffi.so \| grep -oE 'registry/src/[^/]+/[A-Za-z0-9_.+-]+'` (ver 2.3) |
| Componentes en la SBOM de Gradle (`releaseRuntimeClasspath`) | **144** | `android/app/build/reports/cyclonedx-direct/bom.json` (CycloneDX 3.5.1, 2026-10-30T09:34:26Z) |
| Componentes con suma SHA-256 en `verification-metadata.xml` | **478** componentes, **918** sumas | `grep -c "<component " …`, `grep -c "<sha256" …` |
| Versiones duplicadas (Rust) | **2** pares | `cargo metadata`: `getrandom` 0.2.17 y 0.3.4; `syn` 2.0.119 y 3.0.9 |
| Vulnerabilidades conocidas (Rust) | **0** | `cargo audit --deny warnings`: 1386 avisos cargados, 139 paquetes, salida 0 |
| `cargo deny --locked check` | `advisories ok, bans ok, licenses ok, sources ok` | `cargo deny --locked check` (0.20.2, en local) |
| Pruebas de Rust | **92 pasan, 1 ignorada** | `cargo test --workspace --locked` |

## 2. Rust

### 2.1 Dependencias directas

| Crate | Versión pedida | Resuelta | Para qué | Crate |
|---|---|---|---|---|
| `argon2` | `0.5` (sin características por defecto: `alloc`, `zeroize`) | 0.5.3 | Argon2id (KEK) y KeePass | `op-core` |
| `chacha20poly1305` | `0.10` (`stream`) | 0.10.1 | AEAD XChaCha20-Poly1305 y STREAM | `op-core` |
| `hkdf`, `hmac`, `sha2`, `sha1` | `0.12`, `0.12`, `0.10`, `0.10` | 0.12.4, 0.12.1, 0.10.9, 0.10.7 | HKDF, HMAC, SHA-2, TOTP SHA-1 | `op-core` |
| `aes`, `cbc`, `chacha20`, `salsa20` | `0.8`, `0.1`, `0.9`, `0.10` | 0.8.4, 0.1.2, 0.9.1, 0.10.2 | Cifrados de KeePass (KDBX) | `op-core` |
| `flate2` | `1` (`zlib-rs`) | 1.1.10 | gunzip de KDBX | `op-core` |
| `zip` | `=9.0.3` (sin características por defecto, `deflate-flate2-zlib-rs`) | 9.0.3 | `.1pux` | `op-core` |
| `quick-xml` | `0.42` | 0.42.0 | XML de KDBX y archivos de clave | `op-core` |
| `serde`, `serde_json` | `1` | 1.0.229, 1.0.154 | Formato `.opvault`, importadores | `op-core`, `op-ffi` |
| `base64`, `hex`, `unicode-normalization` | `0.22`, `0.4`, `0.1` | 0.22.1, 0.4.3, 0.1.26 | Codificaciones y NFKD | `op-core` (`hex` también `op-ffi`) |
| `getrandom` | `0.3` | 0.3.4 | CSPRNG del sistema | `op-core` |
| `zeroize` | `1` (`derive`) | 1.9.1 | Borrado de claves | `op-core`, `op-ffi` |
| `thiserror` | `2` | 2.0.21 | Errores | `op-core`, `op-ffi` |
| `uniffi` | `0.32` (características por defecto: `cargo-metadata`, …) | 0.32.2 | Bindings de Kotlin | `op-ffi` |
| `anyhow`, `clap`, `rpassword` | `1`, `4`, `7` | 1.0.104, 4.6.7, 7.5.4 | CLI (**fuera de alcance**) | `opvault-cli` |

`Cargo.toml` del núcleo: 21 dependencias; `op-ffi`: 5 más `op-core`; la CLI: 8. Las dependencias de
desarrollo de `op-core` son solo `op-core` con `insecure-test-params` (`core/Cargo.toml`).

### 2.2 Qué se enlaza en `libop_ffi.so`

- Es un `cdylib` (`ffi/Cargo.toml`, `crate-type = ["cdylib", "lib"]`) compilado con `--release --locked
  -p op-ffi` y RUSTFLAGS codificados (`--remap-path-prefix`, `--cfg aes_armv8`,
  `android/app/build.gradle.kts:128-131`), LTO y `panic = "unwind"` (`Cargo.toml:21-25`).
- El `cdylib` **no incluye** `libop_core.rlib` como biblioteca aparte: `op-core` está dentro.
- **Compiladas para el objetivo: 73 unidades.** Incluyen crates que solo existen por la característica
  `cargo-metadata` de `uniffi` (`cargo_metadata`, `camino`, `cargo-platform`, `semver`, `tempfile`,
  `fastrand`, `rustix`, `errno`, `linux-raw-sys`, `typed-path`): `cargo tree -i tempfile --target
  aarch64-linux-android` los muestra colgando de `uniffi` (`uniffi_pipeline` → `uniffi_meta` →
  `uniffi_macros`). **Ninguno deja huella en el binario**: `strings -a libop_ffi.so | grep -c
  'cargo_metadata\|camino\|tempfile'` da **0**. Se eliminan por LTO; la evidencia es la ausencia de
  cadenas, no un análisis de símbolos.
- **Visibles en el binario (arm64): 23 crates**: `aes`, `anyhow`, `argon2`, `base64`, `blake2`, `bytes`,
  `cipher`, `crc32fast`, `flate2`, `hashbrown`, `hex`, `hkdf`, `indexmap`, `itoa`, `memchr`,
  `quick-xml`, `serde_core`, `serde_json`, `tinyvec`, `unicode-normalization`, `uniffi_core`, `zip`,
  `zlib-rs`. Es un **mínimo**: una dependencia sin rutas de *panic* (por ejemplo `sha2`,
  `chacha20poly1305`) no aparece aunque esté enlazada.
- **No se enlazan** (solo compilador o herramienta de la máquina de compilación): `uniffi_bindgen`,
  `askama`, `basic-toml`, `clap` (de `uniffi` con `cli`), `syn`, `proc-macro2`, `quote`. El bindgen se
  ejecuta con `cargo run --features bindgen` (`build.gradle.kts:155`).
- **Tamaño** (`unzip -l android/app/build/outputs/apk/release/app-release.apk`): `libop_ffi.so`
  1 153 984 B (arm64-v8a), 882 924 B (armeabi-v7a) y 1 313 032 B (x86_64). Sin recortar, en
  `build/rust/jniLibs`: 1 565 832, 1 197 124 y 1 610 976 B. El mensaje del commit `3725741` da +9,3 %
  en aarch64 por `unwind`; no se ha vuelto a medir.

### 2.3 Duplicados y avisos

| Paquete | Versiones | Camino | Efecto |
|---|---|---|---|
| `getrandom` | 0.2.17 y 0.3.4 | 0.3.4: directo de `op-core`. 0.2.17: por `rand_core` 0.6 → `crypto-common` 0.1.7 → toda la familia RustCrypto 0.1x (`aead`, `cipher`, `digest`, `universal-hash`) | Dos copias del acceso al CSPRNG en el binario (la 0.2 solo con la característica `getrandom` de `rand_core`, sin verificar si se enlaza) |
| `syn` | 2.0.119 y 3.0.9 | Ambas solo en herramientas de compilación (`proc-macro`) | Ninguno en el binario |

`cargo deny` los marca como `warn` (`deny.toml`: `multiple-versions = "warn"`). `wildcards = "warn"` y no
`deny` porque `op-ffi` y la CLI declaran `op-core = { path = … }` sin `publish = false` (comentario en
`deny.toml`).

**Aviso ignorado**: `RUSTSEC-2026-0374` (`basic-toml` 0.1.10, sin mantenimiento) en
`deny.toml`. Solo lo arrastra `uniffi_bindgen` → `askama`, que no está en el grafo del objetivo Android
(`cargo tree -p op-ffi --target aarch64-linux-android` no lo contiene; sí está en `Cargo.lock:167`).
`cargo audit` (sin `.cargo/audit.toml`, borrado en el árbol de trabajo) devuelve 0 vulnerabilidades.

### 2.4 Licencias frente a GPL-3.0-or-later

De `cargo metadata` sobre los 136 paquetes de crates.io:

| Licencia (SPDX) | Paquetes |
|---|---|
| `MIT OR Apache-2.0` | 82 |
| `MIT` | 17 |
| `Apache-2.0 OR MIT` | 12 |
| **`MPL-2.0`** | **8** (`uniffi`, `uniffi_bindgen`, `uniffi_core`, `uniffi_internal_macros`, `uniffi_macros`, `uniffi_meta`, `uniffi_pipeline`, `uniffi_udl`) |
| `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | 5 |
| `MIT/Apache-2.0` | 3 |
| `Apache-2.0` | 2 |
| `(MIT OR Apache-2.0) AND Unicode-3.0` | 2 (`unicode-ident`, `unicode-normalization`) |
| `Unlicense OR MIT` | 1 (`memchr`) |
| `MIT OR Apache-2.0 OR LGPL-2.1-or-later` | 1 (`r-efi`, solo UEFI) |
| `BSD-3-Clause` | 1 (`subtle`) |
| `Zlib OR Apache-2.0 OR MIT` | 1 (`tinyvec`) |
| `Zlib` | 1 (`zlib-rs`) |

- **Compatibilidad**: MIT, BSD-3-Clause, Zlib, Unicode-3.0 y Apache-2.0 son compatibles con GPL-3.0; MPL-2.0
  permite la distribución bajo GPL (su cláusula de «licencia secundaria»). `cargo deny list` agrupa
  6 paquetes MPL-2.0 (sin `uniffi_bindgen` ni `uniffi_udl`, que solo están en herramientas). **No es
  asesoría jurídica**: es lectura de los metadatos SPDX.
- **Ninguna licencia incompatible** en `cargo deny` (`licenses ok`) con las 10 licencias permitidas de
  `deny.toml`.
- **La lista de licencias permitidas es más ancha de lo necesario**: quitando `Unlicense`,
  `Apache-2.0 WITH LLVM-exception` y `LGPL-2.1-or-later` el resultado sigue siendo `licenses ok`
  (probado con una copia de `deny.toml` en una ruta temporal, `cargo deny --locked --config … check
  licenses`). Los tres solo aparecen como alternativa en una disyunción `OR` que ya se cumple con MIT o Apache. Esto
  importa por `LGPL-2.1-or-later`: abre una puerta que `deny` no necesita. Es una **decisión de
  la lista final** (nº 7, [`decisions.md`](decisions.md)).

### 2.5 Pines y herramientas de Rust

| Elemento | Pin | Dónde |
|---|---|---|
| Compilador | `1.99.1` exacto, con `rustfmt`, `clippy` y los tres objetivos Android | `rust-toolchain.toml` |
| `zip` | `=9.0.3` (comentario: «newer 9.1.x releases are under two weeks old») | `core/Cargo.toml` |
| Resolución | `Cargo.lock` versionado; `--locked` en `cargo test`, `clippy`, `build`, `deny` y en la tarea de Gradle (`build.gradle.kts:135`) | `ci.yml` |
| `cargo-ndk` | `--locked --version 4.1.2` | `ci.yml` |
| `cargo-cyclonedx` | `--locked --version 0.5.9` | `ci.yml`, job `release` |
| `cargo-deny`, `cargo-fuzz` | `0.20.2`, `0.13.2` vía `taiki-e/install-action` | `ci.yml`, `fuzz-nightly.yml` |
| NDK | `30.0.16248370` | `build.gradle.kts:23`, `ci.yml` |
| Actions | SHA de 40 caracteres con la versión en un comentario (7 acciones distintas) | `ci.yml`, `fuzz-nightly.yml` |

El resto de dependencias son rangos de *caret*: el `Cargo.lock` es lo que las fija.
**Límite**: `cargo install` compila desde crates.io sin suma de comprobación propia, y
`taiki-e/install-action` descarga binarios; no hay comprobación independiente de lo descargado
(ver 7).

## 3. Gradle

### 3.1 Dependencias directas (`android/app/build.gradle.kts:75-97`, `libs.versions.toml`)

| Dependencia | Versión | Alcance |
|---|---|---|
| Compose BOM + `activity-compose`, `material3`, `material-icons-core`, `ui`, `ui-tooling-preview` | `2026.09.00`; 1.13.0; 1.4.0 (resuelta); 1.7.8; 1.12.1 | Release |
| `lifecycle-process`, `lifecycle-runtime-compose` | 2.11.0 | Release |
| `kotlinx-coroutines-android` | 1.11.0 | Release |
| **`jna` `@aar`** | 5.17.0 | Release (UniFFI en Kotlin la usa para cargar la biblioteca nativa) |
| `camera-camera2`, `camera-lifecycle`, `camera-view` | 1.6.2 | Release (escáner de QR) |
| `zxing-core` | 3.5.4 | Release (descodifica QR; sin UI ni servicios de Google) |
| `ui-tooling` | (BOM) | Solo `debug` |
| `junit`, `androidx.test:runner`, `androidx.test.ext:junit` | 4.13.2, 1.7.0, 1.3.0 | Pruebas |

Plugins de build: AGP `9.4.1`, Kotlin Compose `2.4.21`, `org.cyclonedx.bom` `3.5.1`. Gradle `9.8.2` con
`distributionSha256Sum` (`gradle-wrapper.properties`).

### 3.2 Lo que acaba en el APK (SBOM de `releaseRuntimeClasspath`, 144 componentes)

| Grupo | Componentes |
|---|---|
| `androidx.*` | 117 (de ellos `androidx.compose.*` 37, `androidx.lifecycle` 18, `androidx.camera` 8) |
| `org.*` (Kotlin, `kotlinx`, `checker-qual`, `jspecify`, `annotations`) | 15 |
| `com.*` (`google.guava` 3, `google.zxing`, `google.dagger`, `google.errorprone`, `google.j2objc`, …) | 9 |
| `net.java.dev.jna`, `jakarta.inject`, `javax.inject` | 3 |

- **Código nativo en el APK**: `libop_ffi.so` y **`libjnidispatch.so` de JNA** (165 992 B arm64, 116 344 B
  armv7, 116 904 B x86_64), tres ABI (`unzip -l app-release.apk`). `abiFilters` descarta las demás.
- **Datos incluidos** (APK de release): `public_suffix_list.dat` (338 012 B, MPL-2.0, `README.md:58`) y
  `assets/eff_large_wordlist.txt` (62 144 B, EFF Large Wordlist, **CC BY 3.0 US** según `README.md:57`).
- **Superficie no usada**: `androidx.media3:media3-common`, `-container` y `-muxer` y
  `androidx.camera:camera-video` llegan por CameraX para vídeo, que la app no usa (el manifiesto elimina
  `ACCESS_NETWORK_STATE`, que arrastra media3). **Sin verificar** si se pueden excluir sin romper el
  escáner.
- **Gradle sin análisis de vulnerabilidades**: ni en la CI ni en local. `cargo audit` y `cargo deny`
  cubren solo Rust. `guava 33.3.1-android`, `dagger 2.59` y `jna 5.17.0` no se han comparado con ninguna base de
  avisos en esta revisión.

### 3.3 Verificación de dependencias

`android/gradle/verification-metadata.xml` (árbol de trabajo): `verify-metadata` activo, **sin firmas**
(`verify-signatures` en `false`), **478** componentes y **918** sumas SHA-256, **133** grupos, y
`aapt2` de **Linux y macOS** (`com.android.tools.build:aapt2:9.4.1-15978811`, jars `linux` y `osx`).
Cubre los plugins de build además de las bibliotecas. **No se ha ejecutado una compilación con la
verificación activa en esta revisión** (no hay JDK en el `PATH`): sin verificar que el fichero
sea completo. La CI lo comprobará al compilar en Linux.

### 3.4 Licencias de Gradle (de la SBOM)

Todos los componentes son `Apache-2.0`, salvo: `androidx.camera:camera-core` (`Apache-2.0`,
`BSD-3-Clause`), `org.checkerframework:checker-qual` (`MIT`) y **`net.java.dev.jna:jna`
(`LGPL-2.1-or-later` y `Apache-2.0`, doble licencia)**. Se puede elegir Apache-2.0, compatible con
GPL-3.0; si se elige LGPL, también lo es. El `README.md` (sección «Componentes de terceros», líneas 57-58) **no menciona JNA**: solo la lista
EFF y la de sufijos. Hay que decir cuál se aplica. Además, **sin verificar** si CC BY 3.0 US (lista EFF)
es compatible con GPL-3.0: la FSF solo reconoce CC BY 4.0 como compatible, según mi conocimiento. Es
un dato, no código, pero conviene decidirlo con la licencia delante.

## 4. Cadena de compilación

| Eslabón | Fijación | Debilidad |
|---|---|---|
| Código fuente | Commit y, tras ADR-AUD-01, etiqueta firmada | — |
| `Cargo.lock` | Versionado, `--locked` | Resuelve contra crates.io; sin copia local (`cargo vendor` es opcional) |
| Gradle | `libs.versions.toml` exactas + `verification-metadata.xml` + wrapper con suma | Sin firmas PGP; JNA y CameraX traen binarios |
| Compilador y NDK | `rust-toolchain.toml` y `ndkVersion` | La descarga del NDK en la CI no se comprueba con suma (`sdkmanager`) |
| Acciones de CI | SHA de commit | `dtolnay/rust-toolchain`: SHA de la rama `stable`, no de una versión |
| Binarios de herramientas | Versión | `taiki-e/install-action` descarga; `cargo install` compila de crates.io sin suma |
| APK de la release | Atestación de procedencia (Sigstore) del APK **sin firmar** y de las SBOM | La firma se añade en el ordenador del mantenedor después; **el APK firmado no está atestado** (ver 6) |

## 5. SBOM y atestaciones: estado

- **Job `release`** (`ci.yml`, solo con etiquetas `v*`; árbol de trabajo, **no confirmado y no
  ejecutado nunca**): compila el APK, genera `op-ffi.cdx.json` (`cargo cyclonedx --manifest-path
  ffi/Cargo.toml --format json --spec-version 1.5`) y la SBOM de Gradle (`cyclonedxDirectBom`,
  `includeConfigs = releaseRuntimeClasspath`), calcula `SHA256SUMS` y atesta el APK sin firmar y las
  dos SBOM con `actions/attest-build-provenance`. Permisos `id-token: write` y `attestations: write`
  solo en ese job. Sube el artefacto con 90 días de retención. **No crea la *release*** de GitHub: adjuntar
  los ficheros es un paso manual.
- **Qué contiene la SBOM de Rust**: la salida de `cargo cyclonedx` sobre `ffi/Cargo.toml`, que
  incluye el grafo completo de `op-ffi` y no solo lo enlazado. Dos ficheros `core/op-core.cdx.json` y
  `cli/opvault-cli.cdx.json` están sin seguimiento en el árbol y no se publican (ID-INT-23).
- **Qué no contiene**: el `libjnidispatch.so` como componente nativo propio, las listas de datos (sufijos
  públicos y EFF) ni las herramientas de compilación.

## 6. Propuestas

Prioridad: **P1** antes de congelar `v0.2.0`; **P2** durante la auditoría; **P3** después.

| Prio. | Propuesta | Por qué | Estado |
|---|---|---|---|
| P1 | **Confirmar y ejecutar una vez** el job `release` con una etiqueta de prueba (`v0.2.0-rc1`) y `gh attestation verify` | Es el único modo de saber que la atestación y las SBOM funcionan; la propia decisión lo exige (paso 17) | Pendiente |
| P1 | Quitar `Unlicense`, `Apache-2.0 WITH LLVM-exception` y `LGPL-2.1-or-later` de `deny.toml` | Reducir la lista a lo necesario (sección 2.4, probado) | Pendiente (decisión nº 7) |
| P1 | **Decisión humana**: confirmar la licencia aplicada a JNA y la compatibilidad de CC BY 3.0 US (lista EFF) con GPL-3.0, y reflejarlo en el `README.md` | Evitar un incumplimiento de licencia | Pendiente |
| P1 | Borrar o ignorar los `*.cdx.json` de `core/` y `cli/` | Evitar confirmar SBOM que no se publican | Pendiente |
| P1 | Comprobar la compilación con `verification-metadata.xml` en Linux y macOS y ver que falla si se altera una suma | Es la prueba del paso 16 | Pendiente (sin JDK en esta máquina) |
| P2 | Atestar también el **APK firmado**, o publicar el `SHA256SUMS` del sin firmar y la regla de comparación | Hoy la firma rompe la cadena de procedencia | Propuesta |
| P2 | Análisis de avisos de Gradle (por ejemplo `osv-scanner` sobre `verification-metadata.xml` o sobre la SBOM) en la CI | Hoy no hay ninguno | Propuesta |
| P2 | Valorar `uniffi = { default-features = false }` con la característica mínima y excluir `media3` de CameraX | Reducir lo que se compila y se distribuye (73 unidades de biblioteca; 3 artefactos `media3`) | **Sin verificar** que compile y funcione |
| P2 | Añadir al SBOM `libjnidispatch.so`, la lista de sufijos públicos, la lista EFF y el NDK | SBOM completa de lo que se envía | Propuesta |
| P2 | `cargo vendor` del espacio de trabajo en la versión congelada, adjunto al paquete del auditor | Revisión sin conexión del código exacto de las dependencias | Opcional en ADR-AUD-01 |
| P2 | `publish = false` en `ffi/Cargo.toml` y `cli/Cargo.toml` y `allow-wildcard-paths = true`; después `wildcards = "deny"` | Cerrar el pendiente de `deny.toml` | Comentario en `deny.toml` |
| P2 | Que Dependabot no abra PR contra `release/0.2` (solo vigila la rama por defecto: `.github/dependabot.yml` no define `target-branch`) | La política de ADR-AUD-01 prohíbe subidas de rutina en la rama congelada | Cierto por defecto; documentarlo |
| P3 | `cargo vet` para las dependencias de criptografía | Revisión humana por versión; descartado antes de la auditoría | Descartado en ADR-AUD-04 |
| P3 | PGP en `verification-metadata.xml` | Mantener un llavero; coste alto | Descartado |

## 7. Qué no se ha podido verificar

- Que la verificación de Gradle esté completa y que falle con una suma alterada.
- Que la SBOM de Gradle cubra todo lo que entra en el APK (es la del classpath de runtime, no un
  análisis del APK final).
- Si `getrandom` 0.2.17 queda enlazado.
- Que `taiki-e/install-action` compruebe las sumas de lo que descarga.
- Que no existan avisos de Gradle (no se ha escaneado).
- La licencia que se aplica de JNA y la compatibilidad de CC BY 3.0 US con GPL-3.0.

## 8. Comandos para reproducirlo

```sh
grep -c '^\[\[package\]\]' Cargo.lock fuzz/Cargo.lock           # 139 y 132
cargo metadata --locked --format-version 1 > meta.json          # licencias, duplicados, orígenes
cargo audit --deny warnings                                     # 0 vulnerabilidades
cargo deny --locked check                                       # advisories, bans, licenses, sources
cargo deny --locked list                                        # licencias por paquete
cargo tree -p op-ffi --locked --target aarch64-linux-android -d # duplicados del objetivo
unzip -l android/app/build/outputs/apk/release/app-release.apk | grep -E 'lib/|public_suffix'
strings -a android/app/build/rust/jniLibs/arm64-v8a/libop_ffi.so | grep -oE 'registry/src/[^/]+/[A-Za-z0-9_.+-]+'
python3 -c "import json;print(len(json.load(open('android/app/build/reports/cyclonedx-direct/bom.json'))['components']))"
```
