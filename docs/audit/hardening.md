# Endurecimiento: ejecutado y pendiente

Lista de las medidas de endurecimiento del proyecto con su prioridad, su estado y lo que las verifica
(commit, test o comando). Distingue lo **hecho** (confirmado en `git`), lo **hecho solo en parte**,
lo **pendiente** y lo **pospuesto o descartado**.

Estado verificado el 2026-10-30 sobre `HEAD` `2bd56ce` («Fase 3: endurecimiento, cadena de suministro y
paquete de auditoría») **más trabajo sin commit** (correcciones de autorrelleno, ajuste del techo de KDBX, guardia de `cfg(fuzzing)`, documentación; `git status` lo lista): lo que antes figuraba como «hecho, sin
confirmar» está ya en ese commit (o en `3725741`, si se indica); lo marcado «sin commit» no. Los números de línea citados en
`ffi/src/lib.rs` y `VaultSession.kt` se escribieron antes de las últimas correcciones y pueden haberse
desplazado; el nombre del test o del símbolo es la referencia estable.

**Prioridad** (de lo que queda por hacer, respecto a la congelación de `v0.2.0`): **P1** bloquea la
congelación o es un defecto que el auditor encontrará en la primera hora; **P2** se corrige durante la
auditoría; **P3** después.

**Estado**: **Hecho**, **Parcial**, **Pendiente**, **Pospuesto**, **Descartado**.

Las pruebas de Rust se han ejecutado en esta revisión (`cargo test --workspace --locked`: 95 pasan,
1 ignorada: 45 unitarios de `op-core`, 9 + 3 + 19 + 5 de integración y 14 de `op-ffi`; `cargo deny --locked check`: `advisories ok, bans ok, licenses ok, sources ok`). **Las pruebas de Kotlin, las instrumentadas y las manuales no se han ejecutado** (no hay
JDK en esta máquina): las filas que dependen de ellas lo dicen.

## 1. Plan de ADR-AUD: los 19 pasos

Reproduce la tabla de «Plan de implementación» de [`decisions.md`](decisions.md) con el estado real.

| # | Paso | Estado | Commit o cambio | Lo verifica |
|---|---|---|---|---|
| 1 | `lock`, `is_locked` y `with` resistentes al envenenamiento | **Hecho** | `3725741` (`ffi/src/lib.rs:302-322`, `437-443`) | `lock_wipes_key_after_poisoned_mutex` (`:705`), `with_after_poison_returns_internal_and_locks` (`:713`) |
| 2 | `panic = "unwind"` y medición de tamaño | **Hecho** | `3725741` (`Cargo.toml:25`) | `cargo build --release`; el mensaje del commit da +9,3 % en aarch64 (umbral 15 %). **No hay medición de las otras dos ABI** en el commit; en el APK: arm64 1 153 984 B, armv7 882 924 B, x86_64 1 313 032 B |
| 3 | Capturar `InternalException` y pasar la sesión a `Locked` | **Hecho** | `3725741` (`VaultSession.kt`, `withVault`) y `2bd56ce` (los 4 sitios que quedaban: `ItemDetailScreen.kt`, `ItemEditorScreen.kt`, `AutofillAuthActivity.kt`; [ID-INT-07](internal-review.md#id-int-07)) | `FfiFailureHandlingTest` (7 tests, no ejecutados). **Límite**: el test solo busca `catch (e: OpException)` sin captura amplia; un sitio sin ningún `catch` no lo vería |
| 4 | Prueba aislada de `SecretString` | **Hecho** | `2bd56ce` (`ffi/src/secret.rs`) | Bindings regenerados: `uniffi::custom_type!` con `String`; `debug_hides_the_value`, `zeroize_empties_the_text` |
| 5 | `SecretString` y `Zeroizing` en toda la API | **Hecho** | `2bd56ce` (`ffi/src/lib.rs`, `ffi/Cargo.toml` +`zeroize`) | `cargo test -p op-ffi` (14), `debug_hides_the_value`, `zeroize_empties_the_text`, `secret_strings_cross_records_and_options` (`lib.rs:880`) |
| 6 | `check_within`, `MOBILE_MAXIMUM`, `KdfTooExpensive`, `backup_kdf` | **Hecho** en `2bd56ce` | `core/src/crypto/kdf.rs:48-66`, `ffi/src/lib.rs:33,472-501` | `check_within_applies_each_axis_of_a_lower_ceiling` (`kdf.rs`), `backup_above_the_mobile_ceiling_fails_fast` (`lib.rs:801`), `mobile_ceiling_is_inclusive` (`:828`), `local_header_above_the_mobile_ceiling_is_refused_before_the_kdf` (`:867`), `backup_kdf_reports_the_header_cost` (`:844`) |
| 7 | Comprobación previa de RAM y mensaje | **Hecho** en `2bd56ce` | `session/KdfMemory.kt`, `VaultSession.kt:126-129,502-504` | `KdfMemoryTest` (6 tests, no ejecutados) |
| 8 | Presupuesto de KDBX y límites del XML | **Hecho** en `2bd56ce` (su aprobación, decisión nº 4, **sigue pendiente de aprobación humana**) | `core/src/import/kdbx.rs:36-51` (`MAX_ARGON2_BYTES` 512 MiB y `MAX_ARGON2_WORK` 3 GiB·pasada, alineados con el techo móvil: ajuste **sin commit**; `MAX_GROUP_DEPTH` 100, `MAX_XML_DEPTH` 256, `MAX_ENTRIES` 100 000) y `check_argon2_cost` (`:544`) | `argon2_budget_accepts_the_edge_and_refuses_above_it`, `deep_group_nesting_is_refused_before_it_costs_memory`, `nesting_and_entry_limits_accept_their_edge` (la memoria pasa de cuadrática a lineal; ver [ID-INT-01](internal-review.md#id-int-01)) |
| 9 | Protección contra *overlays* (A7) | **Parcial** | `3725741` (`OverlayProtection.kt`, `ProtectedAlertDialog` en `Components.kt:187-205`, manifiesto, `VerifyManifest` en `build.gradle.kts:174-176`) | `OverlayProtectionTest` unitario (6) e instrumentado (1, solo `MainActivity`); **faltan** las pruebas de las otras dos actividades y de los diálogos y el banner en las dos actividades de autorrelleno ([ID-INT-13](internal-review.md#id-int-13)) |
| 10 | Detección de root (A10) | **Hecho** | `3725741` (`RootSignals.kt`, `AndroidDeviceProbe.kt`, `<queries>`, `RootWarning` en `Components.kt:226`) | `RootDetectorTest` (10 tests, no ejecutados) |
| 11 | Ganchos `cfg(fuzzing)` y objetivos con *seeds* | **Hecho** | `2bd56ce`: `core/src/lib.rs`, `vault/mod.rs`, `backup/mod.rs`, `import/kdbx.rs` (módulo `fuzzing`), `fuzz/`: 6 objetivos nuevos (`vault_json`, `item_open`, `item_plaintext`, `backup_body`, `ffi_records`, `kdbx_container`) sobre los 5 de `8063fd1`: **11 en total** | `cargo +nightly fuzz build` (no ejecutado aquí); `strings` sobre `libop_ffi.so`: 0 símbolos del gancho ([`fuzzing.md`](fuzzing.md) §2). **Sin commit**: guardia `compile_error!` en `core/src/lib.rs:20-22` para `cfg(fuzzing)` sin `debug_assertions` (compilación `release`), que no sustituye a la comprobación sobre el `.so` ([ID-INT-21](internal-review.md#id-int-21), abierto) |
| 12 | Fuzzing nocturno | **Hecho** | `2bd56ce`: `.github/workflows/fuzz-nightly.yml` (11 objetivos, 10 min cada uno) | **Ninguna ejecución** en GitHub; falta el `workflow_dispatch` en verde |
| 13 | Tests de invariantes de `LoginMatcher` | **Hecho** en `2bd56ce` | `LoginMatcherTest.kt` (+232 líneas; 29 tests; `Random(20260630)`, `Random(7)`) | No ejecutados aquí |
| 14 | `cargo-deny` | **Hecho** en `2bd56ce` | `deny.toml`, `.github/workflows/ci.yml` (job `audit`), `.cargo/audit.toml` borrado | `cargo deny --locked check` → `advisories ok, bans ok, licenses ok, sources ok` (ejecutado) |
| 15 | Acciones por SHA, Dependabot, versiones fijas | **Hecho** en `2bd56ce` | `ci.yml`, `fuzz-nightly.yml`, `.github/dependabot.yml` | `grep -n "uses:" .github/workflows/*.yml`: todas con SHA de 40 caracteres y versión en comentario; `tool: cargo-deny@0.20.2`, `cargo-fuzz@0.13.2`; `cargo-ndk` 4.1.2, `cargo-cyclonedx` 0.5.9 |
| 16 | Verificación de dependencias de Gradle | **Hecho** en `2bd56ce` | `android/gradle/verification-metadata.xml` (478 componentes, 918 sumas, `aapt2` de Linux y macOS) | **No se ha ejecutado** una compilación con la verificación activa; falta probar que falla con una suma alterada |
| 17 | Job `release`: SBOM y atestación | **Hecho** en `2bd56ce` | `ci.yml` (job `release`), `build.gradle.kts` (plugin CycloneDX 3.5.1) | **Nunca ejecutado.** Falta `v0.2.0-rc1` y `gh attestation verify` |
| 18 | Documentación | **Parcial** | `docs/crypto-spec.md` §5 (techo de plataforma, `2bd56ce`); `android/README.md` (permisos y anti-tapjacking, `3725741`; `2bd56ce`); `docs/threat-model.md` (A7 y A10 implementados, nuevas filas A17 y A18 y residuos de secretos), `SECURITY.md` (`release/0.2`) y `fuzz/README.md` (30 s, 11 objetivos, presupuesto de KDBX): actualizados con este paquete de documentación (sin commit todavía) | **Pendiente**: `docs/crypto-spec.md` §10 (`SecretString`, residuos) |
| 19 | Versión 0.2.0, rama `release/0.2`, etiqueta firmada y paquete | **Pendiente** (no depende de la publicación en F-Droid, que está en pausa: la auditoría usa una pre-release de GitHub) | `Cargo.toml` sigue en `0.1.0` (`version.workspace`), `build.gradle.kts:29-30` en `versionCode = 1`, `versionName = "0.1.0"` | `git branch --list 'release/*'` vacío |

## 2. Medidas ejecutadas que se heredan del trabajo anterior

Existían antes de esta fase y siguen en el árbol. El commit es el primero que añade el código, según
`git log -S`.

| Medida | Estado | Commit | Lo verifica |
|---|---|---|---|
| `unsafe_code = "forbid"` en todo el espacio de trabajo | Hecho | `661c8fa` | `Cargo.toml:13`; `grep -rn unsafe core/src ffi/src cli/src` sin resultados |
| Límites de entrada (`MAX_INPUT` 32 MiB, `.1pux` acotado, gunzip acotado) | Hecho | `8d98c3b` (importadores) | `core/src/import/mod.rs:34,504-512`, `kdbx.rs:331-337` |
| `check_bounds` antes de la KDF | Hecho | `661c8fa` | `kdf.rs:48`; test `bounds_reject_costly_or_invalid_params` |
| Sin red y sin copia de seguridad del sistema; permisos exigidos en la compilación | Hecho | `e8a2c69` | `VerifyManifest` (`build.gradle.kts:163-180`) en cada `assemble` |
| `FLAG_SECURE` en las tres actividades | Hecho | `e8a2c69` (principal) | `grep -rn FLAG_SECURE android/app/src/main` (3 coincidencias) |
| `secure_delete` en SQLite | Hecho | `e8a2c69` | `ItemDatabase.kt:15-19` |
| Claves de Keystore (dispositivo y biométrica) con invalidación por alta biométrica | Hecho | `a46b8c9` (biometría) | `BiometricKeyStore.kt:40-56` |
| Espera exponencial tras fallos | Hecho | `5490f62` | `VaultSession.kt:477-481`; `UnlockBackoffTest` |
| Exclusión del autorrelleno del sistema en las ventanas propias | Hecho | `6383ec1` | `AutofillExclusion.kt:11-13` |
| Marca de «sensible» (API 33+) y borrado del portapapeles | Hecho (el borrado, **ineficaz en segundo plano: sin verificar**) | `e8a2c69` | `SensitiveClipboard.kt:21-39`, [ID-INT-14](internal-review.md#id-int-14) |
| Autobloqueo para todo el proceso | Hecho | `55f9054` | `VaultSession.kt:386-425`, `OpenPasswordApp.kt:69-83` |
| Token aleatorio para guardar logins | Hecho | `938761d` | `PendingSaves.kt` (caducidad perezosa: [ID-INT-17](internal-review.md#id-int-17)) |
| Fuzzing de 5 objetivos y `SECURITY.md` | Hecho | `8063fd1` | `fuzz/`, `SECURITY.md` |

## 3. Otras medidas de esta fase no listadas como pasos

| Medida | Estado | Dónde | Lo verifica |
|---|---|---|---|
| Lista de sufijos públicos en el autorrelleno (`LoginMatcher` con `PublicSuffix`) | **Hecho** en `2bd56ce` | `autofill/PublicSuffix.kt`, `LoginMatcher.kt:43-48`, `resources/public_suffix_list.dat` (338 012 B, versión `2026-10-28_13-15-55_UTC`) | `LoginMatcherTest` (29); recurso presente en `app-release.apk`; **sin verificar** la carga en dispositivo ([ID-INT-20](internal-review.md#id-int-20)) |
| `HIDE_OVERLAY_WINDOWS` exigido por `VerifyManifest`; `<queries>` con 6 paquetes; `QUERY_ALL_PACKAGES` prohibido | **Hecho** | `build.gradle.kts:174-177`, `AndroidManifest.xml:11-24` | La compilación falla si falta o sobra |
| `Vault::unlock` ya no pasa `E::KdfParams` a `Internal` | **Hecho** en `2bd56ce` | `ffi/src/lib.rs:69` | Test del techo (`:801`) |
| `README.md` con «Componentes de terceros» (EFF, sufijos públicos) | **Hecho** en `2bd56ce` | `README.md:57-58` | Sin mención de JNA (ver [`dependencies.md`](dependencies.md) §3.4) |

## 4. Pendiente

### 4.1 Defectos encontrados en esta revisión ([`internal-review.md`](internal-review.md))

| Prio. | ID | Medida | Estado |
|---|---|---|---|
| ~~P1~~ | ID-INT-16 | Aceptar `webDomain` solo de navegadores | **Hecho** en `2bd56ce` (`autofill/BrowserCheck.kt`, `StructureParser.targetFor`) y **completado sin commit**: la primera versión aceptaba cualquier app con un `intent-filter` `https`/`http`; ahora solo `KnownBrowsers.PACKAGES` o el navegador por defecto que atienda ambos esquemas (`BrowserCheck.kt:68-73`); host ASCII en `LoginMatcher.kt:67-76`; `PublicSuffix` falla cerrado ante `IOException`. `BrowserCheckTest` (13 `@Test`) y `LoginMatcherTest` (30), no ejecutados. Queda la hipótesis del `iframe` y la prueba en dispositivo |
| ~~P1~~ | ID-INT-26 | Que el destino del autorrelleno no viaje en extras del `PendingIntent` mutable | **Hecho, sin commit**: token aleatorio de 16 bytes, un solo uso, TTL 5 min (`AutofillRequestTokens.kt`); `AutofillAuthActivity.kt:87-98` borra los extras antiguos y falla cerrado; no se ofrece «recordar» en navegadores (`:102,124`). `AutofillRequestTokensTest` (7 `@Test`), no ejecutado. Sin prueba en dispositivo |
| ~~P1~~ | ID-INT-05 | Cerrar el `Vault` en los tres caminos de desbloqueo que fallan tras abrirlo | **Hecho** en `2bd56ce` (`VaultSession.discardOnFailure`); `FfiFailureHandlingTest` prueba la función auxiliar, no los tres caminos. **Sin commit**: `create()` también libera el `Vault` si falla la persistencia (`VaultSession.kt:94-101`) |
| ~~P1~~ | ID-INT-01 | Quitar la memoria cuadrática de `read_entries` y poner un tope de profundidad; semilla y test | **Hecho** en `2bd56ce` (`MAX_GROUP_DEPTH` 100, `MAX_XML_DEPTH` 256, `MAX_ENTRIES` 100 000); tests `deep_group_nesting_is_refused_before_it_costs_memory`, `nesting_and_entry_limits_accept_their_edge`; semillas en `fuzz/seeds/kdbx_xml/` |
| **P1** | ID-INT-14 | Probar el borrado del portapapeles en API 29, 33 y 36 y corregirlo | **Pendiente** (sin verificar en dispositivo) |
| ~~P1~~ | ID-INT-25 | Gancho `cfg(fuzzing)` para `kdbx::parse` (contraseña y KDF fijas) y corregir el README | **Hecho** en `2bd56ce` (`kdbx_fuzzing::{file, container}`, objetivo `kdbx_container`); README corregido (sin commit todavía) |
| ~~P2~~ | ID-INT-07 | Capturar `InternalException` en los 4 sitios y ampliar el test | **Hecho** en `2bd56ce` los 4 sitios; **pendiente** ampliar el test para detectar un sitio sin ningún `catch` |
| **P2** | ID-INT-02 | Decidir la política de KDF de KeePass frente al techo móvil (decisión humana nº 3-4) | **Pendiente**: el presupuesto de KDBX está hecho (ahora 512 MiB / 3 GiB·pasada, sin commit), pero `parse_import` no pasa por `MOBILE_MAXIMUM` ni por la comprobación de RAM |
| **P2** | ID-INT-08 | `lock()` coordinado con `mutex`, o `IllegalStateException` como `Locked` | **Pendiente** |
| **P2** | ID-INT-17 | Vaciar `PendingSaves` al bloquear y caducidad real | **Pendiente** |
| **P2** | ID-INT-21 | Sustituir la comprobación de símbolos del README por la del `.so` con control positivo | **Pendiente** |
| **P2** | ID-INT-06 | Decidir qué hacer con un elemento ilegible | **Pendiente** |
| **P2** | ID-INT-09 | Contar intentos en `verifyPassword` | **Pendiente** |
| **P2** | ID-INT-12 | Leer el fichero sin copias en claro intermedias | **Pendiente** |
| **P2** | ID-INT-13 | Banner en las actividades de autorrelleno y pruebas instrumentadas de actividades y diálogos | **Pendiente** |
| **P3** | ID-INT-03 | Documentar los residuos de los importadores | **Pendiente** |
| **P3** | ID-INT-18 | Recorrido iterativo con tope en `StructureParser` | **Pendiente** |
| **P3** | ID-INT-10, 11, 22, 23 | Robustez menor y limpieza | **Pendiente** |
| P3 | ID-INT-24 | Corregir `fuzz/README.md` (30 s y límites de KDBX) | **Hecho** (documentación, sin commit todavía) |

### 4.2 Pendiente del plan y de la congelación

| Prio. | Medida | Estado |
|---|---|---|
| ~~P1~~ | Confirmar lo que estaba «sin confirmar» | **Hecho** en `2bd56ce` (queda por confirmar esta actualización de documentación) |
| **P1** | Ejecutar una vez el job `release` con `v0.2.0-rc1` y `gh attestation verify` | **Pendiente** |
| **P1** | Ejecutar una vez `fuzz-nightly.yml` con `workflow_dispatch` | **Pendiente** |
| **P1** | Compilar con la verificación de Gradle activa en Linux y macOS; alterar una suma y ver el fallo | **Pendiente** |
| **P1** | Ejecutar `./gradlew :app:testDebugUnitTest` y las pruebas instrumentadas de `OverlayProtectionTest` y `VaultSessionTest` en un emulador | **Pendiente** (no ejecutados en esta revisión) |
| **P1** | Actualizar `docs/threat-model.md` según [`threat-model-review.md`](threat-model-review.md) §5 | **Hecho en parte**: A7 y A10 implementados, fila A17 y residuos de secretos; el resto de [`threat-model-review.md`](threat-model-review.md) §5 no se ha revisado aquí |
| **P1** | `docs/crypto-spec.md` §10 (`SecretString`, residuos) | **Pendiente** (`SECURITY.md` ya menciona `release/0.2`) |
| **P1** | Versión `0.2.0`, rama `release/0.2`, etiqueta firmada, `retention-days` o adjuntar a la release | **Pendiente** (pasos 19 y migración de ADR-AUD-01) |
| **P1** | Decisiones humanas de la lista final de [`decisions.md`](decisions.md): nº 1-10 (el nº 3 se marca ya «sigue pendiente de aprobación humana») | **Pendiente** |
| **P1** | Decisión sobre JNA y CC BY 3.0 US frente a GPL-3.0 | **Pendiente** ([`dependencies.md`](dependencies.md) §3.4) |
| **P2** | Quitar de `deny.toml` `Unlicense`, `Apache-2.0 WITH LLVM-exception` y `LGPL-2.1-or-later`; `publish = false` y `wildcards = "deny"` | **Pendiente** |
| ~~P2~~ | Borrar o ignorar `core/op-core.cdx.json` y `cli/opvault-cli.cdx.json` | **Hecho** en `2bd56ce` (`.gitignore:5`) |
| **P2** | Atestar o hashear el APK **firmado**; escribir el procedimiento de rotación y copia de la clave de firma | **Pendiente** |
| **P2** | Medición real de tiempos y ejecuciones del fuzzing; `backup_header` con `check_within(MOBILE_MAXIMUM)` | **Pendiente** (las semillas de grupos anidados ya existen) |
| **P2** | Análisis de avisos de Gradle en la CI | **Pendiente** |

## 5. Pospuesto o descartado (decisiones registradas)

| Medida | Estado | Dónde | Motivo |
|---|---|---|---|
| Sesión opaca (ADR-AUD-02, opción D): el texto en claro no sale de Rust | **Pospuesto** | [`decisions.md`](decisions.md) | Obliga a rediseñar la UI y el autorrelleno; no cabe en una versión congelada |
| Jazzer para el Kotlin del autorrelleno | **Pospuesto** | ADR-AUD-05 | `AssistStructure` y JUnit 5 ([`fuzzing.md`](fuzzing.md) §4) |
| ClusterFuzzLite | **Pospuesto** | ADR-AUD-05 | Un secreto más y un Dockerfile |
| OSS-Fuzz | **Descartado** | ADR-AUD-05 | Calendario de divulgación y base de usuarios |
| `cargo-vet` | **Descartado por ahora** | ADR-AUD-04 | Coste de mantenimiento para una sola persona |
| Firmas PGP en la verificación de Gradle | **Descartado** | ADR-AUD-04 | Mantener un llavero |
| Techo de KDF por ABI (32 bits 256 MiB / 3 / 4) | **Alternativa sin decidir** | ADR-AUD-07, decisión nº 3 | Comportamiento distinto entre dispositivos |
| Bloquear con root detectado | **Descartado** | ADR-AUD-06 | Falsos positivos (ROM sin root) y evasión (Magisk oculto) |
| KDF en otro proceso o `argon2` con asignación fallible | **No planificado** | Riesgos abiertos de [`decisions.md`](decisions.md) | Única forma de cerrar del todo el aborto por falta de memoria |
| Borrado criptográfico de elementos | **No planificado** | [`threat-model-review.md`](threat-model-review.md) §3.4 | Requiere rotar la clave de elemento y reescribir el baúl |

## 6. Cómo comprobar lo «hecho»

```sh
cargo test --workspace --locked                      # 95 pasan, 1 ignorada
cargo deny --locked check                            # advisories, bans, licenses, sources ok
cargo audit --deny warnings                          # sin vulnerabilidades
git status --short                                   # qué está sin confirmar
grep -n "uses:" .github/workflows/*.yml              # todo con SHA
grep -rn "catch (e: OpException)" android/app/src/main   # cada uno con InternalException al lado
strings -a android/app/build/rust/jniLibs/arm64-v8a/libop_ffi.so | grep -cE 'seal_backup|seal_item_part|TEST_VAULT_KEY'   # 0
unzip -l android/app/build/outputs/apk/release/app-release.apk | grep -E 'lib/|public_suffix'
```
