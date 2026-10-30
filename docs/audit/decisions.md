# Decisiones técnicas previas a la auditoría externa

Estado: **propuesta**, parcialmente implementada. `3725741` y `2bd56ce` implementan ADR-AUD-02 a 07 (estado
paso a paso en [`hardening.md`](hardening.md)); ADR-AUD-01 no (`release/0.2` y la etiqueta firmada no existen). Hay
trabajo adicional **sin commit** sobre `2bd56ce`. El texto de cada ADR describe la decisión tal como se
redactó, con la base `3e94bce`, y **no** se ha reescrito. Las que aparecen en la
[lista final](#decisiones-que-requieren-aprobación-humana) siguen necesitando aprobación humana.

Base inspeccionada al redactar las decisiones: `main` en `3e94bce` («CI: fuzzing con el target gnu del runner»).
Estado actual: `main` en `2bd56ce` más el trabajo sin commit. Versión de
espacio de trabajo `0.1.0` (`Cargo.toml`, `android/app/build.gradle.kts:28-29`).

Alcance de la auditoría: `op-core`, `op-ffi`, la app Android y el formato `.opvault` v1. La CLI
`opvault` (`cli/`) **queda fuera**. Las decisiones que tocan el perfil de Cargo compartido la
mencionan solo por su impacto.

## Resumen

| ID | Decisión | Recomendación | Coste | Reversible |
|---|---|---|---|---|
| ADR-AUD-01 | Congelación de `v0.2.0` | Rama `release/0.2`, etiqueta firmada, cambios solo para correcciones; primero en `main` y después *cherry-pick* (salvo embargo) | Bajo | Sí |
| ADR-AUD-02 | Secretos en UniFFI | Tipo propio `SecretString` (en Kotlin sigue siendo `String`) que se borra al liberarse en Rust; bytes con propietario explícito; documentar el residuo de la JVM y del `RustBuffer` | Medio | Sí |
| ADR-AUD-03 | Panics en FFI | `panic = "unwind"` en `[profile.release]`; UniFFI ya convierte el panic en `InternalException`; arreglar el envenenamiento del `Mutex`; toda llamada FFI desde una corrutina de UI captura `InternalException` y la sesión pasa a `Locked` ante un fallo interno | Bajo-medio | Sí |
| ADR-AUD-04 | Cadena de suministro | `cargo-deny` (sustituye a `cargo-audit`), `verification-metadata.xml` con SHA-256, Actions fijadas por SHA + Dependabot, SBOM CycloneDX y atestación de procedencia solo en la release. Sin `cargo-vet` | Medio | Sí |
| ADR-AUD-05 | Fuzzing | Solo `cargo-fuzz`: 5 objetivos nuevos con ganchos `cfg(fuzzing)` y una ejecución nocturna con corpus en caché. Ni Jazzer ni ClusterFuzzLite ni OSS-Fuzz por ahora | Medio | Sí |
| ADR-AUD-06 | Defensas A7 y A10 | A7: `filterTouchesWhenObscured` en la ventana + `setHideOverlayWindows` (API 31+) en las 3 actividades **y en sus diálogos**, y un aviso. A10: heurísticas locales detrás de una interfaz inyectable; **solo avisa** | Medio | Sí |
| ADR-AUD-07 | KDF y DoS | v1 **sí** acota (2 GiB / 16 / 16), pero ese techo deja un DoS en móvil. Se mantiene en el formato y se añade en `op-ffi` un techo de plataforma (512 MiB / 6 / 8) antes de cualquier KDF, con un error nuevo y una comprobación de RAM en Kotlin. El abort por falta de memoria se reduce, no se elimina | Bajo-medio | Sí |

---

## ADR-AUD-01 · Estrategia de congelación

### Contexto

- En `3e94bce`, la CI (`.github/workflows/ci.yml`) solo se lanza con `push` a `main` y con
  `pull_request`, pero `docs/fdroid/README.md` pide buscar la ejecución de la etiqueta
  (`gh run list --branch v0.1.0`). El disparador `tags: ['v*']` se añade en el commit que cierra
  `v0.1.0`; antes de él no existía. Sigue faltando `release/**`.
- El APK sin firmar que se publica es el de la CI (Linux), es reproducible y su artefacto **caduca a
  los 14 días** (`retention-days: 14`). Una auditoría dura más que eso.
- `SECURITY.md` solo da soporte a «la última versión publicada y `main`».

### Opciones

1. Auditar una etiqueta de `main` sin rama.
2. Rama `release/0.2` con correcciones solo en esa rama.
3. Rama `release/0.2`: correcciones primero en `main` y después *cherry-pick*, con una excepción
   para las vulnerabilidades bajo embargo.

### Decisión

Opción 3.

- **Rama** `release/0.2`, creada desde el commit de `main` que cierra el endurecimiento (todas las
  ADR de este documento implementadas y en verde).
- **Etiqueta** `v0.2.0` anotada y **firmada** (`git tag -s`) sobre la punta de `release/0.2`. Lo que
  se audita es el SHA de 40 caracteres, no el nombre de la etiqueta.
- **Paquete para el auditor**, adjunto a una *pre-release* de GitHub `v0.2.0` (no a un artefacto de la
  CI, que caduca):
  - el SHA del commit y la etiqueta firmada;
  - `git archive --format=tar.gz v0.2.0` con su SHA-256;
  - el APK sin firmar que compila la CI de esa etiqueta, su SHA-256 y el enlace a la ejecución;
  - las SBOM y la atestación de procedencia (ADR-AUD-04);
  - las instrucciones para reproducir el build: `rust-toolchain.toml` (1.99.1), NDK
    `30.0.16248370`, Gradle 9.8.2 con `distributionSha256Sum`, y `docs/fdroid/README.md`;
  - opcional: `cargo vendor` del espacio de trabajo, para que el auditor revise el código exacto de
    las dependencias sin conexión.
- **Política en `release/0.2` durante la auditoría**:

  | Se permite | No se permite |
  |---|---|
  | Correcciones de hallazgos del auditor | Funcionalidades nuevas |
  | Correcciones de avisos llegados por `SECURITY.md` | Refactorizaciones |
  | Subir una dependencia **solo** por un aviso RUSTSEC o GHSA que la afecte | Subir dependencias por rutina, Dependabot incluido |
  | Cambios de CI que no cambian los bytes del APK (fijar SHAs, disparadores) | Cambiar el *toolchain*, el NDK, AGP o Gradle |

  Cada cambio sale como `v0.2.N` (etiqueta firmada) y se entrega al auditor como `git diff v0.2.(N-1)..v0.2.N`.
- **Flujo de correcciones**: PR a `main`, revisión y fusión; después `git cherry-pick -x` a
  `release/0.2`. La `-x` deja la trazabilidad en el mensaje.
  - Excepción por embargo: una vulnerabilidad sin publicar se corrige en el **fork privado
    temporal** del GitHub Security Advisory. Se fusiona en `main` y en `release/0.2` el mismo día que
    se publica `v0.2.N`.
  - Excepción por divergencia: si `main` ya ha cambiado el fichero afectado, se corrige en
    `release/0.2` y se lleva después a `main` (*forward-port*), anotándolo en el PR.
- En `main` hay una **congelación blanda** de `core/src/crypto`, `core/src/vault`, `core/src/backup`
  y `ffi/src` hasta que termine la auditoría: se aceptan cambios, pero cada PR debe justificar por qué
  no espera. Así los *cherry-pick* siguen siendo triviales.

### Justificación

Corregir primero en `main` evita que las ramas diverjan y que se pierdan arreglos, que es el fallo
típico de los proyectos con una sola persona manteniéndolos. La rama da al auditor una base estable y
diferencias pequeñas y revisables. Firmar la etiqueta y adjuntar los artefactos a la release evita
depender de la retención de 14 días.

### Consecuencias y coste

- Dos ramas vivas durante la auditoría, más trabajo de *cherry-pick*.
- `SECURITY.md` debe añadir «`release/0.2` hasta el cierre de la auditoría» a las versiones con soporte.
- Hace falta una clave GPG o SSH de firma de etiquetas.

### Migración

1. Subir la versión a `0.2.0` en `Cargo.toml` (`[workspace.package]`) y en
   `android/app/build.gradle.kts` (`versionCode = 2`, `versionName = "0.2.0"`), con el *changelog* en
   `fastlane/metadata/android/*/changelogs/2.txt`.
2. En `ci.yml`, mantener `push.tags: ['v*']` (añadido en el commit que cierra `v0.1.0`) y añadir
   `push.branches: [main, 'release/**']`.
3. Ampliar `retention-days` o, mejor, adjuntar el APK a la release (paso de ADR-AUD-04).
4. Crear la rama y la etiqueta firmada, montar la *pre-release* y actualizar `SECURITY.md`.

---

## ADR-AUD-02 · Secretos al cruzar UniFFI

### Contexto

Estado actual (`ffi/src/lib.rs`):

| Dato | Tipo FFI | Dirección | Borrado hoy |
|---|---|---|---|
| Contraseña maestra | `String` (`Vault::create`, `Vault::unlock`, `open_backup`, `parse_import`) | Kotlin→Rust | No: el `String` de Rust se libera sin borrar. Solo la copia NFKD se borra (`core/src/crypto/kdf.rs`, `Zeroizing`) |
| Clave secreta (SK) | `String` en las dos direcciones (`generate_secret_key`, `normalize_secret_key`) | ↔ | No en la FFI. `SecretKey` sí se borra en el núcleo |
| Clave del baúl | `Vec<u8>` (`vault_key_bytes`, `unlock_with_vault_key`) | ↔ | Kotlin hace `fill(0)` (`VaultSession.kt:220-224`, `262-269`). En Rust, el `[u8; 32]` intermedio de `try_into` no se borra |
| Valores de campo, notas, historial | `FieldRecord.value`, `ItemDetailsRecord.notes` y `PasswordChangeRecord.value`, todos `String` | ↔ | En el núcleo, `Field` y los detalles derivan `ZeroizeOnDrop` (`core/src/vault/item.rs`). Sus copias `String` en los `Record` no se borran |
| Semilla TOTP | `totp_code(input: String)` | Kotlin→Rust | No |
| Fichero de clave de KeePass | `Option<Vec<u8>>` | Kotlin→Rust | Kotlin hace `fill(0)` (`ExternalImport.kt:188, 198`). Rust no lo borra |
| Ficheros importados o de respaldo | `Vec<u8>` | Kotlin→Rust | Kotlin hace `fill(0)` en la importación (`ExternalImport.kt:54, 61`) |

Límites que no se pueden evitar:

- Compose y la JVM trabajan con `String` inmutables, y los `TextField` de Compose ya crean `String`.
- UniFFI copia los datos de salida a un `RustBuffer`, que libera después sin borrar.

### Opciones

- **A. Documentar solamente.** No cuesta nada y no mejora nada.
- **B. Pasar los secretos a `ByteArray` en la API** (`Vec<u8>`). Kotlin podría borrar su copia, pero la
  contraseña ya es un `String` de Compose antes de llegar ahí. Rompe mucha interfaz y gana poco.
- **C. Un tipo propio de UniFFI `SecretString`** (en Rust, `Zeroizing<String>` con `Debug` oculto; en
  Kotlin, `String`). Rust borra todas sus copias de entrada sin depender de cada función, y la API de
  Kotlin no cambia.
- **D. Sesión opaca**: el texto en claro no sale de Rust y Kotlin pide un campo concreto para
  mostrarlo o copiarlo. Es la mejor reducción, pero obliga a rediseñar la UI y el autorrelleno.

### Decisión

**C**, más un contrato de propiedad explícito. **D** se deja para después de la auditoría, por
ejemplo con la llegada de iOS.

Contrato (va como comentario de módulo en `ffi/src/lib.rs` y en `docs/crypto-spec.md` §10):

1. **Tipo.** En `ffi/src/lib.rs` (o en un `ffi/src/secret.rs` nuevo) se define
   `pub struct SecretString(Zeroizing<String>)`, registrado con `uniffi::custom_type!(SecretString, String, { lower, try_lift })`,
   con `Debug` que imprime `<redacted>`, más `From<String>`, `From<&str>` y `fn expose(&self) -> &str`.
2. **Dónde se usa**: `password` en `Vault::create`, `Vault::unlock` y `open_backup`; `password` en
   `parse_import` (`Option<SecretString>`); `secret_key` en todas las funciones, entrada y salida;
   `FieldRecord.value`, `ItemDetailsRecord.notes`, `PasswordChangeRecord.value`, y la entrada de
   `totp_code`. **No** se usa en `ItemOverviewRecord`: título, URLs y etiquetas son metadatos que
   la lista mantiene siempre en memoria. El modelo de amenazas ya los clasifica aparte (sensibilidad
   «Alta», no «Crítica»).
3. **Bytes.** `vault_key`, `key_file` y los ficheros siguen siendo `Vec<u8>`. En Rust, el `Vec`
   recibido se envuelve en `Zeroizing` en cuanto entra; en `unlock_with_vault_key`, el array de 32
   bytes se crea dentro de un `Zeroizing<[u8; 32]>`.
4. **Propiedad.** Quien crea el buffer lo borra.
   - Un `ByteArray` que Kotlin pasa a Rust sigue siendo de Kotlin, y Kotlin lo borra con `fill(0)` en
     un `finally`.
   - Lo que Rust recibe es suyo y lo borra al soltarlo (`SecretString` o `Zeroizing`).
   - Un `ByteArray` que Rust devuelve (`vault_key_bytes`) pasa a ser de Kotlin, que debe borrarlo.
5. **Vida útil.** La vida de los secretos en claro en Kotlin se limita a la sesión desbloqueada:
   - al pasar a `SessionState.Locked`, `VaultSession` suelta las referencias a los
     `ItemDetailsRecord` descifrados;
   - la SK solo se lee de `VaultStorage` en el momento de usarla.

   Es un objetivo de *best effort* que se revisa, no una garantía.
6. **Residuos aceptados**, que se documentan en `docs/threat-model.md` («Riesgos residuales»):
   - los `String` de JVM y Compose;
   - el `RustBuffer` de salida, que UniFFI libera sin borrar;
   - en la salida, la copia `String` de Rust que se entrega a UniFFI.

   Sí queda borrado lo que entra: en el sentido Kotlin→Rust, UniFFI construye el `String` a partir del
   propio buffer, sin copiarlo, y `SecretString` lo borra.

### Justificación

C cierra lo único que controlamos de verdad, las copias del lado Rust. Lo hace de forma estructural,
porque una función nueva no puede olvidar el borrado si el tipo lo hace por ella, y sin tocar la API
de Kotlin. B tiene mucho coste para muy poca ganancia, porque Compose ya produce `String`. D es
correcta pero no cabe en una versión congelada.

### Consecuencias y coste

- La interfaz Kotlin no cambia: los bindings generados siguen exponiendo `String`.
- Hay que cambiar los tests de Rust de `ffi/src/lib.rs`. Construcciones como `value: "2958".into()`
  siguen compilando, pero aserciones como `assert_eq!(…value, "2958")` deben usar `.expose()` o
  `PartialEq<&str>`.
- Tests nuevos: `Debug` oculta el valor; `zeroize()` explícito deja el texto vacío (sin `unsafe`, se
  comprueba el contenido tras `Zeroize::zeroize`).
- **Riesgo técnico** (verificar en el primer paso): que `uniffi::custom_type!` de la 0.32 funcione
  dentro de `Record` con `#[uniffi(default = …)]` y en `Option<…>`. Si no funciona, la alternativa
  es `Zeroizing::new(arg)` como primera línea de cada función exportada, más una prueba de revisión
  (`grep`) en la CI.

### Migración

1. Prueba aislada (*spike*): `SecretString` con `custom_type!`; regenerar bindings y comprobar que
   el `op_ffi.kt` generado (en `build/`, no versionado) no cambia de tipos.
2. Sustituir los tipos en `ffi/src/lib.rs` y ajustar los tests.
3. Revisar en Kotlin el borrado de `vaultKeyBytes()` y `keyFile`, y que se sueltan los detalles al bloquear.
4. Actualizar `docs/crypto-spec.md` §10 y `docs/threat-model.md` (riesgos residuales).

---

## ADR-AUD-03 · Panics en la frontera FFI

### Contexto

- `[profile.release] panic = "abort"` en `Cargo.toml`, y la app siempre compila `op-ffi` en release
  (`CargoNdkBuild`, `android/app/build.gradle.kts`).
- Los bindings que genera UniFFI (se generan en `build/` y no se versionan) ya esperan panics: el
  código de Kotlin traduce el estado de pánico a `InternalException`, que extiende `kotlin.Exception`.
  Con `abort`, ese camino nunca se ejecuta: un panic mata el proceso, autorrelleno incluido
  (`OpAutofillService` vive en el mismo proceso).
- Superficie con datos no confiables y `expect`/indexación en código de producción:
  `core/src/backup/mod.rs:92`, `core/src/vault/padding.rs:26`, `core/src/crypto/stream.rs:52`
  (estos tres están protegidos por comprobaciones de longitud previas), y los importadores
  (`core/src/import/*`).
- **No hay tests de pánico** (`#[should_panic]` o `catch_unwind`: cero apariciones en `core`, `ffi` y `cli`).
- Una **falta de memoria** (`handle_alloc_error`) aborta **sea cual sea** la estrategia de pánico.
  Cambiar a `unwind` no protege de la KDF (ver ADR-AUD-07).
- `Vault::lock` hace `if let Ok(mut guard) = self.inner.lock()` (`ffi/src/lib.rs:380-384`). Con
  `unwind`, un panic dentro de `Vault::with` **envenena** el `Mutex`, y después **`lock()` no borra la
  clave**. Hoy no pasa porque `abort` no deja sobrevivir a nadie.

### Opciones

1. Mantener `abort`: un fichero malicioso que provoque un panic deja la app sin servicio (DoS).
2. `panic = "unwind"` en `[profile.release]`, sin `catch_unwind` propio: el de UniFFI ya basta.
3. Mixta: un perfil `release-ffi` con `inherits = "release"` y `panic = "unwind"` solo para la app.

### Decisión

Opción 2.

- Poner `panic = "unwind"` en `[profile.release]`. La CLI hereda el cambio, pero está fuera de alcance
  y deshacer la pila (*unwind*) en una CLI es inocuo.
- No se escribe `catch_unwind` a mano: UniFFI ya envuelve cada llamada en su `rust_call`.
- `Vault::lock` y `Vault::is_locked` recuperan el guard envenenado con
  `unwrap_or_else(PoisonError::into_inner)`. El bloqueo **siempre** borra la clave.
- `Vault::with` también trata el envenenamiento: devuelve `OpError::Internal` y **borra** la clave
  (vacía el `Option`), para no seguir usando un estado a medias.
- **Criterio verificable en Kotlin**: toda llamada FFI desde una corrutina de UI (o de un servicio)
  debe capturar `InternalException`, o `Exception`/`Throwable` de forma deliberada. No se mantiene una
  lista ad hoc de «flujos con datos no confiables»: cualquier llamada puede sufrir un panic, y un
  `catch (e: OpException)` a secas deja pasar `InternalException` como excepción no capturada en la
  corrutina, que cierra la app. Se comprueba con `grep` de `catch (e: OpException)` en
  `android/app/src/main`: cada resultado debe tener a su lado un `catch` de `InternalException` o
  `Exception`.
- **Sitios que ya lo cubren** (porque capturan `Exception` o usan `runCatching`; no hay que cambiarlos):
  - `RestoreScreen.kt:78` (`catch (_: Exception)`);
  - `ExternalImport.kt:48` y `:59` (`runCatching` alrededor de `parseImport`, con
    `importErrorMessage(Throwable)`);
  - `ItemEditorScreen.kt:325` e `ItemDetailScreen.kt:236` (`runCatching` sobre `totpCode`);
  - `OpAutofillService.kt:41` (`runCatching` alrededor de `session.details(...)`);
  - `SettingsScreen.kt:148-150` (exportar copia, `catch (_: Exception)`).
- **Sitios que hay que corregir** (solo capturan `OpException`):
  - `SettingsScreen.kt:405-412`: importar una copia desde Ajustes. Es el único flujo de
    restaurar/importar realmente sin cubrir;
  - `VaultSession.kt:108-112`: desbloqueo con contraseña (y `:266`, desbloqueo con la clave del baúl
    desde `BiometricFlows`);
  - `SaveLoginActivity.kt:191`: guardar un login desde el autorrelleno;
  - `ItemEditorScreen.kt:133`: guardar en el editor de elementos;
  - `BiometricFlows.kt:31`: activar el desbloqueo biométrico;
  - `OnboardingScreen.kt:246`: crear el baúl;
  - `ExternalImport.kt:138`: importar elementos externos al baúl;
  - `AutoBackup.kt:102`: copia automática (el `catch (e: OpException)` tras `exportBackup`).
- **Estado de la sesión tras un fallo interno.** Tras un envenenamiento del `Mutex`, `Vault::with`
  borra la clave en Rust, pero Kotlin seguiría creyendo que `SessionState` es `Unlocked`: todas las
  llamadas posteriores devolverían `OpException.Locked` con la UI abierta y sin baúl. Por eso
  `VaultSession` debe pasar a `Locked` y vaciar `entries` al recibir `InternalException` o un `Locked`
  inesperado (es decir, uno que llega con `_state` en `Unlocked`). Se hace en un único punto, el
  envoltorio `withVault` (`VaultSession.kt:412`), y no en cada pantalla.
- **Mensajes.** «Fichero no válido» solo se usa en los flujos de ficheros (restaurar, importar). En el
  resto (desbloqueo, editor, autorrelleno, biometría, alta del baúl) se muestra un error genérico
  («Ha ocurrido un error interno. Vuelve a desbloquear el baúl»). El mensaje del panic **no** se
  muestra ni se registra en el log.

### Justificación

La 3 da el mismo resultado para la app con más piezas: un perfil nuevo, `cargo ndk --profile` y una
ruta de salida distinta, con riesgo para el build reproducible. La 1 deja un DoS evidente que el
auditor marcará. El coste de `unwind` es pequeño, porque los objetivos de Android ya emiten tablas de
deshacer por defecto.

### Consecuencias y coste

- Tamaño: hay que **medirlo**. Hoy `libop_ffi.so` ocupa 1,40 MB en arm64 y 1,09 MB en armv7. Se
  espera un aumento de un dígito porcentual por las *landing pads*. Si pasa del 15 %, se vuelve a
  valorar la opción 3.
- El SHA-256 del APK cambia. No importa, porque es una versión nueva.
- Tests nuevos en `ffi/src/lib.rs`:
  - `lock_wipes_key_after_poisoned_mutex`: envenena el `Mutex` con `std::panic::catch_unwind` sobre un
    hilo que hace panic con el guard tomado. Los tests usan siempre `unwind`.
  - `with_after_poison_returns_internal_and_locks`.
- Dejar un `// panic = "unwind": see docs/audit/decisions.md ADR-AUD-03` en `Cargo.toml`.

### Migración

1. Arreglar `lock`, `is_locked` y `with`, con sus tests. Va **antes** del cambio de perfil.
2. Cambiar el perfil y medir el tamaño de las tres ABI.
3. Capturas de `InternalException` en los sitios de la lista anterior, y paso de `VaultSession` a
   `Locked` (con `entries` vacío) al recibir `InternalException` o un `Locked` inesperado. Un test
   unitario de `VaultSession` con un `Vault` falso que lance `InternalException`.
4. Comprobación manual en el emulador con un `.so` de depuración que incluya una función de pánico de
   prueba, detrás de una *feature* que nunca llega a release. Es opcional.

---

## ADR-AUD-04 · Cadena de suministro

### Contexto

- Rust: `cargo audit --deny warnings`, con ignorados en `.cargo/audit.toml` (`RUSTSEC-2026-0374`,
  `basic-toml`, solo en el *bindgen*). `Cargo.lock` versionado; `zip` fijado (`=9.0.3`).
- Gradle: el *wrapper* ya lleva `distributionSha256Sum`, pero **no** hay `verification-metadata.xml`.
  Los repositorios (`google()` y `mavenCentral()`) están filtrados por contenido en `pluginManagement`.
- Actions fijadas **por etiqueta** (`actions/checkout@v7`, `taiki-e/install-action@v2`,
  `dtolnay/rust-toolchain@stable`…). En `3e94bce`, `cargo install cargo-ndk --locked` instala sin
  versión fija; el commit que cierra `v0.1.0` la fija a `--version 4.1.2`.

### Opciones y valoración

| Herramienta | Qué aporta a la auditoría | Mantenimiento | Decisión |
|---|---|---|---|
| `cargo-deny` | Avisos (lo mismo que `cargo-audit`), **licencias** compatibles con GPL-3.0 (requisito de F-Droid), **orígenes** (solo crates.io) y duplicados | Bajo: un `deny.toml` | **Sí**, sustituye a `cargo-audit` |
| `cargo-vet` | Prueba de revisión humana de cada versión de cada crate | Alto: auditar o importar en cada subida de versión; demasiado para una persona | **No** por ahora; reconsiderar después de la auditoría |
| `verification-metadata.xml` (SHA-256) | Integridad de **todos** los artefactos Maven, plugins incluidos. Es la superficie de dependencias más grande del proyecto | Medio: regenerar al subir versiones; hay artefactos por plataforma (`aapt2` de Linux y de macOS) | **Sí**, solo sumas de comprobación; sin firmas PGP, que exigen mantener un llavero |
| Actions por SHA | Evita que una etiqueta movida ejecute código ajeno en la CI que produce el APK publicado | Bajo, con Dependabot (`github-actions`) | **Sí** |
| SBOM CycloneDX | Inventario exacto de lo que se distribuye: Rust de `op-ffi` y Gradle `releaseRuntimeClasspath` | Bajo si se genera solo en la release | **Sí**, adjunta a la release |
| Atestación de procedencia (`actions/attest-build-provenance`) | Relaciona APK, commit y workflow (SLSA); complementa el build reproducible | Bajo: un paso y dos permisos en un solo job | **Sí**, solo con etiquetas |

### Decisión

El conjunto mínimo y suficiente son las cinco filas marcadas con «Sí»:

1. **`deny.toml`** en la raíz:
   - `[advisories]`: el aviso ignorado se lleva con su motivo;
   - `[licenses]`: lista explícita de licencias admitidas, generada con `cargo deny list` y revisada;
     cualquier licencia nueva exige aprobación;
   - `[sources]`: `unknown-registry = "deny"` y `unknown-git = "deny"`;
   - `[bans]`: `multiple-versions = "warn"`.

   En `ci.yml`, el job `audit` pasa a ser `cargo deny --locked check`. Se borra `.cargo/audit.toml`.
2. **`android/gradle/verification-metadata.xml`** generado con
   `./gradlew --write-verification-metadata sha256 :app:assembleDebug :app:assembleRelease :app:testDebugUnitTest :app:lint`
   **en Linux y en macOS**, uniendo ambos ficheros.
3. **SHAs en `ci.yml`**, con la versión en un comentario (`uses: actions/checkout@<sha> # v7.x.y`).
   Además:
   - un `.github/dependabot.yml` para `github-actions`, semanal;
   - `cargo install cargo-ndk --locked --version 4.1.2` (ya fijado en el commit que cierra `v0.1.0`);
   - versiones fijas en `taiki-e/install-action` (`tool: cargo-deny@x.y.z`, `cargo-fuzz@x.y.z`).
4. **Job `release`** en `ci.yml`, solo con `tags: v*`. Necesita `id-token: write` y
   `attestations: write` **solo en ese job**. Hace esto:
   - compila el APK;
   - genera `cargo cyclonedx` para `op-ffi` y la SBOM de Gradle (plugin `org.cyclonedx.bom`, con
     versión fija y cubierto por la verificación de dependencias);
   - publica la atestación del APK sin firmar y de las SBOM;
   - adjunta todo a la release.

### Consecuencias y coste

- Cada subida de una dependencia de Gradle obliga a regenerar la metadata. Se documenta en
  `android/README.md`.
- El plugin de CycloneDX añade una dependencia de build, solo de build y verificada.
- La atestación usa Sigstore público. Es aceptable en un proyecto de código abierto.

### Migración

Por este orden, y cada paso en verde antes del siguiente: `deny.toml` y el job; los SHAs y
Dependabot; la metadata de Gradle; el job `release`.

---

## ADR-AUD-05 · Infraestructura de fuzzing

### Contexto

- Hay 5 objetivos en `fuzz/fuzz_targets/`: `import`, `kdbx_xml`, `key_file`, `backup_header` y `totp`.
  La CI hace una pasada de 60 s por objetivo (`ci.yml`, job `fuzz`) y el corpus no persiste.
- Lo que no se fuzzea hoy:
  - lo que hay **después** del AEAD: `padding::unpad`, el JSON de `ItemDetails` e `ItemOverview`, y
    el `Body` de la copia;
  - el `serde` de `VaultHeader` y `EncryptedItem` (`encoding::hex_bytes`);
  - la capa `op-ffi`: `parse_header` y `EncryptedItemRecord::try_from`.

  Con entradas aleatorias el AEAD casi nunca deja pasar nada, así que esos analizadores solo se
  alcanzan cifrando la entrada del fuzzer con una clave fija.
- `Cargo.toml` ya declara `check-cfg = ["cfg(fuzzing)"]`.
- No hay servidores propios. Los minutos de Actions de los repositorios públicos son gratuitos.

### Opciones

1. Solo ampliar `cargo-fuzz` y añadir una ejecución nocturna.
2. Además, Jazzer para el Kotlin del autorrelleno.
3. Además, ClusterFuzzLite.
4. OSS-Fuzz.

### Decisión

Opción 1.

Objetivos nuevos, en `fuzz/fuzz_targets/` y registrados en `fuzz/Cargo.toml`:

| Objetivo | Entrada | Camino |
|---|---|---|
| `vault_json` | Bytes | `serde_json::from_slice::<VaultHeader>` y `::<EncryptedItem>` (cubre `hex_bytes`) |
| `item_open` | `EncryptedItem` arbitrario (JSON) | `UnlockedVault::unlock_with_vault_key(cabecera fija, clave fija)` → `decrypt_overview` y `decrypt_details`. Cubre `unwrap_key`, longitudes y AAD |
| `item_plaintext` | Bytes como JSON en claro | Gancho `fuzzing::seal_item_part` (clave fija) → `decrypt_details` y `decrypt_overview`. Cubre `padding::unpad` y el `serde` de los elementos |
| `backup_body` | Bytes como cuerpo en claro | Gancho `fuzzing::seal_backup` (STREAM con clave fija) → `backup::fuzzing::open_with_vault`. Cubre `stream::decrypt` y el JSON del `Body`, **sin KDF** |
| `ffi_records` | Bytes divididos en cabecera y registro | `op_ffi::Vault::unlock_with_vault_key(header_json, [7;32])` → `decrypt_*` con `EncryptedItemRecord` arbitrario. `fuzz/Cargo.toml` pasa a depender de `op-ffi` |

Ganchos:

- Un módulo `#[cfg(fuzzing)] pub mod fuzzing` en `core/src/lib.rs`, que reexporta envoltorios finos
  de `crypto::seal`, `stream::encrypt` y de un `backup::decrypt_body` que recibe un `&UnlockedVault`.
- Nunca se compila fuera de `cargo fuzz`. El auditor lo verá, y se documenta en `fuzz/README.md`.

CI:

- El job `fuzz` de PR y *push* baja a 30 s por objetivo (10 objetivos, unos 5 min).
- Un workflow nuevo `.github/workflows/fuzz-nightly.yml` (`schedule`, a diario) hace 10 min por
  objetivo:
  - corpus en `actions/cache` por objetivo, minimizado con `cargo fuzz cmin` cada semana;
  - si falla, sube los artefactos y el job queda en rojo.

**Jazzer: no por ahora.**

- `StructureParser` depende de `AssistStructure`, así que Jazzer no lo alcanza sin Robolectric.
- `LoginMatcher` (A12) y `FieldClassifier` son funciones puras con tests JUnit 4. Para ellos bastan
  **tests de invariantes con un generador determinista**, sin dependencias nuevas, en
  `LoginMatcherTest.kt`. Ejemplos de invariantes:
  - un host con un dominio registrable distinto nunca coincide;
  - `hostOf` nunca lanza excepciones;
  - una URL `androidapp://` nunca coincide con una web.
- Jazzer obligaría a pasar a JUnit 5 y a meter más dependencias en la metadata de Gradle.

**ClusterFuzzLite: pospuesto.** Para persistir el corpus necesita un repositorio o rama con un token
(un secreto más) y un Dockerfile. El trabajo nocturno ofrece lo esencial con las mismas herramientas
que se usan en local.

**OSS-Fuzz: descartado.** Exige base de usuarios y aceptación, y su calendario de divulgación no
encaja con un proyecto que todavía no ha pasado la auditoría.

### Consecuencias y coste

Cinco ficheros de objetivo, un módulo `cfg(fuzzing)`, *seeds* nuevas en `fuzz/seeds/<objetivo>/`
(generadas con los vectores de `core/tests/vectors/op-v1.json`) y un workflow.

Criterios para reconsiderar:

- Jazzer, si `StructureParser` se refactoriza a una abstracción de nodos sin Android.
- ClusterFuzzLite, si el corpus en caché se pierde a menudo (la caché caduca a los 7 días sin uso).

---

## ADR-AUD-06 · Defensas A7 y A10

### Contexto

- `docs/threat-model.md` afirma `filterTouchesWhenObscured` (A7) y «aviso si se detecta root» (A10).
  Ninguno de los dos existe: un `grep` de `filterTouches|HideOverlay|Build.TAGS` en `android/app/src`
  no devuelve nada.
- Hay **tres** actividades que muestran secretos o piden la contraseña maestra. Las tres ya ponen
  `FLAG_SECURE`:
  - `MainActivity.kt:23`;
  - `autofill/AutofillAuthActivity.kt:72`;
  - `autofill/SaveLoginActivity.kt:69`.
- Patrón existente que se debe imitar: `security/AutofillExclusion.kt` (`excludeFromAutofill(activity)`,
  que se llama después de `setContent`).
- `minSdk = 28`, `targetSdk = 36`. Los tests unitarios son JUnit 4 sin Robolectric.
- `VerifyManifest` (`android/app/build.gradle.kts:163-175`) ya hace fallar el build por permisos prohibidos.

### A7 · Anti-tapjacking

Decisión: proteger **por ventana**, en las tres actividades, en lugar de pantalla a pantalla. Todas
las pantallas de esas actividades piden la contraseña, revelan o copian secretos, o confirman un
guardado o un relleno. Proteger por pantalla dejaría huecos y añadiría complejidad.

Límite que hay que cubrir de forma explícita: los `AlertDialog` de Compose (hay en
`SettingsScreen.kt`, `ExternalImport.kt` y `VaultListScreen.kt`) son **ventanas aparte**, con su
propio *decor view*. `decorView.filterTouchesWhenObscured` ni `setHideOverlayWindows` de la ventana de
la actividad los cubren, y varios piden la contraseña maestra o confirman borrados e importaciones.
Por tanto, «todas las pantallas» solo es cierto si se protegen también los diálogos (ver más abajo).

- **Fichero nuevo** `android/app/src/main/kotlin/io/github/rldona/openpassword/security/OverlayProtection.kt`:
  - `fun protectFromOverlays(activity: Activity)`:
    - pone `activity.window.decorView.filterTouchesWhenObscured = true`. Compose recibe los toques a
      través del `View` raíz, así que basta con el *decor view*;
    - si `SDK_INT >= 31`, llama a `activity.window.setHideOverlayWindows(true)`.
  - `@Composable fun ProtectDialogWindow()`: se coloca dentro del contenido de cada diálogo, obtiene
    su ventana con `(LocalView.current.parent as? DialogWindowProvider)?.window` y le aplica lo mismo
    (`decorView.filterTouchesWhenObscured = true` y, con `SDK_INT >= 31`, `setHideOverlayWindows(true)`).
    Alternativa equivalente: un contenedor propio `ProtectedAlertDialog` en `ui/Components.kt` que lo
    haga una sola vez y sustituya a todos los `AlertDialog` de la app; así un diálogo nuevo no se
    puede olvidar. Se prefiere esta, con una comprobación por `grep` en la CI de que no queda ningún
    `AlertDialog(` fuera de `Components.kt`.
  - Función pura `fun obscuredTouch(flags: Int): Obscured` con los valores `NONE`, `FULL`
    (`MotionEvent.FLAG_WINDOW_IS_OBSCURED`) y `PARTIAL` (`FLAG_WINDOW_IS_PARTIALLY_OBSCURED`, API 29+).
    Recibe las constantes como parámetro, para poder probarla en la JVM.
  - `object OverlayWarning { val detected: StateFlow<Boolean> }`, que se pone a `true` en cuanto llega
    un toque `FULL` o `PARTIAL`.
- **Actividades**: cada una llama a `protectFromOverlays(this)` junto a `excludeFromAutofill(this)`, y
  sobrescribe `dispatchTouchEvent` para avisar a `OverlayWarning` antes de llamar a `super`.
  - Un toque `FULL` ya lo descarta el sistema por el filtro, así que no se cambia el flujo.
  - Un toque `PARTIAL` **no** se descarta: un globo de chat en otra zona de la pantalla es normal.
- **Respuesta**: un aviso no bloqueante en `ui/Components.kt` (`OverlayWarningBanner`) que se muestra
  arriba en `AppRoot` y en las dos actividades de autorrelleno: «Otra app está mostrando algo encima
  de OpenPassword. Por seguridad se ignoran los toques tapados». No se bloquea el baúl.
- **Manifiesto**: `<uses-permission android:name="android.permission.HIDE_OVERLAY_WINDOWS" />`.
  Es un permiso normal (se concede al instalar) y la API lo exige. Hoy `android/README.md` (línea 39)
  afirma que los únicos permisos del manifiesto son `USE_BIOMETRIC` y `CAMERA`: esa frase **hay que
  actualizarla** en la migración. `VerifyManifest` pasa a
  **exigirlo** y a comprobar que se sigue cumpliendo `FLAG_SECURE`, aunque esto último no se puede ver
  en el manifiesto y lo cubre un test instrumentado.
- **Falsos positivos aceptados**: con API 28-30, las apps que oscurecen la pantalla (filtros de luz
  azul) dejan la app sin respuesta en las zonas que cubren. El aviso explica por qué. Los
  *overlays* de accesibilidad no están afectados.

### A10 · Detección de root sin red

Decisión: **solo se avisa, nunca se bloquea.** El público de F-Droid usa a menudo ROM alternativas
(LineageOS: compilaciones `userdebug`, `test-keys`) sin root. Bloquear expulsaría a usuarios
legítimos y, además, no sirve contra un root que se oculta (Magisk). El modelo de amenazas ya deja A10
fuera de alcance, así que el aviso es informativo.

- **Fichero nuevo** `security/RootSignals.kt`, en Kotlin puro y sin Android:
  - `interface DeviceProbe { fun fileExists(path: String): Boolean; fun packageInstalled(name: String): Boolean; val buildTags: String?; val buildType: String }`;
  - `enum class RootSignal { SU_BINARY, ROOT_MANAGER_APP, TEST_KEYS, DEBUG_BUILD }`;
  - `object RootDetector { fun evaluate(probe: DeviceProbe): Set<RootSignal> }`;
  - las listas de rutas y paquetes como constantes del objeto, para que el test las recorra.
- **Heurísticas**:
  - rutas de `su`: `/system/bin/su`, `/system/xbin/su`, `/sbin/su`, `/su/bin/su`,
    `/data/local/xbin/su`, `/data/local/bin/su`, `/system/sd/xbin/su`, `/vendor/bin/su`, y también
    `/data/adb/magisk` y `/data/adb/ksu`;
  - paquetes: `com.topjohnwu.magisk`, `me.weishu.kernelsu`, `eu.chainfire.supersu`,
    `com.koushikdutta.superuser`, `com.noshufou.android.su`, `com.kingroot.kinguser`;
  - `Build.TAGS` que contiene `test-keys`;
  - `Build.TYPE` igual a `userdebug` o `eng`.
- **Lo que no se usa, a propósito**:
  - `android.os.SystemProperties` por reflexión (interfaces fuera del SDK, restringidas desde la API 28);
  - `Runtime.exec("su")` o `getprop` (lanzar procesos es una señal sospechosa para el auditor);
  - Play Integrity o SafetyNet (red y Google);
  - la atestación de claves (`RootOfTrust.verifiedBootState`), que se puede hacer sin red pero exige
    analizar ASN.1 y queda para el futuro.
- **Visibilidad de paquetes (API 30+)**: un bloque `<queries>` con los paquetes concretos en
  `AndroidManifest.xml`. **No** se usa `QUERY_ALL_PACKAGES`.
- **Implementación Android** `security/AndroidDeviceProbe.kt`: usa `File.exists`,
  `PackageManager.getPackageInfo` y `Build`.
- **Cuándo se evalúa**: una vez en `OpenPasswordApp.onCreate`, en `Dispatchers.IO`, y se expone como
  `val rootSignals: StateFlow<Set<RootSignal>>`.
- **Aviso en la UI**:
  - una tarjeta descartable en `ui/unlock/UnlockScreen.kt` y una sección «Seguridad del dispositivo»
    en `ui/settings/SettingsScreen.kt`;
  - el descarte se guarda en `SharedPreferences` junto con el conjunto de señales: si aparece una
    señal nueva, el aviso vuelve a salir.
  - Texto: «Este dispositivo parece tener root o una compilación de depuración. Con root, otras apps
    pueden leer tus secretos de la memoria. OpenPassword no puede protegerte en ese caso».
- **Falsos positivos aceptados**: ROM personalizadas sin root (`test-keys`, `userdebug`), emuladores y
  paquetes de gestión de root instalados pero sin usar.
- **Falsos negativos aceptados**: Magisk oculto (paquete con otro nombre, DenyList) y KernelSU con
  rutas ocultas.

### Tests

| Test | Tipo | Cubre |
|---|---|---|
| `app/src/test/.../RootDetectorTest.kt` | JUnit 4 con un `DeviceProbe` falso | Cada señal por separado; ninguna señal en un perfil «limpio»; `test-keys` dentro de otras etiquetas; las rutas y paquetes de las listas |
| `app/src/test/.../OverlayProtectionTest.kt` | JUnit 4 | `obscuredTouch` con combinaciones de banderas |
| `app/src/androidTest/.../OverlayProtectionTest.kt` | Instrumentado (emulador de la CI local) | Las tres actividades tienen `decorView.filterTouchesWhenObscured == true` y `FLAG_SECURE` en `window.attributes.flags`; **además**, cada diálogo que muestran (contraseña maestra, importación, borrado) tiene `filterTouchesWhenObscured == true` en la ventana del propio diálogo, y un toque con la bandera `FLAG_WINDOW_IS_OBSCURED` sobre su botón de confirmar no se entrega |
| `VerifyManifest` | Build | Que exista `HIDE_OVERLAY_WINDOWS` |
| Manual (lista de comprobación en `docs/audit/`) | Dispositivo | Una app de *overlay* de pruebas sobre `UnlockScreen` (API 30 y 34) y un emulador `userdebug` (debe mostrar el aviso) |

No hace falta un dispositivo rooteado: `DeviceProbe` es la frontera de prueba.

### Migración

1. Primero `OverlayProtection.kt` (incluida la protección de diálogos) con sus tests, el manifiesto y
   las tres actividades; después el aviso.
2. Después `RootSignals.kt` y `AndroidDeviceProbe.kt` con sus tests, `<queries>` y el aviso en la UI.
3. Actualizar `docs/threat-model.md`:
   - en A7, el texto real (incluye `setHideOverlayWindows` en API 31+, la protección de los diálogos y
     las limitaciones en API 28-30);
   - en A10: «aviso heurístico, sin red, que se puede eludir».
4. Actualizar `android/README.md` (línea 39): la frase «los únicos permisos del manifiesto son
   `USE_BIOMETRIC` y `CAMERA`» pasa a incluir `HIDE_OVERLAY_WINDOWS`. También `docs/fdroid/README.md`
   si lista permisos (por verificar).

---

## ADR-AUD-07 · Límites de la KDF y denegación de servicio

### Contexto: el formato v1 sí acota los parámetros, y se demuestra en el código

- `core/src/crypto/kdf.rs` define
  `KdfParams::MAXIMUM = argon2id(2_097_152, 16, 16)` (2 GiB, 16 pasadas, 16 carriles).
  `check_bounds()` rechaza cualquier parámetro por encima de ese máximo y lo que `argon2::Params::new`
  no acepte.
- `check_bounds` se aplica en dos sitios:
  1. en `backup::parse` (`core/src/backup/mod.rs`, `header.vault.kdf.check_bounds()?`), **antes** de
     pedir la contraseña;
  2. en `derive_kek` (`params.check_bounds()?` como primera instrucción). Por ahí pasan **todos** los
     caminos hacia Argon2: `UnlockedVault::unlock`, `rekey`, `backup::open` y el `Vault::unlock` de la FFI.
- Está especificado en `docs/crypto-spec.md` §5 (fila «Máximo aceptado al leer») y en
  `docs/opvault-format.md:58`. Los tests están en `kdf.rs` (`bounds_reject_costly_or_invalid_params`)
  y el objetivo `backup_header` lo recorre.
- Hay un filtro antes de la KDF: `UnlockedVault::unlock` compara `header.secret_key_id` con el de la
  SK del usuario y devuelve `WrongSecretKey` **antes** de derivar.

### Pero el techo deja un DoS en móvil

- 2 GiB es más de lo que puede reservar un proceso de armv7 y más de lo que tienen muchos teléfonos.
  `argon2` 0.5 reserva la memoria de bloques con una asignación infalible, así que un fallo de
  memoria **aborta el proceso** aunque se adopte ADR-AUD-03. Si el sistema sobrecompromete memoria, el
  *low-memory killer* mata la app durante el relleno.
- En tiempo de cálculo: 2 GiB × 16 pasadas son unas 43 veces el coste del perfil recomendado
  (256 MiB × 3). En un móvil, eso son minutos de CPU que no se pueden cancelar desde Kotlin.
- **Cómo se alcanza**:
  - `VaultSession.importBackup` con un respaldo **ajeno**: el atacante entrega el fichero **y** su
    SK, así que el filtro de `secret_key_id` no sirve;
  - `VaultSession.restore`;
  - un respaldo propio sustituido en la nube (A4): el `secret_key_id` es visible en cualquier cabecera
    de un respaldo legítimo de la víctima.

  El efecto es un cierre o un cuelgue que se puede repetir. No hay pérdida de datos, porque la
  restauración solo escribe después de abrir.
- La cabecera local (`VaultStorage.readHeader`) solo la puede manipular quien escribe en el
  almacenamiento privado de la app, es decir, un atacante con root (fuera de alcance).
- **KDBX**, relacionado: `core/src/import/kdbx.rs:35-37` acepta Argon2 de hasta 1 GiB con
  **1000 iteraciones** y AES-KDF de 200 millones de rondas. 1 GiB × 1000 son horas. El usuario elige
  el fichero, pero sigue siendo un DoS.
- La app solo crea baúles con `RECOMMENDED` (256 MiB, 3, 4) o `MINIMUM` (64 MiB, 2, 1), según la RAM
  (`OpenPasswordApp.kt`, `kdfProfileFor`). La CLI usa `RECOMMENDED` (`cli/src/main.rs:168`) y los
  vectores usan 256 KiB o 64 MiB. **Ningún fichero creado por OpenPassword supera 256 MiB, 3 pasadas
  y 4 carriles.**

### Opciones

1. No hacer nada: el formato ya acota.
2. Bajar `KdfParams::MAXIMUM` en el núcleo. Cambia lo que el formato v1 considera válido, y con ello
   la especificación y la CLI.
3. Mantener el máximo del formato y añadir en `op-ffi` un **techo de plataforma** más bajo, que se
   comprueba antes de cualquier KDF, más una comprobación de RAM en Kotlin antes de llamar.

### Decisión

Opción 3.

- **El formato v1 no cambia**: `MAXIMUM`, la especificación y los vectores siguen igual. La validez
  del formato y la política de una plataforma son cosas distintas, y la política vive en la capa de
  la plataforma (`op-ffi`), lo que mantiene la dirección de dependencias.
- **En el núcleo**, un método puro nuevo en `core/src/crypto/kdf.rs`:
  `pub fn check_within(&self, limit: &KdfParams) -> Result<()>`. Es `check_bounds` generalizado, y
  `check_bounds` pasa a ser `self.check_within(&Self::MAXIMUM)`, sin cambiar su comportamiento.
- **En `op-ffi`** (`ffi/src/lib.rs`):
  - `const MOBILE_MAXIMUM: KdfParams = KdfParams::argon2id(524_288, 6, 8)` (512 MiB, 6 pasadas, 8
    carriles). Razonamiento con números:
    - es el doble de memoria y de pasadas del perfil recomendado (256 MiB / 3 / 4), así que **4 veces**
      el coste (512 × 6 = 3072 frente a 256 × 3 = 768 MiB·pasada): margen para subir el perfil en el
      futuro sin tocar el techo;
    - ningún baúl creado por la app lo supera (`OpenPasswordApp.kt:61` solo usa `MINIMUM` o
      `RECOMMENDED`), de modo que no invalida nada que haya salido de OpenPassword;
    - el techo que se descartó, 1 GiB / 8 / 8, cuesta 8192 MiB·pasada, unas 10,7 veces el recomendado,
      y 1 GiB seguido en un proceso de 32 bits corre riesgo de fallar por fragmentación del espacio de
      direcciones. 512 MiB lo reduce mucho, aunque no desaparece del todo en armv7;
    - alternativa que se somete a aprobación: un techo **por ABI** (32 bits: 256 MiB / 3 / 4, que es
      exactamente lo que crea la app; 64 bits: 512 MiB / 6 / 8). Complica el comportamiento entre
      dispositivos (un respaldo se abre en un teléfono y no en otro) a cambio de más seguridad en
      armv7;
    - es un techo **de plataforma** (`op-ffi`). `KdfParams::MAXIMUM` (2 GiB / 16 / 16), la
      especificación del formato v1 y los vectores **no cambian**;
  - se comprueba en `Vault::unlock` (después de `parse_header`) y en `open_backup`, antes de llamar a
    `backup::open`. Para eso se lee la cabecera con `backup::read_header(&bytes)`; analizarla dos
    veces cuesta muy poco;
  - una variante nueva `OpError::KdfTooExpensive { m_kib: u32, t: u32, p: u32 }`. Hoy
    `E::KdfParams(_)` se traduce a `Internal`; cuando el límite se supera, la traducción pasa a ser
    `InvalidInput`.
- **Comprobación previa en Kotlin**: una función nueva de la FFI, `backup_kdf(bytes: Vec<u8>) -> KdfInfo { m_kib, t, p }`,
  que no lleva ningún secreto.
  - En `VaultSession.restore` e `importBackup`: si `m_kib × 1024 > totalMem / 2`, se rechaza con un
    mensaje claro antes de llamar a `openBackup`. Se reutiliza la consulta de
    `ActivityManager.MemoryInfo` de `kdfProfileFor`. Esta comprobación es **complementaria**: con 4 GB
    de RAM el umbral es 2 GiB y deja pasar cualquier valor por debajo del techo de `op-ffi`, que es
    la barrera real. Solo sirve para dispositivos con poca RAM (por ejemplo, 1 GB deja el umbral en
    512 MiB; con 512 MiB de techo, solo cambia algo por debajo de 1 GB de RAM).
  - El caso se añade a `OpException.toUserMessage()` (`VaultSession.kt:462`).
- **KDBX**: un presupuesto conjunto `memory × iterations ≤ 16 GiB·pasada` en `argon2_kdf` (por
  ejemplo, 64 MiB × 256 o 1 GiB × 16). Necesita aprobación (ver la lista final), porque puede rechazar
  bases de KeePass legítimas con parámetros muy altos.

### Consecuencias y coste

- Un respaldo con un coste entre el techo móvil y el máximo del formato es válido según v1 pero no se
  abre en Android. Se informa con un error claro, y lo podría abrir la CLI. Ningún baúl creado por la
  app queda afectado (la app nunca supera 256 MiB / 3 / 4).
- Tests:
  - en `kdf.rs`, `check_within` en los bordes;
  - en `ffi/src/lib.rs`, un respaldo con `m_kib = 524_289` falla con `KdfTooExpensive` sin tardar
    (el test debe acabar en milisegundos). La cabecera se construye a mano a partir de una copia real,
    porque `create` no permite crear baúles así;
  - el objetivo `backup_header` comprueba también `check_within(MOBILE_MAXIMUM)`.
- No hace falta cambiar el formato ni migrar datos.

### Migración

1. `check_within` en el núcleo y sus tests.
2. El techo y el error en `op-ffi`, con sus tests.
3. `backup_kdf` y la comprobación previa en Kotlin.
4. El presupuesto de KDBX, si se aprueba.
5. Una nota en `docs/crypto-spec.md` §5: «las plataformas PUEDEN aplicar un techo más bajo; Android:
   512 MiB / 6 / 8».

---

## Plan de implementación (orden y verificación)

Cada paso se puede verificar por separado.

| # | Paso | Ficheros | Depende de | Verificación |
|---|---|---|---|---|
| 1 | `lock`, `is_locked` y `with` resistentes al envenenamiento | `ffi/src/lib.rs` | — | `cargo test -p op-ffi` con los dos tests nuevos |
| 2 | `panic = "unwind"` y medición de tamaño | `Cargo.toml` | 1 | `cargo build --release`; tamaño de `libop_ffi.so` por ABI anotado en el PR |
| 3 | Capturar `InternalException` en toda llamada FFI desde corrutinas de UI y pasar la sesión a `Locked` ante un fallo interno | `session/VaultSession.kt` (`:108-112`, `:266`, `withVault`), `ui/settings/SettingsScreen.kt` (`:405-412`), `ui/settings/ExternalImport.kt` (`:138`), `ui/vault/ItemEditorScreen.kt` (`:133`), `ui/unlock/BiometricFlows.kt` (`:31`), `ui/onboarding/OnboardingScreen.kt` (`:246`), `autofill/SaveLoginActivity.kt` (`:191`), `backup/AutoBackup.kt` (`:102`) | 2 | `./gradlew :app:testDebugUnitTest`; `grep` de `catch (e: OpException)` sin captura de `InternalException`/`Exception` al lado: cero resultados |
| 4 | Prueba aislada de `SecretString` (`custom_type!`) | `ffi/src/lib.rs` (o `ffi/src/secret.rs`) | — | Bindings regenerados sin cambios de tipo en `op_ffi.kt` |
| 5 | Aplicar `SecretString` y `Zeroizing` en toda la API | `ffi/src/lib.rs` | 4 | `cargo test -p op-ffi`; app compilada |
| 6 | `check_within`, `MOBILE_MAXIMUM`, `KdfTooExpensive` y `backup_kdf` | `core/src/crypto/kdf.rs`, `ffi/src/lib.rs` | 5 (misma superficie) | Tests de bordes; un test de DoS que acaba en < 100 ms |
| 7 | Comprobación previa de RAM y mensaje de usuario | `session/VaultSession.kt` | 6 | Test unitario de la función de decisión |
| 8 | Presupuesto de KDBX (si se aprueba) | `core/src/import/kdbx.rs` | — | Tests con parámetros en el borde |
| 9 | Protección contra *overlays* (A7), incluidos los diálogos | `security/OverlayProtection.kt`, las 3 actividades, `ui/Components.kt` (`ProtectedAlertDialog`) y los `AlertDialog` de `SettingsScreen.kt`, `ExternalImport.kt` y `VaultListScreen.kt`, `AndroidManifest.xml`, `build.gradle.kts` (`VerifyManifest`), `android/README.md` (permisos) | — | Tests unitarios e instrumentados (actividades y diálogos); `assembleRelease` falla si se quita el permiso |
| 10 | Detección de root (A10) | `security/RootSignals.kt`, `security/AndroidDeviceProbe.kt`, `OpenPasswordApp.kt`, `ui/unlock/UnlockScreen.kt`, `ui/settings/SettingsScreen.kt`, `AndroidManifest.xml` (`<queries>`) | — | `RootDetectorTest`; emulador `userdebug` con aviso |
| 11 | Ganchos `cfg(fuzzing)` y 5 objetivos nuevos con *seeds* | `core/src/lib.rs`, `core/src/backup/mod.rs`, `fuzz/` | 6 | `cargo +nightly fuzz build`; 60 s sin fallos por objetivo; `cargo build --release` no expone `fuzzing` |
| 12 | Fuzzing nocturno | `.github/workflows/fuzz-nightly.yml`, `ci.yml` | 11 | Una ejecución manual (`workflow_dispatch`) en verde |
| 13 | Tests de invariantes de `LoginMatcher` | `app/src/test/.../LoginMatcherTest.kt` | — | `testDebugUnitTest` |
| 14 | `cargo-deny` | `deny.toml`, `ci.yml`, borrar `.cargo/audit.toml` | — | `cargo deny --locked check` en verde |
| 15 | Actions por SHA, Dependabot y versiones de herramientas fijadas | `ci.yml`, `.github/dependabot.yml` | 14 | CI en verde; ningún `uses:` sin SHA (`grep`) |
| 16 | Verificación de dependencias de Gradle | `android/gradle/verification-metadata.xml`, `android/README.md` | 15 | Build en Linux (CI) y en macOS en verde; falla si se altera una suma |
| 17 | Job `release`: SBOM y atestación | `ci.yml`, `android/app/build.gradle.kts` (plugin CycloneDX) | 15, 16 | Ejecución con una etiqueta de prueba (`v0.2.0-rc1`); `gh attestation verify` pasa |
| 18 | Documentación: modelo de amenazas (A7, A10, residuos), especificación §5 y §10, `fuzz/README.md`, `SECURITY.md` | `docs/` | 1-17 | Revisión; ninguna defensa descrita sin código que la implemente |
| 19 | Versión 0.2.0, rama `release/0.2`, etiqueta firmada y paquete para el auditor | `Cargo.toml`, `build.gradle.kts`, `fastlane/` | Todo | El SHA-256 del APK de la CI coincide con un build de Linux independiente |

Los pasos 1-8, 9-10, 11-13 y 14-17 forman bloques independientes y pueden avanzar en paralelo.

## Riesgos que quedan abiertos

| Riesgo | Por qué queda abierto | Mitigación o siguiente paso |
|---|---|---|
| Secretos en `String` de JVM y Compose | No se pueden borrar en la JVM | ADR-AUD-02, opción D (sesión opaca) después de la auditoría; documentado como residuo |
| `RustBuffer` de salida y copia `String` de salida sin borrar | UniFFI no ofrece un gancho de borrado | Documentado; reconsiderar si UniFFI añade uno |
| Fallo de memoria en Argon2 = abort | Asignación infalible en `argon2` 0.5; `panic = "unwind"` no lo evita | El techo de 512 MiB / 6 / 8 y la comprobación de RAM **reducen** la probabilidad, pero **no** lo mitigan: un dispositivo con poca memoria libre o un proceso de 32 bits fragmentado puede abortar igualmente, y la comprobación de RAM de Kotlin (`totalMem / 2`) es laxa. Queda abierto; solo lo cerraría una asignación fallible en `argon2` o una KDF en otro proceso |
| KDF que no se puede cancelar | Llamada FFI bloqueante | Aviso «puede tardar» en la UI; fuera de alcance |
| Root oculto (Magisk o KernelSU con ocultación) | Las heurísticas locales se pueden eludir por diseño | Solo aviso; A10 sigue fuera de alcance |
| Tapjacking parcial en API 28-30 | `filterTouchesWhenObscured` no filtra `PARTIALLY_OBSCURED` | Aviso; API 31+ oculta los *overlays* |
| `StructureParser` sin fuzzing | Depende de `AssistStructure` | Refactor a una abstracción de nodos más adelante, y después Jazzer |
| Dependencias de Rust sin revisión humana | No se adopta `cargo-vet` | `cargo-deny`, pocas dependencias, versiones fijadas; reconsiderar después de la auditoría |
| Reversión a una versión anterior (A6) | Sin sincronización no se detecta | Aceptado en v1 |
| Disparadores de CI para etiquetas y `release/**` | `tags: ['v*']` se añade con el cierre de `v0.1.0` y aún no se ha probado con una etiqueta; `release/**` todavía no existe | ADR-AUD-01, migración 2; verificarlo con una etiqueta `-rc` |
| Ganchos `cfg(fuzzing)` en el código del núcleo | Código que solo existe en fuzzing | Revisión del auditor; test de que el build de release no exporta el módulo |

## Decisiones que requieren aprobación humana

1. **ADR-AUD-01**: firmar etiquetas (qué clave), la congelación blanda de `core/` y `ffi/` en `main`, y
   añadir `release/0.2` a las versiones con soporte de `SECURITY.md`.
2. **ADR-AUD-03**: cambiar `panic = "abort"` por `"unwind"`, y el umbral de tamaño (+15 %) a partir
   del cual se vuelve al perfil separado.
3. **ADR-AUD-07**: el valor del techo móvil (512 MiB / 6 / 8, o un techo por ABI: 32 bits
   256 MiB / 3 / 4 y 64 bits 512 MiB / 6 / 8), y que haya respaldos válidos según v1 que no se abran en
   Android. **Sigue pendiente de aprobación humana.**
4. **ADR-AUD-07**: el presupuesto de KDBX (`memory × iterations ≤ 16 GiB·pasada`), que puede rechazar
   bases de KeePass legítimas.
5. **ADR-AUD-06**: **avisar sin bloquear** cuando se detecta root; y el bloque `<queries>` con los
   nombres de paquetes de root (es visible en el manifiesto publicado).
6. **ADR-AUD-06**: el permiso `HIDE_OVERLAY_WINDOWS` en el manifiesto (aparece en F-Droid como permiso
   nuevo) y la actualización de `android/README.md`, que hoy dice que solo hay dos permisos.
7. **ADR-AUD-04**: la lista de licencias admitidas en `deny.toml`, y añadir el plugin de CycloneDX
   (una dependencia de build nueva).
8. **ADR-AUD-04**: usar atestaciones de Sigstore (registro público) y conceder `id-token: write` al
   job de release.
9. **ADR-AUD-05**: no adoptar Jazzer ni ClusterFuzzLite antes de la auditoría.
10. **ADR-AUD-02**: aplazar la sesión opaca (opción D) a después de la auditoría y aceptar los
    residuos documentados.
