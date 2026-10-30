# Revisión crítica del modelo de amenazas

Revisión de [`../threat-model.md`](../threat-model.md) (v1, 48 líneas) contra el código del repositorio.
No modifica `threat-model.md`: la sección 5 lista los cambios que habría que aplicar.

> **Actualización posterior a `2bd56ce`.** Se han aplicado en `threat-model.md` los cambios 1 (A7), 3 (A10), 4 (con una fila nueva A17 en lugar de ampliar A12; ID-INT-16 está corregido) y 13 (residuos de secretos y de importadores). Siguen sin aplicar los demás. Las secciones que describen ID-INT-01 y ID-INT-16 (y la fila A12 de la sección 2) reflejan el estado **antes** de `2bd56ce`, donde ambos quedaron corregidos. La numeración de filas nuevas de la sección 5 (punto 10) ya no es válida: A17 es ahora «App que declara el dominio de una web». Se añadió también A18 («App rellenada que dispara el `PendingIntent` de autenticación», ID-INT-26), también sin commit.

Estado verificado el 2026-10-30 sobre el árbol de trabajo (`HEAD` `3725741` más cambios sin confirmar,
que desde entonces están en `2bd56ce`; ver [`hardening.md`](hardening.md)). Los hallazgos `ID-INT-nn` están en
[`internal-review.md`](internal-review.md). Las afirmaciones que no se pueden comprobar sin un
dispositivo se marcan **sin verificar**.

## 1. Resumen

- El documento **ya no es fiel al código** en dos filas: A7 y A10 siguen diciendo «Previsto, aún no
  implementado» y las dos defensas existen desde `3725741` (`OverlayProtection.kt`, `RootSignals.kt`).
- Una fila afirma algo que el código **no cumple**: A12 dice «nombre de paquete exacto (verificado
  por Android) en apps» y lo toma como garantía general, pero el autorrelleno confía en el
  `webDomain` que declara cualquier app (ID-INT-16).
- Una defensa que el documento da por hecha **puede no funcionar en el caso de uso principal**: el
  borrado del portapapeles (A7) no actúa si la app ya no tiene el foco (ID-INT-14, sin verificar en
  dispositivo).
- Faltan, como mínimo, 16 ataques o riesgos (sección 3). Los nueve que se pidieron expresamente
  están todos; cada uno indica qué hay hoy en el código y qué falta decidir.
- Hay supuestos implícitos que cambian el resultado del análisis (sección 4), el más importante: que
  el atacante nunca controla un **proveedor de documentos**, una **app instalada** que el usuario
  abre, ni el **ordenador del mantenedor**.

## 2. Qué afirma frente a lo que existe

Veredicto: **Cierto** (el código lo respalda), **Parcial**, **Desactualizado** (el texto es anterior al
código), **Incorrecto** (el código lo contradice) o **Sin verificar**.

### 2.1 Activos y supuestos

| Texto de `threat-model.md` | Veredicto | Evidencia y matiz |
|---|---|---|
| Activos: secretos, metadatos, credenciales de acceso, respaldos | Parcial | Faltan **la clave de firma** del APK y **el kit de emergencia** (contiene la SK en claro, `EmergencyKit.kt:31-39`). Ver 3.7 y 3.5 |
| Supuesto: SO y hardware sin comprometer | Cierto, pero incompleto | No cubre a otras apps (sí son no confiables en el autorrelleno), al teclado ni a los proveedores de documentos |
| Supuesto: el CSPRNG funciona | Cierto | `getrandom::fill` (`core/src/crypto/rng.rs:4-6`); un fallo devuelve `Error::Rng` y no sigue |
| Supuesto: el usuario conserva la contraseña maestra o el kit | Cierto | Sin recuperación. Además, **no hay cambio de contraseña en la app**: `rekey` existe en `op-core` (`vault/mod.rs:144`) y no está en `op-ffi` ni en la UI (`grep -rn rekey ffi android` no da resultados). El «riesgo residual» de «respaldos con credenciales antiguas» describe una función que no se puede usar. La especificación (§8) dice que la app DEBE avisar; no hay función que avisar |

### 2.2 Atacantes y defensas

| # | Estado que declara | Veredicto | Evidencia y matiz |
|---|---|---|---|
| A1 | Protegido | Cierto | Cabecera sin datos de usuario (`vault/mod.rs:21-33`); elementos cifrados (`ItemDatabase.kt:9-12`); SK sellada con Keystore (`DeviceKeyStore.kt`). **Matiz**: el `id` y la `revision` de cada elemento van en claro, y la existencia y el número de elementos se ven. No se menciona |
| A2 | Protegido | Parcial | Espera exponencial: 4 intentos libres, luego 30 s duplicándose hasta 1 h (`VaultSession.kt:477-481`, test `UnlockBackoffTest`). Solo cubre `unlock`; `verifyPassword` no cuenta ni espera (`:201-210`, ID-INT-09). La biometría cae en el límite del sistema |
| A3 | Protegido | Cierto con una condición | «Sin la SK, probar contraseñas no sirve» solo se sostiene mientras la SK no se filtre. Se filtra por **el kit de emergencia en claro** (3.5) y está **en el teléfono** sellada con Keystore. Argon2id mínimo permitido para baúles nuevos: 64 MiB / 2 / 1 (`kdf.rs:33`) |
| A4 | Protegido | Parcial | «Solo ve un blob autenticado»: cierto para lectura. No considera que el proveedor **escriba, sustituya o borre** (3.2) ni que `AutoBackup` **borre** copias antiguas por patrón de nombre (`AutoBackup.kt:143-145`) |
| A5 | Protegido | Cierto | `body_aad` = SHA-256 de la región de cabecera (`backup/mod.rs:46-48`); STREAM con último trozo marcado; AAD por elemento, revisión y parte (`vault/mod.rs:63-76`). Tests: `core/tests/backup.rs` (9) |
| A6 | Aceptado | Parcial | Aceptado, pero la **importación** de una copia antigua del mismo baúl **resucita elementos borrados** (3.2). No es solo «un elemento a una versión anterior» |
| A7 | Parcial («Previsto, aún no implementado» `filterTouchesWhenObscured`) | **Desactualizado** | Implementado en `3725741`: `filterTouchesWhenObscured`, `setHideOverlayWindows` (API 31+), diálogos protegidos (`ProtectedAlertDialog`, `Components.kt:187-205`), y exigencia del permiso en `VerifyManifest` (`build.gradle.kts:174-176`). Quedan límites reales: un toque parcialmente tapado (`PARTIAL`) se entrega y en API 28-30 no existe `setHideOverlayWindows`; el aviso es un `Toast` una sola vez por proceso en las actividades de autorrelleno (`OverlayProtection.kt:39,57-62`). **«Portapapeles sensible con borrado»: sin verificar y probablemente ineficaz en segundo plano** (ID-INT-14) |
| A8 | Mitigado | Cierto | `PasswordVisualTransformation` y revelado por campo (`Components.kt:79`) |
| A9 | Mitigado | **Parcial** | «`cargo audit`»: ya se sustituyó por `cargo deny` en el árbol de trabajo (`ci.yml`, job `audit`). «Builds reproducibles»: `docs/fdroid/README.md:59-61` dice que **solo se confirma cuando F-Droid compile**; no hay comprobación independiente hoy. «Pocas dependencias»: 136 crates de terceros en el `Cargo.lock` y 144 componentes Gradle en la SBOM de `releaseRuntimeClasspath` ([`dependencies.md`](dependencies.md)). Cubre dependencias, **no** CI ni la clave de firma (3.8 y 3.7) |
| A10 | Fuera de alcance («Previsto, aún no implementado» el aviso) | **Desactualizado** | Aviso heurístico implementado (`RootSignals.kt`, `RootWarning` en `Components.kt:226-237`, `<queries>` en el manifiesto). El texto debe decir «aviso heurístico, sin red, que se puede eludir», como pide ADR-AUD-06 |
| A11 | Fuera de alcance | Cierto | No hay señuelo ni contraseña de coacción |
| A12 | Mitigado | **Incorrecto en parte** | La coincidencia de hosts es estricta y usa la lista de sufijos públicos (`LoginMatcher.kt:43-48`, `PublicSuffix.kt`). Pero un `webDomain` lo declara **cualquier app** y no se comprueba que sea un navegador (`StructureParser.kt:35,53`, ID-INT-16). «Verificado por Android» vale para el **paquete**, no para el dominio |
| A13 | Protegido | Parcial | 30 s en segundo plano, 3 min si hay un selector de ficheros, apagado de pantalla y 5 min de inactividad (`VaultSession.kt:471-474`). No se vacía `PendingSaves` al bloquear (ID-INT-17) y un desbloqueo fallido deja el `Vault` nativo vivo (ID-INT-05) |
| A14 | Protegido | Cierto | `IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS` en las tres actividades (`AutofillExclusion.kt:11-13`; llamadas en `MainActivity.kt:45`, `AutofillAuthActivity.kt`, `SaveLoginActivity.kt`) |
| A15 | Mitigado | Parcial | «Los bytes leídos se borran»: `bytes.fill(0)` borra la copia final (`ExternalImport.kt:50-58,61-63`), pero `readBackupFile` deja otra en el `ByteArrayOutputStream` (`Components.kt:159`) y en Rust el árbol `serde_json::Value`, los `String` del CSV y el `hex` del archivo de clave no se borran (ID-INT-03, ID-INT-12) |
| A16 | Mitigado | Cierto, con un matiz | Solo `otpauth://totp/` (`QrDecoder.kt:49-52`), sin red, sin guardar fotogramas. **Matiz**: la imagen pasa por el descodificador de imágenes del sistema antes de ZXing (`QrScanner.kt:163-177`), que es código nativo no auditado aquí |

### 2.3 Riesgos residuales

| Texto | Veredicto | Matiz |
|---|---|---|
| Pérdida total | Cierto | — |
| Memoria de la JVM | Parcial | Falta: el `RustBuffer` de salida de UniFFI y la copia `String` de Rust se liberan sin borrar (`ffi/src/lib.rs:13-14`, `secret.rs:8-11`, ADR-AUD-02 §6). Falta también la memoria de Compose, `PendingSaves` y los `String` de las exportaciones de otros gestores |
| Metadatos de tamaño | Cierto | El *padding* es de 64 bytes (`padding.rs:7`): oculta la longitud exacta, no el orden de magnitud |
| Respaldos con credenciales antiguas | Sin efecto hoy | No hay cambio de contraseña (ver 2.1) |

## 3. Ataques y riesgos que faltan

Cada entrada: **qué es**, **lo que hay hoy** (con evidencia), **brecha** y **propuesta para
`threat-model.md`**. Las nueve primeras (3.1 a 3.9) son las que se pidieron expresamente.

### 3.1 Denegación de servicio por parsers

- **Qué es**: un fichero hostil que bloquea, cuelga o mata la app: copia `.opvault`, base KDBX, CSV,
  JSON, `.1pux`, QR, imagen o `AssistStructure`. Un *panic* de Rust y una falta de memoria no son lo mismo.
- **Hoy**: `panic = "unwind"` (`Cargo.toml:25`) más captura de `InternalException` convierten el
  *panic* en un error (`VaultSession.kt:434-443`); el techo móvil de KDF 512 MiB / 6 / 8
  (`ffi/src/lib.rs:33`) y el presupuesto KDBX (hoy 512 MiB y 3 GiB·pasada, `kdbx.rs:36-42`; antes 16 GiB·pasada) acotan el coste; el
  límite de entrada es de 32 MiB (`import/mod.rs:34`) y de 64 MiB en Kotlin (`Components.kt:171`).
- **Brecha**: una **falta de memoria aborta el proceso** con cualquier estrategia de *panic*
  (ADR-AUD-03; riesgo abierto en [`decisions.md`](decisions.md)). Y hay un DoS real, reproducido:
  **memoria cuadrática en el XML de KeePass** (ID-INT-01: 180 KB de XML → 757 MB de RSS). La KDF de
  KeePass no pasa por el techo móvil (ID-INT-02). El cuerpo de una copia `.opvault` no tiene tope en Rust.
- **Propuesta**: nueva fila **A17 «Fichero hostil»**, estado «Parcial», con la lista de límites y la
  salvedad del aborto por memoria.

### 3.2 Reversión y sustitución con copias antiguas

- **Qué es**: A6 cubre sustituir un elemento por una versión anterior. No cubre: (a) restaurar o
  importar una copia **antigua** del mismo baúl, (b) un proveedor que sustituya o borre ficheros en la
  carpeta de copia automática, (c) el borrado de elementos que no se propaga.
- **Hoy**: `importBackup` mezcla por revisión: si el elemento no existe localmente lo añade
  (`VaultSession.kt:184`: `mine == null -> upsert; added++`), así que **un elemento borrado vuelve** al
  importar una copia anterior; si la revisión de la copia es mayor, sobrescribe (`:185`). No hay
  *tombstones*. `restore` solo funciona sin baúl (`:136`).
- **Brecha**: lo único que una copia antigua no puede hacer es bajar la revisión de un elemento
  existente. Pero **una contraseña que el usuario borró porque se filtró reaparece**. Además
  `AutoBackup` borra por nombre (`BackupNames.toDelete`, `AutoBackup.kt:143-145`): un proveedor que
  escribe ficheros con nombres posteriores desplaza las copias legítimas fuera de las 10 conservadas
  (hipótesis deducida del código, **sin reproducir**).
- **Propuesta**: ampliar A6: «copias antiguas resucitan elementos borrados; no hay *tombstones*»; en
  A4 añadir «un proveedor con escritura puede desplazar o borrar copias».

### 3.3 Teclados que aprenden y historial del portapapeles

- **Qué es**: un IME de terceros aprende o guarda lo que se teclea o se copia.
- **Hoy**: los campos de contraseña usan `KeyboardType.Password` y `autoCorrectEnabled = false`
  (`Components.kt:51-80`, `ItemEditorScreen.kt:261-262`); los PIN y números de tarjeta usan
  `NumberPassword`. En el resto (título, usuario, **notas**, URL) el teclado es de texto normal
  (`ItemEditorScreen.kt:288-294`) y **no se usa** `privateImeOptions` ni la bandera de aprendizaje
  personalizado (`grep -rn "privateImeOptions\|NO_PERSONALIZED" android/app/src/main` no da
  resultados). El portapapeles lleva `EXTRA_IS_SENSITIVE` solo desde API 33 (`SensitiveClipboard.kt:23-27`).
- **Brecha**: las **notas seguras** (frases semilla, claves API) se escriben en un campo de texto que el
  teclado puede aprender; y en API 28-32 un gestor de portapapeles o el teclado ve el valor copiado sin
  marca (ID-INT-15). Android 10+ solo da el portapapeles a la app con foco y al IME por defecto, que es
  justo el teclado.
- **Propuesta**: nueva fila **A18 «Teclado o gestor de portapapeles de terceros»**, «Parcial», con los
  campos protegidos y los que no.

### 3.4 Residuos de WAL y de SQLite

- **Qué es**: restos de datos tras borrar o editar un elemento: páginas libres, diario de reversión,
  WAL.
- **Hoy**: `PRAGMA secure_delete = ON` (`ItemDatabase.kt:15-19`); no hay `enableWriteAheadLogging` ni
  `setJournalMode` (`grep -rn "WriteAheadLogging\|journal" android/app/src` no da resultados), así que
  el modo lo decide el valor por defecto de Android (**sin verificar** cuál ni si deja un `-journal`
  persistente en cada versión). Lo que se escribe es cifrado.
- **Brecha**: borrar un elemento **no es un borrado criptográfico**: la clave del elemento va envuelta
  con la clave del baúl, que no cambia (`update_item` conserva la clave de elemento,
  `vault/mod.rs:174-193`). Quien conserve una página antigua, un diario o un respaldo del disco y
  consiga después la clave del baúl descifra **elementos que ya se borraron**. Las revisiones
  anteriores de un elemento editado van cifradas con la misma clave de elemento. La exclusión de
  `database` en `data_extraction_rules.xml` evita que salgan por la copia del sistema.
- **Propuesta**: en «Riesgos residuales»: «borrar no es borrado criptográfico; el cifrado del
  almacenamiento de Android es la defensa»; comprobar en dispositivo el modo de diario y la presencia
  de `items.db-journal` o `items.db-wal` tras borrar.

### 3.5 PDF del kit de emergencia (la SK en claro)

- **Qué es**: el kit contiene la SK. El texto del modelo no lo trata como activo ni como riesgo.
- **Hoy**: se genera en memoria (`EmergencyKit.pdf` devuelve un `ByteArray`, `EmergencyKit.kt:31-39`) y
  se escribe donde el usuario elija con `CreateDocument` (`SettingsScreen.kt:116-128`,
  `OnboardingScreen.kt:192-203`). La app **no escribe en caché** (`grep -rn
  "cacheDir\|FileProvider\|createTempFile" android/app/src/main` no da resultados). El mensaje dice
  «Imprímelo y después borra el PDF del teléfono».
- **Brecha**: el destino es un proveedor arbitrario: carpeta sincronizada, nube, indexador de
  documentos; la app no puede borrarlo ni saber dónde quedó. Con la SK fuera, A3 depende solo de la
  contraseña. El `ByteArray` del PDF no se borra de la memoria (residuo, no un hallazgo aparte).
- **Propuesta**: añadir el kit como **activo** (sensibilidad Crítica, «igual que la SK») y una fila
  **A19 «Kit de emergencia filtrado»**: «el usuario es responsable; sin SK, A3 se degrada a la
  fortaleza de la contraseña».

### 3.6 Intents falsificados

- **Qué es**: otra app que envía un `Intent` a `MainActivity`, `AutofillAuthActivity` o
  `SaveLoginActivity`, o que falsifica un `PendingIntent`.
- **Hoy**: solo `MainActivity` está exportada y no lee el intent; las otras dos no (`AndroidManifest.xml:39-64`);
  el token de guardado son 16 bytes aleatorios con vida de 5 min (`PendingSaves.kt:15-24`); el
  `PendingIntent` de autorrelleno es mutable pero de `Intent` explícito (`Datasets.kt:50-55`). Detalle
  en [`attack-surface.md`](attack-surface.md) §2.9.
- **Brecha** (corregida después de esta revisión): este análisis dio por bueno el `PendingIntent` mutable de autorrelleno, pero la app rellenada recibe el `IntentSender` y puede añadirle extras: ver [ID-INT-26](internal-review.md#id-int-26), corregido sin commit con un token de un solo uso, y la fila A18 de `threat-model.md`. **Matiz**: la caducidad del token es perezosa y
  no hay vaciado al bloquear (ID-INT-17).
- **Propuesta**: fila **A20 «App que envía intents»**, «Mitigado»: actividades no exportadas, token
  aleatorio, sin datos en el intent.

### 3.7 Rotación o pérdida de la clave de firma

- **Qué es**: perder la clave deja a los usuarios sin actualizaciones; filtrarla permite una
  actualización maliciosa con la firma legítima.
- **Hoy**: la clave de release está en `~/.openpassword/release-signing.properties` y su `.p12`, en el
  ordenador del mantenedor (`build.gradle.kts:13-18`, `scripts/firmar-release.sh:13`); firma v2 y v3
  «para poder rotarla» (`build.gradle.kts:43-45`). El APK se firma **después** de bajar el artefacto de
  la CI (`firmar-release.sh:21`). `docs/fdroid/README.md:29-31` pide una copia fuera del ordenador y
  admite que, si se pierde, «no podrás publicar actualizaciones con la misma firma».
- **Brecha**: no hay procedimiento escrito de rotación (v3 lo permite, pero requiere el certificado
  antiguo) ni de revocación; una app que no se puede actualizar con la misma firma obliga a
  **desinstalar**, y desinstalar **borra el baúl local**, así que la única vía es restaurar una copia.
  Punto único de fallo humano y de equipo.
- **Propuesta**: activo «clave de firma» (Crítica) y fila **A21 «Compromiso o pérdida de la clave de
  firma»**, «Aceptado con procedimiento», que enlace a un runbook por escribir (rotación v3, copia
  fuera de línea, aviso de seguridad). **Es una decisión humana.**

### 3.8 CI y GitHub Actions comprometidas

- **Qué es**: que el APK que firma el mantenedor no sea el del código fuente.
- **Hoy** (commit `2bd56ce`): Actions fijadas por SHA, `cargo-deny@0.20.2` y
  `cargo-fuzz@0.13.2` con versión, `dependabot.yml`, `verification-metadata.xml` de Gradle y un job
  `release` con atestación de procedencia (`ci.yml`, `.github/dependabot.yml`,
  `android/gradle/verification-metadata.xml`). Permisos de la CI: `contents: read`, y
  `id-token`/`attestations: write` solo en el job `release`.
- **Brecha**: el mantenedor firma el artefacto de la CI **sin reconstruirlo antes** (macOS no
  reproduce el APK de Linux, `firmar-release.sh:4-5`); la única comprobación independiente la hará
  F-Droid después. `dtolnay/rust-toolchain` se fija por el SHA de su **rama** `stable` (`# stable branch`), no de una
  versión etiquetada, lo que dificulta revisar qué cambia en cada subida. `cargo install cargo-ndk` y
  `cargo install cargo-cyclonedx` van con versión y `--locked`, pero **sin suma de comprobación**. El `release` no crea la *release*: adjuntar los ficheros es manual.
- **Propuesta**: fila **A22 «CI o dependencia de build comprometida»**, «Parcial»; ampliar A9 y citar
  atestación, SBOM y verificación de Gradle como defensas, con el límite de que firma una persona sobre un
  artefacto que no ha reconstruido.

### 3.9 Sufijos públicos en el autorrelleno

- **Qué es**: que un login de `github.io` o `co.uk` se ofrezca a cualquier subdominio de ese sufijo.
- **Hoy**: `LoginMatcher.hostMatches` solo permite subdominios de un host guardado si **no** es un
  sufijo público (`LoginMatcher.kt:43-48`); la lista (`public_suffix_list.dat`, versión
  `2026-10-28_13-15-55_UTC`, 338 012 bytes) va en `src/main/resources`; sin lista, **solo coincide el
  host exacto** (`PublicSuffix.kt:10-12, 20`). Tests: `LoginMatcherTest` (29).
- **Brecha**: no hay mecanismo de actualización de la lista. El recurso **sí está en el APK de release**
  (`unzip -l android/app/build/outputs/apk/release/app-release.apk | grep public_suffix` →
  `public_suffix_list.dat`, 338 012 bytes), pero **sin verificar** que se cargue en un dispositivo (los
  tests corren en la JVM y no hay prueba instrumentada). Si no se cargara, la degradación es silenciosa
  y segura (host exacto), pero se perdería la coincidencia por subdominio.
- **Propuesta**: nota en A12 con el comportamiento («subdominios solo de dominios registrables según la
  lista de sufijos públicos del 28/10/2026; sin lista, coincidencia exacta»).

### 3.10 Más ataques que faltan

| # | Qué es | Hoy | Propuesta |
|---|---|---|---|
| 3.10.1 | **`webDomain` declarado por una app** (variante de A12) | `StructureParser.kt:35,53`: se usa el primero que aparezca sin comprobar que quien lo declara sea un navegador | Corregir A12 y abrir el hallazgo ID-INT-16 |
| 3.10.2 | **Credenciales en claro hacia `system_server` y el teclado** en cada respuesta de relleno | `OpAutofillService.kt:36-44` y `Datasets.kt:37-43`: con el baúl abierto se entregan hasta 5 `Dataset` con usuario y contraseña, sin autenticación de dataset (`setAuthentication` solo con el baúl bloqueado) | Documentar como diseño de Android; fila en A12/A13 |
| 3.10.3 | **Proveedor de documentos hostil** (SAF) | Ver [`attack-surface.md`](attack-surface.md) §2.10; solo se escriben copias cifradas y el kit | Nueva fila A23 junto a A4 |
| 3.10.4 | **Descodificadores de imagen del sistema** al leer un QR de una imagen | `QrScanner.kt:163-177` | Nota en A16 |
| 3.10.5 | **Un solo registro ilegible impide desbloquear** | `VaultSession.kt:108,141,280` (ID-INT-06) | Riesgo residual de disponibilidad; la restauración exige no tener baúl (`:136`) |
| 3.10.6 | **Kotlin y Rust en el mismo proceso** | Sin frontera de privilegios | Supuesto explícito (sección 4) |
| 3.10.7 | **Borrado del portapapeles en segundo plano** | `SensitiveClipboard.kt:38` (ID-INT-14) | Corregir A7 |

## 4. Supuestos implícitos

1. **El atacante nunca tiene el teléfono desbloqueado a la vez que conoce la contraseña.** Con el
   baúl abierto no hay nada que impida ver todo (A8 cubre solo al mirón). La espera exponencial
   actúa **después** de 4 fallos.
2. **Los proveedores de documentos son pasivos.** El modelo no distingue una carpeta local de una
   nube ni de un proveedor malicioso; `AutoBackup` borra y crea ficheros ahí.
3. **Todo lo que declara una app en `AssistStructure` es cierto salvo el paquete.** Es falso para el
   `webDomain` (ID-INT-16).
4. **El almacenamiento privado no se lee tras borrarlo.** Se apoya en el cifrado de Android; no hay
   borrado criptográfico (3.4).
5. **El teclado no es hostil.** Se recomienda un campo `Password` donde se puede; las notas van en
   texto normal.
6. **Un solo mantenedor firma y custodia la clave**, y es de fiar (3.7).
7. **La CI de GitHub, Sigstore y el índice de crates.io son de fiar** salvo lo que fijan los SHA y las
   sumas (3.8).
8. **El `Vec<u8>` y el `String` de UniFFI salen sin borrar**; se acepta porque el atacante que leyera la
   memoria del proceso ya tiene root (A10, fuera de alcance). Si A10 pasara a estar en alcance, el
   análisis cambia por completo.
9. **El reloj del teléfono es de fiar** para el autobloqueo y para el cálculo de los 14 días de la
   contraseña obligatoria (`System.currentTimeMillis`, `VaultSession.kt:224`; el autobloqueo usa
   `elapsedRealtime`, que sí es monótono).
10. **Android reinicia el contador de arranque solo al reiniciar** (`BOOT_COUNT`); el modelo lo usa
    como prueba de «el teléfono se reinició» (`VaultSession.kt:223`).
11. **Una app de solo lectura del baúl no existe**: quien puede abrir la app puede editar y borrar todo.

## 5. Cambios concretos que hay que aplicar a `threat-model.md`

Ninguno se ha aplicado. Orden de aplicación recomendado, de lo que corrige falsedades a lo que añade.

1. **A7**: sustituir «Previsto, aún no implementado: `filterTouchesWhenObscured`» por el texto real:
   `FLAG_SECURE` en las tres actividades; `filterTouchesWhenObscured` en cada ventana y en los diálogos
   (`ProtectedAlertDialog`); `setHideOverlayWindows` desde API 31 con el permiso normal
   `HIDE_OVERLAY_WINDOWS`; aviso (banner en la actividad principal, `Toast` único en las de
   autorrelleno); límite en API 28-30 (un toque parcialmente tapado se entrega). Estado «Mitigado»
   solo cuando existan los tests instrumentados de las otras dos actividades y de los diálogos
   (hoy solo `MainActivity`, `androidTest/.../OverlayProtectionTest.kt`).
2. **A7, portapapeles**: «portapapeles sensible (API 33+) con borrado a los 30 s **si la app aún tiene
   acceso**; en segundo plano el borrado puede no actuar (sin verificar en dispositivo)». No decir
   «con borrado» sin cualificar hasta confirmarlo.
3. **A10**: «aviso heurístico, sin red, que se puede eludir; no bloquea».
4. **A12**: añadir «`webDomain` lo declara la app de origen; hoy se confía en él sin exigir un
   navegador (ID-INT-16)» o, una vez corregido, «solo se confía en `webDomain` de navegadores de una lista». Citar la lista de
   sufijos públicos y su fecha.
5. **A2**: precisar «espera exponencial en el desbloqueo con contraseña (`unlock`); la verificación de
   contraseña de Ajustes no cuenta intentos» hasta que se corrija ID-INT-09.
6. **A4 y A6**: añadir proveedor con escritura (sustituir, borrar, desplazar copias) y la
   resurrección de elementos borrados al importar una copia antigua.
7. **A9**: separar tres filas. Dependencias (cargo-deny, verificación de Gradle, SBOM); CI (SHAs,
   atestación); y clave de firma. Retirar «builds reproducibles» o cualificarlo con «pendiente de
   confirmar por F-Droid».
8. **A13**: añadir `PendingSaves` (vaciado) y el comportamiento tras un fallo interno
   (la sesión pasa a `Locked`, `VaultSession.kt:434-443`).
9. **A15**: «el `ByteArray` final se borra; quedan copias transitorias (`ByteArrayOutputStream`, árboles
   de `serde_json`, cadenas del CSV)».
10. **Filas nuevas**: A17 fichero hostil; A18 teclado y portapapeles de terceros; A19 kit de
    emergencia filtrado; A20 intents; A21 clave de firma; A22 CI y cadena de compilación; A23
    proveedor de documentos hostil.
11. **Activos**: añadir «Clave de firma (Crítica)» y «Kit de emergencia (Crítica, contiene la SK)».
12. **Supuestos**: añadir los de la sección 4 que el equipo decida mantener (1, 2, 5, 6, 7 y 8 como
    mínimo).
13. **Riesgos residuales**: añadir el borrado no criptográfico (3.4), el `RustBuffer` de salida
    (`secret.rs:8-11`), el aborto por falta de memoria (ADR-AUD-03/07), y quitar «Respaldos con
    credenciales antiguas» hasta que exista el cambio de contraseña.
14. **Encabezado**: el documento dice «se revisa antes de cada versión mayor y antes de la auditoría».
    Añadir fecha y el SHA sobre el que se revisó.

## 6. Qué no se ha podido comprobar

- Todo lo marcado **sin verificar**: modo de diario de SQLite, borrado del portapapeles en segundo
  plano, carga de la lista de sufijos públicos en un dispositivo, y la fiabilidad de cualquier
  prueba en dispositivo (no se ha ejecutado ninguna prueba instrumentada ni manual en esta revisión).
- La ejecución del job `release` de la CI y de `cargo deny` en GitHub: `cargo deny --locked check` se
  ejecutó en local y salió con «advisories ok, bans ok, licenses ok, sources ok».
