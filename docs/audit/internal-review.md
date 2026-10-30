# Auditoría interna previa

Revisión del código por el propio proyecto, antes de entregárselo al auditor externo. Una sección por
área. Cada hallazgo se puede **comprobar con `grep`, `sed -n` o un comando** que se indica; los que se
han reproducido llevan el procedimiento. Si un área está limpia, se dice y se demuestra por qué.

Estado verificado el 2026-10-30 sobre el árbol de trabajo (`HEAD` `3725741` más cambios sin confirmar,
ver [`hardening.md`](hardening.md)). Las líneas pueden cambiar si el código cambia: el auditor trabajará
sobre el SHA congelado ([`decisions.md`](decisions.md), ADR-AUD-01).

**Alcance de esta revisión**: lectura de `core/src`, `ffi/src`, `android/app/src/main`, los workflows y
la configuración de build, más una ejecución de `cargo test --workspace --locked` (**92 pasan, 0 fallan,
1 ignorado**: 42 unitarios de `op-core`, 9 + 3 + 19 + 5 de integración y 14 de `op-ffi`), `cargo audit` y
`cargo deny --locked check`. **No** se han ejecutado los tests de Kotlin (no hay JDK en el `PATH` de
esta máquina), ni los instrumentados, ni ninguna prueba en dispositivo. **No es una revisión
criptográfica**: no se han comprobado la derivación ni los vectores más allá de lo que cubren los tests.

## Escala de severidad

La del proyecto ([`findings-process.md`](findings-process.md) §1): **Crítica**, **Alta**, **Media**,
**Baja**, **Info**. Las asignadas aquí son propuestas del proyecto; el auditor las revisa. Donde el
criterio de la escala y la explotabilidad real apuntan a niveles distintos, se explica.

## Resumen

| Severidad | Hallazgos |
|---|---|
| Crítica | 0 |
| Alta | 1 |
| Media | 3 |
| Baja | 11 |
| Info | 10 |
| **Total** | **25** |

| ID | Sev. | Área | Título | Estado |
|---|---|---|---|---|
| [ID-INT-01](#id-int-01) | Media | Rust | KDBX: el XML consume memoria cuadrática (DoS reproducido) | Abierto |
| [ID-INT-02](#id-int-02) | Baja | Rust | KDBX: la KDF de KeePass no pasa por el techo móvil de `.opvault` | Abierto |
| [ID-INT-03](#id-int-03) | Baja | Rust | Importadores: secretos en búferes que no se borran | Abierto |
| [ID-INT-04](#id-int-04) | Info | FFI | Residuos de salida de UniFFI aceptados | Aceptado |
| [ID-INT-05](#id-int-05) | Media | Android | El desbloqueo no cierra el `Vault` si falla después de `Vault.unlock` (conocido) | Abierto |
| [ID-INT-06](#id-int-06) | Baja | Android | Un solo elemento ilegible impide desbloquear el baúl | Abierto |
| [ID-INT-07](#id-int-07) | Baja | Android | Cuatro llamadas FFI sin captura de `InternalException` | Abierto |
| [ID-INT-08](#id-int-08) | Baja | Android | `lock()` no toma el `mutex`: carrera con una operación en curso | Abierto |
| [ID-INT-09](#id-int-09) | Baja | Android | `verifyPassword` no cuenta ni espera intentos | Abierto |
| [ID-INT-10](#id-int-10) | Info | Android | `atomicWrite` no fuerza el volcado a disco | Abierto |
| [ID-INT-11](#id-int-11) | Info | Android | `AutoBackup` traga `CancellationException` | Abierto |
| [ID-INT-12](#id-int-12) | Baja | Android | `readBackupFile` deja una copia en claro sin borrar | Abierto |
| [ID-INT-13](#id-int-13) | Info | Android | A7: la implementación y sus pruebas no alcanzan lo que describe el ADR | Parcial |
| [ID-INT-14](#id-int-14) | Media | Portapapeles | El borrado de los 30 s probablemente no actúa si la app perdió el foco | Abierto, sin verificar en dispositivo |
| [ID-INT-15](#id-int-15) | Info | Portapapeles | Sin marca de «sensible» en API 28-32 | Aceptado |
| [ID-INT-16](#id-int-16) | Alta | Autorrelleno | El dominio de una página lo declara cualquier app: no se exige un navegador | Abierto, sin reproducir en dispositivo |
| [ID-INT-17](#id-int-17) | Baja | Autorrelleno | `PendingSaves`: caducidad perezosa y sin vaciado al bloquear | Abierto |
| [ID-INT-18](#id-int-18) | Baja | Autorrelleno | `StructureParser` recorre el árbol de forma recursiva y sin límite | Abierto |
| [ID-INT-19](#id-int-19) | Info | Autorrelleno | Hasta 5 logins en claro viajan a `system_server` sin autenticación de dataset | Aceptado |
| [ID-INT-20](#id-int-20) | Info | Autorrelleno | La lista de sufijos públicos: sin prueba en dispositivo y sin actualización | Abierto |
| [ID-INT-21](#id-int-21) | Baja | Herramientas | La comprobación de que `cfg(fuzzing)` no entra en release no detecta nada | Abierto |
| [ID-INT-22](#id-int-22) | Info | Herramientas | `cargoBuild` no declara `rust-toolchain.toml` ni `.cargo/config.toml` como entradas | Abierto |
| [ID-INT-23](#id-int-23) | Info | Herramientas | Ficheros generados y *lockfiles* fuera de cobertura | Abierto |
| [ID-INT-24](#id-int-24) | Info | Herramientas | `fuzz/README.md` está desactualizado respecto a la CI y a los límites | Abierto |
| [ID-INT-25](#id-int-25) | Baja | Herramientas | El objetivo `import` no llega al analizador de la cabecera de KDBX | Abierto |

### Defectos ya conocidos antes de esta revisión

| Defecto | Dónde se registró | Hallazgo | Estado |
|---|---|---|---|
| El desbloqueo no cierra el `Vault` si `decryptOverview` falla después de `Vault.unlock` | Revisión previa (este documento) | ID-INT-05 | **Abierto** |
| Llamadas FFI sin captura de `InternalException` | [`decisions.md`](decisions.md) ADR-AUD-03 (8 sitios) | ID-INT-07 | Los 8 de la lista están cubiertos (commit `3725741`); **quedan 4 fuera de la lista** |
| Falta de memoria en Argon2 aborta el proceso | [`decisions.md`](decisions.md), «Riesgos que quedan abiertos» | ID-INT-02 | **Abierto**: el techo móvil lo reduce, no lo elimina |
| KDF que no se puede cancelar | Ídem | — | Abierto, fuera de alcance |
| Secretos en `String` de la JVM y Compose; `RustBuffer` de salida sin borrar | ADR-AUD-02 §6 | ID-INT-04 | Aceptado y documentado |
| `StructureParser` sin fuzzing | ADR-AUD-05 | ID-INT-18 | Pospuesto ([`fuzzing.md`](fuzzing.md)) |

---

## 1. Rust: `op-core`

### 1.1 Método

- `unsafe` está **prohibido** en todo el espacio de trabajo: `[workspace.lints.rust] unsafe_code =
  "forbid"` (`Cargo.toml:13`) y los tres crates heredan `[lints] workspace = true`.
  `grep -rn "unsafe" core/src ffi/src cli/src` no da resultados.
- Se ha revisado cada `unwrap`, `expect`, indexación y `as` de producción (antes de `#[cfg(test)]`).
  Comando: `for f in core/src/*.rs core/src/*/*.rs; do awk '/#\[cfg\(test\)\]/{exit} /\.unwrap\(\)|\.expect\(|panic!/{print FILENAME":"NR": "$0}' $f; done`.
  Resultado en `op-core`: **19 `expect` de producción** (más 2 en el módulo `cfg(fuzzing)`,
  `backup/mod.rs:168,173`), **0 `unwrap`, 0 `panic!`**. Todos están protegidos por una comprobación previa:

| Lugar | Por qué no puede fallar con entrada hostil |
|---|---|
| `backup/mod.rs:67` `u32::try_from(header_json.len())` | Cabecera que la propia app acaba de serializar (`write`), no entrada |
| `backup/mod.rs:92` `try_into` de 4 bytes | Después de `bytes.len() < fixed` (`:84-86`) |
| `crypto/stream.rs:52` `chunks.pop()` | Después de `ciphertext.len() < TAG_LEN` (`:47-49`): hay al menos un trozo |
| `vault/padding.rs:26` `prefix.try_into()` | `unpad` exige longitud múltiplo de 64 y no vacía (`:22-24`): hay ≥ 64 bytes |
| `import/kdbx.rs:90,95,100` `take(n)?.try_into()` | `take` devuelve exactamente `n` bytes o error (`:75-83`, con `checked_add`) |
| `import/kdbx.rs:195,200,206,357` | Guardas `data.len() >= 4`, `== 8`, `== 4`, `== 4` justo antes |
| `crypto/aead.rs:41`, `stream.rs:31,36` | Cifrado en memoria; solo falla si el tamaño supera el límite de la AEAD |
| `crypto/mod.rs:29` partes de AAD > 4 GiB | Las partes son constantes cortas y ids |
| `totp.rs:180`, `kdbx.rs:471` HMAC | HMAC acepta claves de cualquier longitud |
| `secret_key.rs:44,57` | Salida HKDF de 4 bytes y base32 ASCII |

- Tests (`cargo test --workspace --locked`, todos en verde): 42 unitarios de `op-core` (54 s: Argon2
  con 64 MiB en el perfil de pruebas), 9 de `tests/backup.rs`, 3 de `known_answers.rs`, 19 de
  `tests/vault.rs` y 5 de `tests/vectors.rs` (1 ignorado).

### 1.2 Zonas limpias y por qué

- **Formato `.opvault` y AEAD** (`backup/mod.rs`, `crypto/stream.rs`, `crypto/aead.rs`,
  `vault/mod.rs`): longitudes comprobadas antes de dividir; AAD con dominio, ids y revisión
  (`vault/mod.rs:63-76`); cabecera autenticada por el AAD del cuerpo (`backup/mod.rs:46-48`); la
  versión se comprueba tras la magia (`:86-92`) y `check_bounds` va **antes** de cualquier KDF (`:101`).
  El `secret_key_id` se compara antes de derivar (`vault/mod.rs:105-107`).
- **TOTP** (`totp.rs`): entrada ≤ 4096 bytes (`:76`), `period` entre 1 y 3600 (`:60`) —una división por
  cero es imposible—, dígitos entre 6 y 8 (`:57`), `10u32.pow(8)` sin desbordamiento, `get(..10)` sobre
  límite de carácter (`:81`).
- **Padding** (`vault/padding.rs`): `len > rest.len()` impide cualquier lectura fuera de rango (`:27`).

<a id="id-int-01"></a>
### ID-INT-01 · KDBX: el XML consume memoria cuadrática (DoS reproducido)

| Campo | Valor |
|---|---|
| Severidad | **Media** (DoS repetible con un fichero hostil, criterio de la escala) |
| Componente | `op-core`, importador KDBX |
| Evidencia | `core/src/import/kdbx.rs:648` (`group_uuids: Vec<String>`), `:660` (se añade un elemento por cada `<Group>`), `:710` (`entries.push((entry, group_uuids.clone()))`) |
| Estado | **Abierto** |

**Qué pasa.** Cada `<Entry>` guarda una **copia completa** de la pila de grupos abiertos
(`group_uuids.clone()`), y todas las copias se retienen hasta el final para decidir si el elemento
está en la papelera (`:722-729`). No hay límite de profundidad de anidamiento ni de número de
entradas más allá de los 32 MiB de entrada (`import/mod.rs:34`). El consumo es `24 B × profundidad ×
entradas` (el tamaño de un `String`).

**Reproducción** (no se ha tocado ningún fichero del repositorio): un crate de prueba fuera del
repositorio, con `op-core = { path = … }` y `RUSTFLAGS="--cfg fuzzing"`, que llama a
`op_core::import::kdbx_fuzzing::xml` con `<KeePassFile><Root>` + D × `<Group>` + E × `<Entry></Entry>` +
D × `</Group>`:

| Profundidad D | Entradas E | Tamaño del XML | Tiempo | RSS máximo |
|---|---|---|---|---|
| 1000 | 1000 | 30 040 B | 8 ms | 11 MB |
| 4000 | 4000 | 120 040 B | 158 ms | 388 128 KB |
| 8000 | 4000 | 180 040 B | 527 ms | 757 504 KB |

Medido en macOS arm64 con `ps` cada 20 ms; coincide con el cálculo (8000 × 4000 × 24 B = 768 MB). Con el
tope de 32 MiB la memoria necesaria **no tiene techo práctico**: es una extrapolación lineal, sin
ejecutar.

**Quién lo puede explotar.** El autor del `.kdbx`, que también elige la contraseña que se teclea: una
base «de un amigo, la contraseña es X». El proceso muere por falta de memoria (aborta aunque el
perfil sea `unwind`, ADR-AUD-03). El objetivo de fuzzing `kdbx_xml` (`-rss_limit_mb=2048`) no lo ha
encontrado porque exige anidamiento profundo **y** muchas entradas.

**Recomendación.** Guardar en cada entrada solo el índice o la cadena de ids de su grupo, o decidir
«está en la papelera» al cerrar el `<Entry>` con la pila actual; y fijar un tope de profundidad (por
ejemplo 64) devolviendo `Malformed`. Añadir un test con ese XML y una semilla a `fuzz/seeds/kdbx_xml/`.

<a id="id-int-02"></a>
### ID-INT-02 · KDBX: la KDF de KeePass no pasa por el techo móvil de `.opvault`

| Campo | Valor |
|---|---|
| Severidad | **Baja** (riesgo ya registrado en [`decisions.md`](decisions.md); vector que exige una base hostil) |
| Componente | `op-core` / `op-ffi` |
| Evidencia | `core/src/import/kdbx.rs:36-40,509-517` (1 GiB, 1000 pasadas, 64 carriles, `memoria × pasadas ≤ 16 GiB·pasada`); `ffi/src/lib.rs:542-574` (`parse_import` no llama a `check_mobile_kdf`); `VaultSession.kt:126-129,139,168` (la comprobación de RAM solo existe para `.opvault`); `ExternalImport.kt:54,62` (importación sin esa comprobación) |
| Estado | **Abierto** (el presupuesto de KDBX está implementado pero su aprobación está en la lista de decisiones humanas, nº 4) |

**Qué pasa.** Una copia `.opvault` está limitada a 512 MiB / 6 / 8 en Android (`ffi/src/lib.rs:33`),
pero una base KeePass puede pedir **1 GiB × 16 pasadas** y la importación la acepta (el test
`argon2_budget_accepts_the_edge_and_refuses_above_it` lo fija como válido). `argon2` 0.5 reserva la
memoria sin posibilidad de fallo recuperable: en un proceso de 32 bits o con poca memoria libre
**aborta**. No hay comprobación de RAM previa para este camino.

**Recomendación.** Decidir la política: aplicar a KDBX el mismo techo móvil (rechazando con un
mensaje claro), o al menos una comprobación de RAM antes de `parse_import`. Es una decisión humana
porque rechaza bases legítimas.

<a id="id-int-03"></a>
### ID-INT-03 · Importadores: secretos en búferes que no se borran

| Campo | Valor |
|---|---|
| Severidad | **Baja** (residuo no documentado; requiere leer memoria del proceso, A10) |
| Componente | `op-core`, importadores |
| Evidencia | `core/src/import/mod.rs:333` (`serde_json::Value` con todas las contraseñas), `:517` (`data.fill(0)` solo borra el `Vec<u8>` del `.1pux`, y no en la ruta de error del `?` de `:513-515`), `:227-250` (`Vec<Vec<String>>` del CSV); `core/src/import/kdbx.rs:399-400` (`hex: String` y `decode_hex` con el material del archivo de clave); `core/src/totp.rs` (`percent_decode` crea un `String` con el secreto) |
| Estado | **Abierto** |

**Qué pasa.** `docs/threat-model.md` (A15) dice «los bytes leídos se borran de memoria al analizarlos».
Eso es cierto para el búfer de entrada (`Zeroizing` en `op-ffi`, `fill(0)` en Kotlin), pero la
estructura **analizada** (el árbol JSON, los campos del CSV, las cadenas de KeePass tras
`reveal`, `kdbx.rs:578`) contiene las mismas contraseñas y se libera sin borrar. En el `.1pux` el
`fill(0)` ni siquiera se ejecuta si el JSON no es válido (`?` en `:513-515`).

**Recomendación.** No se puede borrar un `serde_json::Value` sin reescribirlo. Documentarlo como
residuo en el modelo de amenazas, y cuando sea barato envolver las cadenas finales en `Zeroizing`
(`Field` ya deriva `ZeroizeOnDrop`).

---

## 2. FFI: `op-ffi`

### 2.1 Método

Se ha leído `ffi/src/lib.rs` (903 líneas) y `ffi/src/secret.rs` (69) completos y se han ejecutado sus
14 tests (`cargo test -p op-ffi`, 14 pasan).

### 2.2 Zona limpia y por qué

No hay hallazgos nuevos en el código Rust de la frontera. Evidencia, punto por punto:

- **Ningún secreto en un tipo sin borrado**: `password` y `secret_key` son `SecretString` en
  `create` (`:334-336`), `unlock` (`:349-351`), `open_backup` (`:459-460`), `normalize_secret_key`
  (`:511`); `generate_secret_key` devuelve `SecretString` (`:505`); `FieldRecord.value`,
  `ItemDetailsRecord.notes` y `PasswordChangeRecord.value` lo son (`:145,151,160`); `totp_code(input)`
  también (`:588`). Los `Vec<u8>` con secretos se envuelven en `Zeroizing` al entrar: `vault_key`
  (`:366`, y el `[u8; 32]` intermedio, `:367`), el `.opvault` (`:461`), los ficheros importados
  (`:535,548`) y el archivo de clave (`:549`). Fuera de la lista, por diseño: `ItemOverviewRecord`
  (metadatos), `header_json` (sin datos de usuario) y `TotpCode.code` (6 a 8 dígitos de vida corta).
  `Debug` de `SecretString` imprime `<redacted>` (`secret.rs:38-42`, test `debug_hides_the_value`).
- **`Mutex` resistente al envenenamiento**: `guard()` recupera el guard (`:302-304`); `with` borra la
  clave, limpia el envenenamiento y devuelve `OpError::Internal` (`:309-322`); `lock` y `is_locked`
  usan `guard()` (`:437-443`). Tests: `lock_wipes_key_after_poisoned_mutex` (`:705`) y
  `with_after_poison_returns_internal_and_locks` (`:713`).
- **Techo de KDF antes de cualquier derivación**: `unlock` (`:355`) y `open_backup` (`:463`) llaman a
  `check_mobile_kdf` (`:472-481`) antes de `UnlockedVault::unlock`/`backup::open`;
  `Vault::create` solo acepta `KdfProfile` (`:333-337`), sin parámetros libres; `unlock_with_vault_key`
  no ejecuta KDF. Tests: `backup_above_the_mobile_ceiling_fails_fast` (`:801`),
  `mobile_ceiling_is_inclusive` (`:828`), `local_header_above_the_mobile_ceiling_is_refused_before_the_kdf`
  (`:867`), `backup_kdf_reports_the_header_cost` (`:844`).
- **Los errores no filtran datos**: `OpError::from` solo reenvía cadenas estáticas (`:59-75`);
  `E::KdfParams` se traduce a `InvalidInput`, no a `Internal`.
- **`expect` único**: `:382` (`serde_json::to_string(v.header())`) serializa una estructura de cadenas y
  números, imposible que falle.
- **Sin `unsafe`** (ver 1.1).

<a id="id-int-04"></a>
### ID-INT-04 · Residuos de salida de UniFFI aceptados

| Campo | Valor |
|---|---|
| Severidad | **Info** |
| Componente | `op-ffi` / UniFFI |
| Evidencia | `ffi/src/lib.rs:13-14` y `:385-387`; `ffi/src/secret.rs:8-11`, `:44-47` (`lower: \|secret\| secret.expose().to_owned()`) |
| Estado | **Aceptado** (ADR-AUD-02 §6) |

La copia `String` que `lower` entrega a UniFFI y el `RustBuffer` de salida se liberan sin borrar;
`vault_key_bytes` devuelve un `Vec<u8>` que Kotlin debe borrar (`VaultSession.kt:236-243` lo hace).
No hay gancho de borrado en UniFFI 0.32. Se registra para que el auditor lo vea como decisión y no
como descuido. `docs/crypto-spec.md` §10 **todavía no** menciona `SecretString` (ADR-AUD-02,
migración 4, pendiente).

---

## 3. Android: sesión, almacenamiento y ventanas

### 3.1 Método

Lectura completa de `VaultSession.kt`, `VaultStorage.kt`, `ItemDatabase.kt`, `DeviceKeyStore.kt`,
`BiometricKeyStore.kt`, `AutoBackup.kt`, `OverlayProtection.kt`, `RootSignals.kt`, `MainActivity.kt`,
`OpenPasswordApp.kt` y el manifiesto; `grep` de todos los `catch` y llamadas a `session.*`.

### 3.2 Zonas limpias y por qué

- **Manifiesto**: sin `INTERNET`; `allowBackup="false"`; `dataExtractionRules` excluye los cinco
  dominios en nube y transferencia (`xml/data_extraction_rules.xml`); solo `MainActivity` exportada y
  sin leer el intent; el servicio exige `BIND_AUTOFILL_SERVICE`. `VerifyManifest`
  (`build.gradle.kts:163-180`) lo hace cumplir en cada `assemble`.
- **Claves de Keystore**: AES-256-GCM, `setRandomizedEncryptionRequired(true)`,
  `setUnlockedDeviceRequired(true)`; la biométrica exige autenticación fuerte en **cada** uso
  (`setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)`, API 30+; en API 28-29 el sistema usa
  el comportamiento por defecto de `setUserAuthenticationRequired(true)`, **sin verificar** que sea
  por uso) y se invalida al dar de alta una biometría (`BiometricKeyStore.kt:40-56`).
- **Anti-tapjacking** (A7): protección por ventana y por diálogo en las tres actividades;
  `AlertDialog(` aparece una sola vez en `ui/Components.kt:195`
  (`grep -rn "AlertDialog(" android/app/src/main`).
- **Sesión tras un fallo interno**: `withVault` bloquea la sesión ante `InternalException` o un
  `Locked` inesperado (`VaultSession.kt:434-443`, `:468-469`), con 4 tests (`FfiFailureHandlingTest`).
- **Reinicio**: la contraseña se exige tras un reinicio y cada 14 días (`:219-228`).

<a id="id-int-05"></a>
### ID-INT-05 · El desbloqueo no cierra el `Vault` si falla después de `Vault.unlock` (conocido)

| Campo | Valor |
|---|---|
| Severidad | **Media**. El criterio de la escala (§1: «clave en memoria tras bloquear con el proceso vivo») apunta a **Alta**; la explotación exige leer la memoria del proceso (A10, fuera de alcance, «Info» según la misma escala). Se propone Media; **decide el auditor** |
| Componente | Android, `VaultSession` |
| Evidencia | `VaultSession.kt:107-108` (`unlock`), `:140-141` (`restore`), `:279-280` (`unlockWithBiometric`) |
| Estado | **Abierto** |

**Qué pasa.** En los tres caminos, `Vault.unlock`, `openBackup` o `Vault.unlockWithVaultKey` devuelven un
`Vault` con la clave en memoria, y a continuación `storage.items().map { … decryptOverview(it) }` (o
`contents.items.map {…}`) puede lanzar `OpException.Corrupted` (una fila dañada) o `InternalException`
(un *panic*). La variable local no se bloquea (`lock()`) ni se cierra (`close()`) en ninguna rama:
en `unlock` y `unlockWithBiometric` las ramas `catch` solo devuelven un `UnlockResult.Failed`; en
`restore` la excepción sale sin tocar `contents.vault`. La clave queda en memoria nativa hasta que
el `Cleaner` de UniFFI libere el objeto tras una recolección (`op_ffi.kt`, `UniffiCleaner`,
`build/generated/…:725`), momento no determinista. La interfaz muestra «bloqueado».

**Contraste**: `importBackup` sí lo hace bien (`:193-196`, `finally { source.lock(); source.close() }`)
y `verifyPassword` también (`use { it.lock() }`, `:203`).

**Recomendación.** En los tres sitios: `try { … } catch (t: Throwable) { unlocked.lock(); unlocked.close(); throw t }`
o un bloque `use`. Test unitario con un `Vault` falso cuyo `decryptOverview` lance.

<a id="id-int-06"></a>
### ID-INT-06 · Un solo elemento ilegible impide desbloquear el baúl

| Campo | Valor |
|---|---|
| Severidad | **Baja** (disponibilidad; requiere una fila dañada) |
| Componente | Android, `VaultSession` |
| Evidencia | `VaultSession.kt:108`, `:141`, `:280`: el `map { decryptOverview }` no tiene tolerancia por elemento; `:136` (`restore` exige que no haya baúl) |
| Estado | **Abierto** |

**Qué pasa.** Una fila con un bit cambiado (fallo de almacenamiento) hace que `decryptOverview`
lance `Corrupted` y que **todo el desbloqueo falle** con «Los datos están dañados». La app no ofrece
borrar el baúl ni restaurar sobre uno existente (`restore` exige `!storage.hasVault()`,
`VaultSession.kt:136`): el usuario debe borrar los datos de la app desde Ajustes de Android y
restaurar una copia. **Sin reproducir.**

**Recomendación.** Decidir la política: aislar el elemento dañado y avisar, o mantener el fallo total
y documentar la vía de recuperación.

<a id="id-int-07"></a>
### ID-INT-07 · Cuatro llamadas FFI sin captura de `InternalException`

| Campo | Valor |
|---|---|
| Severidad | **Baja** (no se conoce ningún *panic* alcanzable; el criterio de ADR-AUD-03 no se cumple) |
| Componente | Android, UI |
| Evidencia | `ui/vault/ItemDetailScreen.kt:77` (`produceState { value = session.details(entry) }`) y `:217` (`session.delete(entry)`); `ui/vault/ItemEditorScreen.kt:93` (`LaunchedEffect`, `session.details(existing)`); `autofill/AutofillAuthActivity.kt:172-176` (`pick`: `session.details`, `session.save`) |
| Estado | **Abierto** |

**Qué pasa.** ADR-AUD-03 exige que **toda** llamada FFI desde una corrutina de la UI capture
`InternalException` o `Exception`. Estos cuatro sitios no tienen `try` en absoluto, así que un *panic*
llega a la corrutina como excepción no capturada y **cierra la app**. `withVault` ya bloquea la
sesión antes de relanzar (`VaultSession.kt:439-442`), de modo que no hay fuga de clave: el efecto es
cierre de la app.

**Por qué no lo detecta el test.** `FfiFailureHandlingTest` (`:37-52`) busca `catch (e: OpException)`
sin captura amplia al lado; un sitio **sin ningún `catch`** no aparece, y es el caso de estos cuatro.

**Recomendación.** Envolverlos en `try/catch` de `InternalException` (y `Exception`), y ampliar el
test a todas las llamadas a `session.*` dentro de `launch`/`LaunchedEffect`/`produceState`.

<a id="id-int-08"></a>
### ID-INT-08 · `lock()` no toma el `mutex`: carrera con una operación en curso

| Campo | Valor |
|---|---|
| Severidad | **Baja** (carrera estrecha; **sin reproducir**) |
| Componente | Android, `VaultSession` |
| Evidencia | `VaultSession.kt:300-307` (`lock()`: `it.lock(); it.close(); vault = null`, sin `mutex`); `:419-420` (`backgroundLock` ejecuta `lock()` en el hilo principal); `:434-443` (`withVault` mantiene `mutex` y llama al `Vault` desde `Dispatchers.Default`); `build/generated/uniffi/…/op_ffi.kt:1451-1453` (tras `close()`, una llamada lanza `IllegalStateException("… object has already been destroyed")`) |
| Estado | **Abierto** |

**Qué pasa.** El autobloqueo (30 s en segundo plano, `ACTION_SCREEN_OFF`) llama a `lock()` desde el
hilo principal sin esperar a una operación que esté dentro de `withVault`. Si esa operación hace
varias llamadas FFI seguidas (`importExternal` itera por todos los elementos, `:339-347`), las
posteriores a `close()` lanzan `IllegalStateException`, que **no es** `OpException` ni
`InternalException`. `withVault` la relanza (`:441`) y los llamadores solo capturan esas dos (por
ejemplo `ExternalImport.kt:140-145`, `AutoBackup.kt:98-107` dentro de un `MainScope` sin manejador):
la corrutina falla y la app se cierra. La clave nativa sí se borra (`lock()` va primero), no hay fuga.

**Recomendación.** Que `lock()` espere al `mutex` (con un `tryLock` y diferir), o que `withVault`
capture `IllegalStateException` como `OpException.Locked`.

<a id="id-int-09"></a>
### ID-INT-09 · `verifyPassword` no cuenta ni espera intentos

| Campo | Valor |
|---|---|
| Severidad | **Baja** (requiere el baúl ya abierto y en manos del atacante) |
| Componente | Android, `VaultSession` |
| Evidencia | `VaultSession.kt:201-210` (sin `remainingWait()` ni contador) frente a `:103-117` (`unlock` sí); uso en `SettingsScreen.kt:333` («ver la clave secreta») |
| Estado | **Abierto** |

**Qué pasa.** La comprobación de contraseña de Ajustes ejecuta Argon2 completo cada vez, sin límite
ni espera. Quien tenga el teléfono con el baúl abierto (A2, no A1) puede probar contraseñas sin la
espera exponencial. Cada intento ejecuta Argon2 completo (coste no medido en esta revisión), lo que lo frena pero no lo limita.

**Recomendación.** Reutilizar el contador de fallos de `unlock`; o documentar que A2 con el baúl
abierto ya ve todo.

<a id="id-int-10"></a>
### ID-INT-10 · `atomicWrite` no fuerza el volcado a disco

| Campo | Valor |
|---|---|
| Severidad | **Info** (sin reproducir; la cabecera solo se escribe al crear o restaurar) |
| Componente | Android, `VaultStorage` |
| Evidencia | `VaultStorage.kt:72-76`: `tmp.writeBytes(bytes)` y `renameTo` sin `FileDescriptor.sync()`; usos: `:39` (cabecera), `:41` (clave secreta), `:57` (clave biométrica) |
| Estado | **Abierto** |

**Qué pasa.** Tras un corte de energía justo después de crear el baúl, el `rename` puede persistir
antes que los datos y dejar una cabecera vacía. La cabecera no cambia después, así que el riesgo se
limita a un baúl recién creado o restaurado.

<a id="id-int-11"></a>
### ID-INT-11 · `AutoBackup` traga `CancellationException`

| Campo | Valor |
|---|---|
| Severidad | **Info** |
| Componente | Android, `AutoBackup` |
| Evidencia | `AutoBackup.kt:108-121` (`catch (_: Exception)` alrededor de `withContext(Dispatchers.IO)`); `:62-67` (`disable()` borra el error y cancela el trabajo) |
| Estado | **Abierto** |

**Qué pasa.** Cancelar el trabajo (`schedule`, `disable`, `backupNow`) durante la escritura lanza
`CancellationException`, que `catch (_: Exception)` convierte en «No se pudo escribir…» y guarda en
`KEY_ERROR` (`fail`, `:148-152`) incluso después de `disable()`. Solo afecta al mensaje de la interfaz.

<a id="id-int-12"></a>
### ID-INT-12 · `readBackupFile` deja una copia en claro sin borrar

| Campo | Valor |
|---|---|
| Severidad | **Baja** (residuo; contradice parcialmente A15) |
| Componente | Android, UI |
| Evidencia | `ui/Components.kt:159` (`ByteArrayOutputStream`), `:167` (`out.toByteArray()` copia); `ExternalImport.kt:54-56,61-63` solo borran el `ByteArray` devuelto |
| Estado | **Abierto** |

**Qué pasa.** Para exportaciones en claro (CSV, JSON, `.1pux`) el `ByteArrayOutputStream` guarda su
propio búfer interno (hasta 2× el tamaño por el crecimiento) y `toByteArray()` otra copia. Solo la
última se borra. El texto con todas las contraseñas queda en el montón hasta el siguiente GC.

**Recomendación.** Leer directamente a un `ByteArray` del tamaño conocido (`available`/`length`) y
borrarlo; o aceptarlo y documentarlo en A15.

<a id="id-int-13"></a>
### ID-INT-13 · A7: la implementación y sus pruebas no alcanzan lo que describe el ADR

| Campo | Valor |
|---|---|
| Severidad | **Info** |
| Componente | Android, `OverlayProtection` |
| Evidencia | `androidTest/.../OverlayProtectionTest.kt` (solo `MainActivity`; el propio comentario dice «Pending: AutofillAuthActivity / SaveLoginActivity … and the dialogs»); `ui/AppRoot.kt:47` (`OverlayWarningBanner` solo en `MainActivity`); `security/OverlayProtection.kt:39,57-62` (un `Toast` y solo la primera vez por proceso) |
| Estado | **Parcial** |

La defensa está en las tres actividades y en los diálogos (código), pero ADR-AUD-06 pedía un banner
en las dos actividades de autorrelleno y una prueba instrumentada para cada actividad y diálogo. Hoy
hay una prueba (solo `MainActivity`) y un `Toast` único. Los 6 tests unitarios de `obscuredTouch` sí
existen. No se han ejecutado pruebas instrumentadas en esta revisión.

---

## 4. Portapapeles

Código: `security/SensitiveClipboard.kt` (45 líneas), usado desde la UI y limpiado desde
`OpenPasswordApp.kt:79` (apagado de pantalla).

<a id="id-int-14"></a>
### ID-INT-14 · El borrado de los 30 s probablemente no actúa si la app perdió el foco

| Campo | Valor |
|---|---|
| Severidad | **Media** (la escala diría **Alta**: «una defensa descrita en el modelo de amenazas … se salta»; se propone Media hasta confirmarlo en un dispositivo) |
| Componente | Android, portapapeles |
| Evidencia | `SensitiveClipboard.kt:34-39`: `if (clipboard.primaryClipDescription?.label == LABEL) clipboard.clearPrimaryClip()`, con el comentario «Android 10+ may deny clipboard access in the background: then the description is null»; `OpenPasswordApp.kt:78-79` |
| Estado | **Abierto**, **sin verificar en dispositivo** |

**Qué pasa.** El uso típico es copiar una contraseña y **cambiar a la otra app** para pegarla: en ese
momento OpenPassword ya no tiene el foco. Desde Android 10 solo la app con foco y el teclado por
defecto leen el portapapeles; el propio código lo reconoce y, sin acceso, `primaryClipDescription` es
`null`, la comparación falla y **no se borra nada**. El temporizador de 30 s y el receptor de
`ACTION_SCREEN_OFF` hacen lo mismo. Conclusión por el código y el comentario; **no probado en un
dispositivo**.

**Recomendación.** Probarlo en API 29, 33 y 36. Si se confirma: borrar también al volver a primer
plano, o sin comprobar la etiqueta (`clearPrimaryClip()` incondicional si se copió algo hace menos de
30 s), y no afirmar «con borrado» en A7.

<a id="id-int-15"></a>
### ID-INT-15 · Sin marca de «sensible» en API 28-32

| Campo | Valor |
|---|---|
| Severidad | **Info** |
| Componente | Android, portapapeles |
| Evidencia | `SensitiveClipboard.kt:23-27` (`EXTRA_IS_SENSITIVE` solo con `SDK_INT >= TIRAMISU`); `minSdk = 28` (`build.gradle.kts:27`) |
| Estado | **Aceptado** (limitación de la plataforma, sin alternativa pública) |

---

## 5. Autorrelleno

### 5.1 Método

Lectura de `OpAutofillService`, `StructureParser`, `FieldClassifier` (por encima), `LoginMatcher`,
`PublicSuffix`, `Datasets`, `PendingSaves`, `SavePlanner`, `AutofillAuthActivity` y
`SaveLoginActivity`; `LoginMatcherTest` (29 tests, con generadores deterministas `Random(20260630)` y
`Random(7)`).

### 5.2 Zona limpia y por qué: `LoginMatcher` y `PublicSuffix`

- `hostMatches` (`LoginMatcher.kt:43-48`): host exacto, o subdominio real de un dominio **no**
  público; sin lista, solo exacto (fail closed). Direcciones IP y literales con `:` nunca coinciden por
  sufijo (`:45,52`).
- `hostOf` usa `java.net.URI`, así que `https://google.com@evil.com` da `evil.com`; un nombre con `_`
  da `null` y no coincide (`:55-65`).
- Un login web nunca vale para una app y al revés (`:24-35`); una etiqueta suelta como `localhost`
  no se compara (`:70`).
- La lista (`PublicSuffix.kt`) se carga una vez, rechaza una lista con menos de 100 reglas (`:40`) y
  maneja reglas con comodín, excepciones y formas punycode (`:34-36`, `:44-47`).
- **No cubre** (ver ID-INT-16 y 20): el origen del `webDomain` y la actualización de la lista.

<a id="id-int-16"></a>
### ID-INT-16 · El dominio de una página lo declara cualquier app: no se exige un navegador

| Campo | Valor |
|---|---|
| Severidad | **Alta** (criterio de la escala: «el autorrelleno entrega credenciales a un sitio o app equivocados») |
| Componente | Android, autorrelleno |
| Evidencia | `autofill/StructureParser.kt:35` (`node.webDomain` del primer nodo que lo tenga) y `:53` (`webDomain?.let { FillTarget.Web(it) } ?: FillTarget.App(packageName)`); no hay lista de navegadores: `grep -rniE "chrome|browser|trusted|allowlist" android/app/src/main/kotlin/io/github/rldona/openpassword/autofill` solo devuelve tres comentarios (`OpAutofillService.kt:22`, `LoginMatcher.kt:6`, `FieldClassifier.kt:14`) y ninguna comprobación; `OpAutofillService.kt:38,41-42` y `Datasets.kt:37-43` entregan los datos |
| Estado | **Abierto**, **sin reproducir en dispositivo** |

**Qué pasa.** `ViewNode.webDomain` es un valor que **rellena la app de origen** con
`ViewStructure.setWebDomain`; no es un dato que el sistema verifique. `StructureParser` lo usa en
cuanto aparece (`:35`) y, si existe, descarta el paquete (`:53`). Una app maliciosa que el usuario abra
puede declarar `webDomain = "banco.example"` en su pantalla de acceso; `LoginMatcher` ofrecerá los
logins de `banco.example` y, con el baúl abierto, los entregará en `Dataset` directos
(`OpAutofillService.kt:36-44`) al pulsar el usuario la sugerencia. La defensa A12 («nombre de paquete
exacto, verificado por Android») no se aplica porque se elige la rama web.

**Condiciones**: el usuario debe instalar y abrir la app y tocar la sugerencia (aparece con el título
del login legítimo). La guía de Android para servicios de autorrelleno pide confiar en el dominio
solo de navegadores conocidos (lista de aplicaciones permitidas o *Digital Asset Links*). **No
reproducido**: sin dispositivo ni app de prueba. Hipótesis relacionada, también sin probar: en un
navegador, el `webDomain` de un nodo dentro de un `iframe` puede diferir del del primer nodo, y los
campos de ese `iframe` se rellenarían con el dominio de otro origen.

**Recomendación.** Aceptar `webDomain` solo si `structure.activityComponent.packageName` pertenece a
una lista de navegadores soportados (como hacen otros gestores de contraseñas), y en cualquier otro
caso usar `FillTarget.App`; contrastar `webDomain` por nodo con el de los campos que se rellenan; test
de invariantes en `LoginMatcherTest` (una app no navegadora con `webDomain` nunca coincide con un
login web).

<a id="id-int-17"></a>
### ID-INT-17 · `PendingSaves`: caducidad perezosa y sin vaciado al bloquear

| Campo | Valor |
|---|---|
| Severidad | **Baja** |
| Componente | Android, autorrelleno |
| Evidencia | `autofill/PendingSaves.kt:20-40` (`expire()` solo se llama desde `put` y `peek`; no hay temporizador); `SaveLoginActivity.kt:122` (única llamada a `remove`, solo `if (isFinishing)`); `VaultSession.kt:300-307` (`lock()` no toca `PendingSaves`); `grep -rn PendingSaves android/app/src/main` lo confirma |
| Estado | **Abierto** |

**Qué pasa.** La contraseña tecleada en otra app queda en un `String` del montón hasta 5 min **solo
si** otra llamada a `put`/`peek` ejecuta `expire()`; si no llega ninguna, permanece hasta que el
proceso muera. Si `SaveLoginActivity` se destruye sin `isFinishing` (p. ej. por falta de memoria), el
elemento no se elimina. Bloquear el baúl no lo vacía. README Android dice «La contraseña tecleada se
queda en la memoria de la app»; no dice cuánto.

**Recomendación.** Vaciar `PendingSaves` en `VaultSession.lock()` y caducar con un temporizador real.

<a id="id-int-18"></a>
### ID-INT-18 · `StructureParser` recorre el árbol de forma recursiva y sin límite

| Campo | Valor |
|---|---|
| Severidad | **Baja** (teórico: **sin reproducir**) |
| Componente | Android, autorrelleno |
| Evidencia | `autofill/StructureParser.kt:15-18` (`find`) y `:34-48` (`visit`): recursión por `getChildAt` sin profundidad máxima; la llamada de `onFillRequest` no está protegida (`OpAutofillService.kt:30`) |
| Estado | **Abierto** |

**Qué pasa.** La estructura la construye la app de origen. Un árbol con anidamiento muy profundo
podría agotar la pila y lanzar `StackOverflowError` (un `Error`, no una `Exception`) dentro del
proceso de OpenPassword, que es el mismo que la app. No se ha comprobado qué profundidad permite el
sistema al transmitir el `AssistStructure` ni si Android la acota antes.

**Recomendación.** Recorrido iterativo con tope de profundidad (p. ej. 100) y de nodos. Es el
candidato que justificaría fuzzing de `StructureParser` si se refactoriza a una abstracción de nodos
([`fuzzing.md`](fuzzing.md)).

<a id="id-int-19"></a>
### ID-INT-19 · Hasta 5 logins en claro viajan a `system_server` sin autenticación de dataset

| Campo | Valor |
|---|---|
| Severidad | **Info** (comportamiento de diseño; hay que documentarlo) |
| Componente | Android, autorrelleno |
| Evidencia | `OpAutofillService.kt:36-44` (con el baúl abierto: `MAX_DIRECT = 5`, `:89`) y `Datasets.kt:37-43` (`builder.setValue(id, AutofillValue.forText(…))` con usuario y contraseña); `setAuthentication` solo se usa con el baúl bloqueado (`Datasets.kt:56`) |
| Estado | **Aceptado** |

Con el baúl abierto, cada respuesta de relleno entrega a `system_server` (y de ahí al servicio de
sugerencias y a la app destino cuando el usuario elige) los datos de hasta 5 logins que coinciden,
no solo el elegido. Es la forma estándar de funcionar de Android sin autenticación de dataset, y se
amortigua porque la coincidencia es estricta y porque el baúl se bloquea. Conviene que el modelo de
amenazas lo diga explícitamente. Importa más cuanto más débil es la coincidencia (ID-INT-16).

<a id="id-int-20"></a>
### ID-INT-20 · La lista de sufijos públicos: sin prueba en dispositivo y sin actualización

| Campo | Valor |
|---|---|
| Severidad | **Info** |
| Componente | Android, autorrelleno |
| Evidencia | `PublicSuffix.kt:18` (carga por `classLoader.getResourceAsStream`), `:20` (`isAvailable`); `unzip -l android/app/build/outputs/apk/release/app-release.apk` incluye `public_suffix_list.dat` (338 012 B); versión `2026-10-28_13-15-55_UTC` (cabecera del fichero); `ls android/app/src/androidTest/kotlin/…` (3 clases, ninguna de autorrelleno) |
| Estado | **Abierto** (sin verificar en dispositivo) |

El recurso está en el APK, pero no hay prueba que confirme en un dispositivo que `getResourceAsStream`
lo encuentra con R8 activo (`isMinifyEnabled = true`, `build.gradle.kts:55`); si fallara, la
degradación sería a host exacto, silenciosa. La lista se cuenta como dato versionado sin proceso de
actualización: una lista vieja deja pasar como «dominio registrable» un sufijo público nuevo.

---

## 6. Herramientas, CI y build

### 6.1 Método

Lectura de `.github/workflows/ci.yml` y `fuzz-nightly.yml`, `deny.toml`, `.github/dependabot.yml`,
`android/app/build.gradle.kts`, `android/gradle/verification-metadata.xml`, `scripts/firmar-release.sh`
y `fuzz/`. Ejecución de `cargo audit` (0 vulnerabilidades, 139 *crates*) y `cargo deny --locked check`
(`advisories ok, bans ok, licenses ok, sources ok`).

### 6.2 Zonas limpias y por qué

- **CI con mínimo privilegio**: `permissions: contents: read` a nivel de *workflow*; el job `release`
  añade `id-token: write` y `attestations: write` solo en sí mismo (`ci.yml`).
- **Actions fijadas por SHA** con la versión en el comentario, y `cargo-deny`, `cargo-fuzz`,
  `cargo-ndk` y `cargo-cyclonedx` con versión (`ci.yml`; `grep -n "uses:" .github/workflows/*.yml` no
  muestra ninguna sin SHA). El detalle y los límites están en [`dependencies.md`](dependencies.md).
- **Gradle**: `verification-metadata.xml` con SHA-256 (sin firmas PGP).
- **`rust-toolchain.toml`** fija `1.99.1` y los tres objetivos de Android; el APK se compila con
  `--locked` (`build.gradle.kts:135`).

<a id="id-int-21"></a>
### ID-INT-21 · La comprobación de que `cfg(fuzzing)` no entra en release no detecta nada

| Campo | Valor |
|---|---|
| Severidad | **Baja** (falsa seguridad en un control documentado) |
| Componente | Herramientas, fuzzing |
| Evidencia | `fuzz/README.md` («cargo build -p op-core --release && ! strings target/release/libop_core.rlib \| grep -E 'seal_backup\|seal_item_part\|TEST_VAULT_KEY'»); control negativo: `strings -a target/release/libop_core.rlib \| grep -c "cost above the accepted maximum"` da **0** aunque esa cadena existe en el código, mientras que en `libop_ffi.so` da **1** |
| Estado | **Abierto** |

**Qué pasa.** Con `lto = true` el `.rlib` contiene *bitcode* de LLVM y `strings` ni siquiera lo lee
bien (`warning: … Not an int attribute`); el comando siempre «pasa». La comprobación real y que sí
funciona es sobre el binario final: `strings -a …/libop_ffi.so | grep -cE
'seal_backup|seal_item_part|TEST_VAULT_KEY'` da **0** (arm64, compilado a las 10:14 del 30/10) y la
cadena de control da 1.

**Recomendación.** Sustituirla en el README y en un paso de la CI por la comprobación sobre
`libop_ffi.so`, **con** el control positivo.

<a id="id-int-22"></a>
### ID-INT-22 · `cargoBuild` no declara `rust-toolchain.toml` ni `.cargo/config.toml` como entradas

| Campo | Valor |
|---|---|
| Severidad | **Info** |
| Componente | Build |
| Evidencia | `android/app/build.gradle.kts:183-187` (`include("Cargo.toml", "Cargo.lock", "core/Cargo.toml", "core/src/**", "ffi/Cargo.toml", "ffi/uniffi.toml", "ffi/src/**")`) |
| Estado | **Abierto** |

Un cambio de toolchain o de `rustflags` no invalida la tarea y Gradle puede reutilizar un `.so`
antiguo en local. No afecta a la CI (partida limpia). Relevante para quien reproduzca el build.

<a id="id-int-23"></a>
### ID-INT-23 · Ficheros generados y *lockfiles* fuera de cobertura

| Campo | Valor |
|---|---|
| Severidad | **Info** |
| Componente | Herramientas |
| Evidencia | `git status --short` muestra `core/op-core.cdx.json` (78 084 B) y `cli/opvault-cli.cdx.json` (95 577 B) sin seguimiento ni ignorados (`git check-ignore` no devuelve nada); `fuzz/Cargo.lock` (132 paquetes) tiene su propio espacio de trabajo y no lo recorre `cargo deny` (que corre en la raíz) |
| Estado | **Abierto** (los `.cdx.json` parecen restos de una prueba de `cargo cyclonedx`) |

Riesgo de confirmar por error dos SBOM que no se publican, y que el entorno de *fuzzing* no tenga
revisión de avisos. El segundo es de desarrollo y no entra en el binario.

<a id="id-int-24"></a>
### ID-INT-24 · `fuzz/README.md` está desactualizado respecto a la CI y a los límites

| Campo | Valor |
|---|---|
| Severidad | **Info** |
| Componente | Documentación |
| Evidencia | `fuzz/README.md`: «La CI ejecuta cada objetivo 60 s en cada push» frente a `ci.yml` (`-max_total_time=30`); «Argon2 ≤ 1 GiB y 1000 pasadas en KDBX» frente a `kdbx.rs:36-40` (hoy `memoria × pasadas ≤ 16 GiB·pasada`) |
| Estado | **Abierto** |

No se ha modificado (fuera del alcance de esta tarea).

<a id="id-int-25"></a>
### ID-INT-25 · El objetivo `import` no llega al analizador de la cabecera de KDBX

| Campo | Valor |
|---|---|
| Severidad | **Baja** (hueco de cobertura y documentación que afirma más de lo que hace) |
| Componente | Fuzzing, importador KDBX |
| Evidencia | `fuzz/fuzz_targets/import.rs:6-9` (`needs_password` y `parse(data, now)` sin credenciales); `core/src/import/mod.rs:62-75` (un `.kdbx` sin contraseña ni archivo de clave devuelve «this KeePass database needs its password» **antes** de llamar a `kdbx::parse`); `fuzz/README.md` («… y la cabecera de KDBX») |
| Estado | **Abierto** |

**Qué pasa.** El README y el comentario del objetivo dicen que `import` recorre «la cabecera de
KDBX». No es cierto: sin credenciales, `parse_with_credentials` rechaza el fichero en la puerta
(`mod.rs:70-75`) y nunca ejecuta `kdbx::parse`, donde están el `Cursor`, los campos de la cabecera y
`variant_dictionary` (`kdbx.rs:75-215`). Comprobado con los dos *seeds* de KeePass del propio
objetivo (`fuzz/seeds/import/keepassxc-3.1.kdbx` y `keepassxc-keyfile.kdbx`) y un programa de prueba
fuera del repositorio: `needs_password` da `true` y `parse` da «this KeePass database needs its
password» en los dos. Resultado: **ningún objetivo ejercita** el analizador de la cabecera externa,
`variant_dictionary`, el flujo de bloques con HMAC (KDBX 4), el flujo de bloques con hash (KDBX 3.1),
el gunzip ni la cabecera interna de KDBX 4 (`kdbx.rs:343-362`); `kdbx_xml` empieza después de todo eso.

**Recomendación.** Un gancho `cfg(fuzzing)` que llame a `kdbx::parse` con una contraseña fija y una
KDF mínima (o que pase por alto la derivación con una clave compuesta fija), igual que
`seal_item_part` hace con el AEAD. Mientras tanto, corregir el README. Ver [`fuzzing.md`](fuzzing.md).

---

## 7. Qué no se ha revisado

- La **criptografía** (derivación, longitudes, vectores): solo lo que ejercitan los tests.
- Las **dependencias** por dentro (`argon2`, `chacha20poly1305`, `quick-xml`, `zip`, `uniffi`):
  inventario y avisos en [`dependencies.md`](dependencies.md), sin revisión de su código.
- La **interfaz Compose** en general (estados, navegación); solo las llamadas a `session.*`.
- `FieldClassifier` y `SavePlanner`: leídos por encima, con tests.
- El **proceso de publicación** completo (F-Droid, firma) más allá de lo citado.
- Cualquier **prueba en dispositivo** (ID-INT-14, 16, 18 y 20 lo necesitan).
