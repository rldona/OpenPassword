# Auditoría interna previa

Revisión del código por el propio proyecto, antes de entregárselo al auditor externo. Una sección por
área. Cada hallazgo se puede **comprobar con `grep`, `sed -n` o un comando** que se indica; los que se
han reproducido llevan el procedimiento. Si un área está limpia, se dice y se demuestra por qué.

Los hallazgos se redactaron el 2026-10-30 sobre el árbol de trabajo (`HEAD` `3725741` más cambios sin
confirmar). Esos cambios y las correcciones de los hallazgos ID-INT-01, 05, 07, 16 y 25 quedaron
confirmados en `2bd56ce` («Fase 3: endurecimiento, cadena de suministro y paquete de auditoría»); el
estado de cada hallazgo se ha vuelto a contrastar con el código de ese commit. **Los números de línea
de las secciones «Evidencia» describen el código antes de la corrección** y ya no coinciden en los
hallazgos corregidos. Un segundo bloque de correcciones, **todavía sin commit** (sobre `2bd56ce`), cierra ID-INT-26 (nuevo) y
completa ID-INT-16 (su primera corrección era eludible), además de ajustar ID-INT-02, ID-INT-05 y ID-INT-21; está descrito en cada hallazgo. Las líneas pueden cambiar si el código cambia: el auditor trabajará sobre el SHA
congelado ([`decisions.md`](decisions.md), ADR-AUD-01).

**Alcance de esta revisión**: lectura de `core/src`, `ffi/src`, `android/app/src/main`, los workflows y
la configuración de build, más una ejecución de `cargo test --workspace --locked` (**95 pasan, 0 fallan,
1 ignorado**: 45 unitarios de `op-core`, 9 + 3 + 19 + 5 de integración y 14 de `op-ffi`), `cargo audit` y
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
| Alta | 2 |
| Media | 3 |
| Baja | 11 |
| Info | 10 |
| **Total** | **26** |

| ID | Sev. | Área | Título | Estado |
|---|---|---|---|---|
| [ID-INT-01](#id-int-01) | Media | Rust | KDBX: el XML consume memoria cuadrática (DoS reproducido) | **Corregido** (`2bd56ce`) |
| [ID-INT-02](#id-int-02) | Baja | Rust | KDBX: la KDF de KeePass no pasa por el techo móvil de `.opvault` | Abierto (presupuesto de KDBX hecho; falta la política frente al techo móvil) |
| [ID-INT-03](#id-int-03) | Baja | Rust | Importadores: secretos en búferes que no se borran | Abierto |
| [ID-INT-04](#id-int-04) | Info | FFI | Residuos de salida de UniFFI aceptados | Aceptado |
| [ID-INT-05](#id-int-05) | Media | Android | El desbloqueo no cierra el `Vault` si falla después de `Vault.unlock` (conocido) | **Corregido** (`2bd56ce`) |
| [ID-INT-06](#id-int-06) | Baja | Android | Un solo elemento ilegible impide desbloquear el baúl | Abierto |
| [ID-INT-07](#id-int-07) | Baja | Android | Cuatro llamadas FFI sin captura de `InternalException` | **Corregido** (`2bd56ce`) |
| [ID-INT-08](#id-int-08) | Baja | Android | `lock()` no toma el `mutex`: carrera con una operación en curso | Abierto |
| [ID-INT-09](#id-int-09) | Baja | Android | `verifyPassword` no cuenta ni espera intentos | Abierto |
| [ID-INT-10](#id-int-10) | Info | Android | `atomicWrite` no fuerza el volcado a disco | Abierto |
| [ID-INT-11](#id-int-11) | Info | Android | `AutoBackup` traga `CancellationException` | Abierto |
| [ID-INT-12](#id-int-12) | Baja | Android | `readBackupFile` deja una copia en claro sin borrar | Abierto |
| [ID-INT-13](#id-int-13) | Info | Android | A7: la implementación y sus pruebas no alcanzan lo que describe el ADR | Parcial |
| [ID-INT-14](#id-int-14) | Media | Portapapeles | El borrado de los 30 s probablemente no actúa si la app perdió el foco | Abierto, sin verificar en dispositivo |
| [ID-INT-15](#id-int-15) | Info | Portapapeles | Sin marca de «sensible» en API 28-32 | Aceptado |
| [ID-INT-16](#id-int-16) | Alta | Autorrelleno | El dominio de una página lo declara cualquier app: no se exige un navegador | **Corregido** (`2bd56ce`, completado en el bloque sin commit; sin probar en dispositivo) |
| [ID-INT-17](#id-int-17) | Baja | Autorrelleno | `PendingSaves`: caducidad perezosa y sin vaciado al bloquear | Abierto |
| [ID-INT-18](#id-int-18) | Baja | Autorrelleno | `StructureParser` recorre el árbol de forma recursiva y sin límite | Abierto |
| [ID-INT-19](#id-int-19) | Info | Autorrelleno | Hasta 5 logins en claro viajan a `system_server` sin autenticación de dataset | Aceptado |
| [ID-INT-20](#id-int-20) | Info | Autorrelleno | La lista de sufijos públicos: sin prueba en dispositivo y sin actualización | Abierto |
| [ID-INT-21](#id-int-21) | Baja | Herramientas | La comprobación de que `cfg(fuzzing)` no entra en release no detecta nada | Abierto |
| [ID-INT-22](#id-int-22) | Info | Herramientas | `cargoBuild` no declara `rust-toolchain.toml` ni `.cargo/config.toml` como entradas | Abierto |
| [ID-INT-23](#id-int-23) | Info | Herramientas | Ficheros generados y *lockfiles* fuera de cobertura | Parcial (`.gitignore`; falta `fuzz/Cargo.lock`) |
| [ID-INT-24](#id-int-24) | Info | Herramientas | `fuzz/README.md` está desactualizado respecto a la CI y a los límites | **Corregido** (documentación) |
| [ID-INT-25](#id-int-25) | Baja | Herramientas | El objetivo `import` no llega al analizador de la cabecera de KDBX | **Corregido** (`2bd56ce`) |
| [ID-INT-26](#id-int-26) | Alta | Autorrelleno | Una app rellenada puede inyectar el dominio en el `PendingIntent` mutable y recibir credenciales de cualquier sitio | **Corregido** (sin commit; sin probar en dispositivo) |

### Defectos ya conocidos antes de esta revisión

| Defecto | Dónde se registró | Hallazgo | Estado |
|---|---|---|---|
| El desbloqueo no cierra el `Vault` si `decryptOverview` falla después de `Vault.unlock` | Revisión previa (este documento) | ID-INT-05 | **Corregido** (`2bd56ce`) |
| Llamadas FFI sin captura de `InternalException` | [`decisions.md`](decisions.md) ADR-AUD-03 (8 sitios) | ID-INT-07 | Los 8 de la lista, cubiertos en `3725741`; los 4 que quedaban fuera de la lista, en `2bd56ce` (**corregido**) |
| Falta de memoria en Argon2 aborta el proceso | [`decisions.md`](decisions.md), «Riesgos que quedan abiertos» | ID-INT-02 | **Abierto**: el techo móvil lo reduce, no lo elimina, y KDBX no pasa por él |
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

- Tests (`cargo test --workspace --locked`, todos en verde): 45 unitarios de `op-core` (33 s en la última ejecución: Argon2
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
| Estado | **Corregido** en `2bd56ce`. |

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

**Corrección (`2bd56ce`).** `read_entries` ya no clona la pila de grupos por entrada (`core/src/import/kdbx.rs:808`) y el
XML descifrado tiene límites: `MAX_GROUP_DEPTH` 100 grupos abiertos, `MAX_XML_DEPTH` 256 elementos abiertos y `MAX_ENTRIES` 100 000
(`kdbx.rs:45-49`, comprobados en `:829`, `:836` y `:896`); al superarlos la importación falla con `InvalidInput` («cannot be imported»). Con ellos la memoria es lineal. Tests:
`deep_group_nesting_is_refused_before_it_costs_memory` (`kdbx.rs:1226`; el XML de 180 KB que antes pedía ~900 MB se rechaza),
`nesting_and_entry_limits_accept_their_edge` (`:1248`). Semillas nuevas: `fuzz/seeds/kdbx_xml/deep-groups-many-entries.xml` y
`depth-limit-edge.xml`. El mensaje del commit da 926 MB de RSS → 3,4 MB para ese XML (cifra del commit; **no se ha vuelto a medir** en esta revisión).

<a id="id-int-02"></a>
### ID-INT-02 · KDBX: la KDF de KeePass no pasa por el techo móvil de `.opvault`

| Campo | Valor |
|---|---|
| Severidad | **Baja** (riesgo ya registrado en [`decisions.md`](decisions.md); vector que exige una base hostil) |
| Componente | `op-core` / `op-ffi` |
| Evidencia | `core/src/import/kdbx.rs:36-42,544-555` (hoy 512 MiB, 1000 pasadas, 64 carriles y `memoria × pasadas ≤ 3 GiB·pasada`; antes, 1 GiB y 16 GiB·pasada); `ffi/src/lib.rs:542-574` (`parse_import` no llama a `check_mobile_kdf`); `VaultSession.kt:126-129,139,168` (la comprobación de RAM solo existe para `.opvault`); `ExternalImport.kt:54,62` (importación sin esa comprobación) |
| Estado | **Abierto** (el presupuesto de KDBX está implementado pero su aprobación está en la lista de decisiones humanas, nº 4) |

**Contraste en `2bd56ce`.** Sigue abierto: `parse_import` no llama a `check_mobile_kdf`, y la comprobación de RAM (`checkKdfFits`, `VaultSession.kt:126`, regla de `KdfMemory.kt`: memoria de la KDF ≤ la mitad de la RAM)
solo se aplica a copias `.opvault` (`restore` e `importBackup`). Lo que sí hay es el presupuesto conjunto de KDBX (`MAX_ARGON2_BYTES` 512 MiB y `MAX_ARGON2_WORK` 3 GiB·pasada, `kdbx.rs:36-42`), pendiente de aprobación humana (nº 4).
**Actualización (sin commit):** el techo de KDBX se bajó de 1 GiB / 16 GiB·pasada a 512 MiB / 3 GiB·pasada, igual que el techo móvil de `.opvault` (512 MiB × 6 pasadas; `ffi/src/lib.rs:33`); el comentario de `kdbx.rs:34-37` lo justifica así. Sigue sin comprobación de RAM previa y el hallazgo sigue abierto.

**Qué pasa.** Una copia `.opvault` está limitada a 512 MiB / 6 / 8 en Android (`ffi/src/lib.rs:33`),
pero (en `2bd56ce`) una base KeePass podía pedir **1 GiB × 16 pasadas** y la importación la aceptaba. Ya no: el test
`argon2_budget_accepts_the_edge_and_refuses_above_it` fija ahora como borde 512 MiB × 6 y rechaza 512 MiB × 7 y 1 GiB × 1 (`kdbx.rs:1191-1212`). `argon2` 0.5 reserva la
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
| Estado | **Corregido** en `2bd56ce`. |

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

**Corrección (`2bd56ce`).** Los tres caminos (`unlock`, `restore`, `unlockWithBiometric`) envuelven el `map { decryptOverview }`
en `VaultSession.discardOnFailure` (`VaultSession.kt`, `companion object`), que ante cualquier `Throwable` llama a `lock()` y `close()` del `Vault`
(`Vault.discard()`, mejor esfuerzo) y relanza el error original. `restore` también usa `discard()` en su `catch`. Tests
(JVM, no ejecutados en esta revisión): `FfiFailureHandlingTest`, «a failure after opening the vault releases it and rethrows»,
«a failing release does not hide the original error» y «success does not release the vault». **No** hay un test que ejerza los tres caminos con un `Vault` falso, solo la
función auxiliar.

**Ampliación (sin commit).** `VaultSession.create()` también libera el `Vault` recién creado si falla la persistencia (`clearItems`, `saveSecretKey`, `writeHeader`, `recordPasswordUnlock`) con `discardOnFailure(created::discard)` (`VaultSession.kt:94-101`).

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
| Estado | **Corregido** en `2bd56ce`. |

**Qué pasa.** ADR-AUD-03 exige que **toda** llamada FFI desde una corrutina de la UI capture
`InternalException` o `Exception`. Estos cuatro sitios no tienen `try` en absoluto, así que un *panic*
llega a la corrutina como excepción no capturada y **cierra la app**. `withVault` ya bloquea la
sesión antes de relanzar (`VaultSession.kt:439-442`), de modo que no hay fuga de clave: el efecto es
cierre de la app.

**Por qué no lo detecta el test.** `FfiFailureHandlingTest` (`:37-52`) busca `catch (e: OpException)`
sin captura amplia al lado; un sitio **sin ningún `catch`** no aparece, y es el caso de estos cuatro.

**Recomendación.** Envolverlos en `try/catch` de `InternalException` (y `Exception`), y ampliar el
test a todas las llamadas a `session.*` dentro de `launch`/`LaunchedEffect`/`produceState`.

**Corrección (`2bd56ce`).** Los cuatro sitios capturan ahora `OpException` e `InternalException` y muestran un mensaje
(`ItemDetailScreen.kt`: `produceState` y borrado; `ItemEditorScreen.kt`: carga, que además deja el formulario cerrado para no guardar un elemento vacío encima;
`AutofillAuthActivity.kt`: `pick`). **Límite que sigue**: `FfiFailureHandlingTest` sigue buscando solo `catch (e: OpException)` sin captura amplia, así que un sitio
nuevo **sin ningún `catch`** seguiría sin detectarse; la recomendación de ampliar el test no se ha aplicado.

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
| Estado | **Corregido**: la primera corrección (`2bd56ce`) era eludible y se cerró en el mismo bloque de trabajo (ver [ID-INT-26](#id-int-26) y la nota al final de este hallazgo); sin commit y sin probar en dispositivo. |

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

**Corrección (`2bd56ce`).** `StructureParser.targetFor` solo devuelve `FillTarget.Web` si `webDomain != null` **y** `browsers.isBrowser(packageName)`;
en otro caso, `FillTarget.App` (`autofill/StructureParser.kt:27-28`). `CachedBrowserCheck` (`autofill/BrowserCheck.kt`) considera navegador al paquete que
atiende a la vez enlaces `https://` y `http://` (consulta con `queryIntentActivities`, `<queries>` en el manifiesto, sin `QUERY_ALL_PACKAGES`), con caché de 5 min.
`LoginMatcher` empareja subdominios solo con un dominio registrable según `PublicSuffix` y exige coincidencia exacta si no hay lista o es una IP.
Tests: `BrowserCheckTest` (8) y los de invariantes de `LoginMatcherTest` (29; p. ej. `appsPretendingToBeBrowsersGetNothingFromWebLogins`), no ejecutados aquí.
**Límites de esa primera corrección**: una app que se declarase navegador (atendiese esos enlaces) seguía siendo creída; la hipótesis del `iframe` (el `webDomain` se toma del primer nodo que lo tiene, `StructureParser.kt:39`)
**no se ha tratado**; sin prueba en dispositivo.

**Segunda corrección (sin commit).** La comprobación de navegador **ya no se basa solo en el `intent-filter`**: declarar un filtro `VIEW`/`BROWSABLE` para `http` y `https` no exige ningún permiso, así que cualquier app lo cumplía.
`CachedBrowserCheck.isBrowser` (`autofill/BrowserCheck.kt:68-73`) acepta un paquete si está en `KnownBrowsers.PACKAGES` (`:26-39`) **o** si es el navegador por defecto (`resolveActivity` de `ACTION_VIEW` `https` con `MATCH_DEFAULT_ONLY`, `:83-87`; `android`, el selector del sistema, se descarta) **y** atiende `https` y `http` (`:61-65`).
`LoginMatcher` valida además el host como nombre ASCII (`[a-z0-9.-]+`, sin esquema, puerto, ruta ni Unicode; `LoginMatcher.kt:67-76`) y `PublicSuffix` captura `IOException` al leer la lista y falla cerrado (coincidencia exacta de host; `PublicSuffix.kt:21-25`).
Tests (JVM, no ejecutados aquí): `BrowserCheckTest` (13 `@Test`) y `LoginMatcherTest` (30 `@Test`).
**Riesgos residuales**: un navegador que el usuario elija como predeterminado y sea malicioso es creído; la lista de navegadores se queda desactualizada (un navegador nuevo y no predeterminado se trata como app); la hipótesis del `iframe` sigue sin tratar.

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

<a id="id-int-26"></a>
### ID-INT-26 · Una app rellenada puede inyectar el dominio en el `PendingIntent` mutable y recibir credenciales de cualquier sitio

| Campo | Valor |
|---|---|
| Severidad | **Alta** (criterio de la escala: «el autorrelleno entrega credenciales a un sitio o app equivocados») |
| Componente | Android, autorrelleno |
| Evidencia | Antes: la actividad leía el destino de los extras del `Intent` (`op.autofill.domain`, `op.autofill.package`, `op.autofill.username`, `op.autofill.password`; ver `Datasets.LEGACY_EXTRAS`, `Datasets.kt:76`) y el `PendingIntent` es mutable (`Datasets.kt:50-55`, `FLAG_MUTABLE`). Ahora: `autofill/AutofillRequestTokens.kt:16-54`, `Datasets.kt:47-59,70-76`, `AutofillAuthActivity.kt:87-98` |
| Estado | **Corregido** (sin commit; sin probar en dispositivo). Detectado en la revisión de la primera corrección de [ID-INT-16](#id-int-16). |

**Qué pasa.** `Dataset.setAuthentication` entrega el `IntentSender` a la **app que se rellena**. Como el
`PendingIntent` tiene que ser mutable (el sistema le añade la estructura), esa app puede dispararlo con
`Intent.fillIn` y añadir o sustituir extras. Si el dominio de destino viajaba en un extra, una app
maliciosa podía poner `op.autofill.domain = "banco.example"`, hacer que el usuario desbloquease y
eligiese un login, y recibir en su pantalla las credenciales de **cualquier** dominio. Eso eludía todo lo
que ID-INT-16 había cerrado (el origen del `webDomain` y la coincidencia estricta), porque el
dominio dejaba de salir de `StructureParser`.

**Condiciones**: el usuario debe abrir la app maliciosa, tocar la sugerencia de OpenPassword y elegir un
login (la actividad muestra el destino: «Para: …»). **No reproducido**: sin dispositivo ni app de prueba;
el vector se deduce de la documentación de `PendingIntent` y `Intent.fillIn`.

**Corrección (sin commit).** El `Intent` lleva solo un token: 16 bytes de `SecureRandom` en hexadecimal
(`AutofillRequestTokens.put`, `:25-30`). El destino (`FillTarget`) y los ids de campo se guardan en un
`ConcurrentHashMap` del proceso (`:23`), con TTL de 5 min (`TTL_MS`, `:50`) y de un solo uso
(`take` elimina la entrada, `:33-37`). `AutofillAuthActivity` borra los extras antiguos
(`Datasets.LEGACY_EXTRAS.forEach(intent::removeExtra)`) antes de leer nada, recupera la solicitud con el
token y **falla cerrado**: token ausente, desconocido, usado o caducado, o sin campos, llama a
`finish()` sin resultado (`AutofillAuthActivity.kt:89-98`). La solicitud resuelta se conserva en un
`ViewModel` para la rotación (`RequestHolder`, `:160-162`) y se borra al terminar (`:136-140`).
En la misma actividad, «recordar el login para esta app» no se ofrece ni se aplica si el paquete es un
navegador (`canRemember = target is FillTarget.App && !isBrowserApp`, `:102,124`; `PickLogin`, `:195`).
Tests (JVM, no ejecutados aquí): `AutofillRequestTokensTest` (7 `@Test`).

**Riesgos residuales**: el `PendingIntent` sigue siendo mutable (el sistema lo exige), por eso nada de
lo que llegue en él se trata como dato; el almacén está en memoria del proceso, así que lo lee quien ya
ejecute código en OpenPassword (A10, fuera de alcance); sin probar en dispositivo.

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

**Mitigación parcial (sin commit).** `core/src/lib.rs:20-22` añade `#[cfg(all(fuzzing, not(debug_assertions)))] compile_error!(…)`: una compilación `release` con `--cfg fuzzing` falla en vez de incluir los ganchos (`cargo fuzz build` mantiene `debug_assertions`). Esto no sustituye a la comprobación sobre el `.so`, que sigue sin cambiar; el hallazgo sigue **abierto**.

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
| Estado | **Parcial**: `*.cdx.json` está en `.gitignore` (`2bd56ce`) y los dos ficheros ya no existen; `fuzz/Cargo.lock` sigue sin revisión de `cargo deny` |

Riesgo de confirmar por error dos SBOM que no se publican, y que el entorno de *fuzzing* no tenga
revisión de avisos. El segundo es de desarrollo y no entra en el binario.

<a id="id-int-24"></a>
### ID-INT-24 · `fuzz/README.md` está desactualizado respecto a la CI y a los límites

| Campo | Valor |
|---|---|
| Severidad | **Info** |
| Componente | Documentación |
| Evidencia | `fuzz/README.md`: «La CI ejecuta cada objetivo 60 s en cada push» frente a `ci.yml` (`-max_total_time=30`); «Argon2 ≤ 1 GiB y 1000 pasadas en KDBX» frente a `kdbx.rs:36-42` (`memoria × pasadas ≤ 3 GiB·pasada` y 512 MiB) |
| Estado | **Corregido** (documentación). |

No se ha modificado (fuera del alcance de esta tarea).

**Corrección.** `fuzz/README.md` ya dice 30 s por objetivo en la CI (`ci.yml`, `-max_total_time=30`), 11 objetivos y el presupuesto conjunto de KDBX en lugar de «1 GiB y 1000 pasadas» (cifras actualizadas después a 512 MiB y 3 GiB·pasada).

<a id="id-int-25"></a>
### ID-INT-25 · El objetivo `import` no llega al analizador de la cabecera de KDBX

| Campo | Valor |
|---|---|
| Severidad | **Baja** (hueco de cobertura y documentación que afirma más de lo que hace) |
| Componente | Fuzzing, importador KDBX |
| Evidencia | `fuzz/fuzz_targets/import.rs:6-9` (`needs_password` y `parse(data, now)` sin credenciales); `core/src/import/mod.rs:62-75` (un `.kdbx` sin contraseña ni archivo de clave devuelve «this KeePass database needs its password» **antes** de llamar a `kdbx::parse`); `fuzz/README.md` («… y la cabecera de KDBX») |
| Estado | **Corregido** en `2bd56ce`. |

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

**Corrección (`2bd56ce`).** El objetivo `import` llama ahora también a `kdbx_fuzzing::file` (`fuzz/fuzz_targets/import.rs`), que ejecuta `read_header` y `open_payload`
con una clave transformada fija, sin la KDF. Además hay un objetivo nuevo, `kdbx_container`, que sella un KDBX 3.1/4 con esa clave y llega a los bloques con HMAC o con hash, el cifrado externo, el gunzip,
la cabecera interna y el XML; semillas en `fuzz/seeds/kdbx_container/` (5). Los ganchos son `kdbx_fuzzing::{file, container}` (`kdbx.rs`, módulo `fuzzing`). **No se ha ejecutado** `cargo fuzz` en esta revisión
(ver [`fuzzing.md`](fuzzing.md)).

---

## 7. Qué no se ha revisado

- La **criptografía** (derivación, longitudes, vectores): solo lo que ejercitan los tests.
- Las **dependencias** por dentro (`argon2`, `chacha20poly1305`, `quick-xml`, `zip`, `uniffi`):
  inventario y avisos en [`dependencies.md`](dependencies.md), sin revisión de su código.
- La **interfaz Compose** en general (estados, navegación); solo las llamadas a `session.*`.
- `FieldClassifier` y `SavePlanner`: leídos por encima, con tests.
- El **proceso de publicación** completo (F-Droid, firma) más allá de lo citado.
- Cualquier **prueba en dispositivo** (ID-INT-14, 16, 18 y 20 lo necesitan).
