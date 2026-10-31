# Alcance de la auditoría (scope of work)

Documento para el auditor. Describe qué se audita, con qué versión, cómo reproducir el código y la
build, qué preguntas concretas nos importan y qué esperamos recibir.

Estado: **pendiente** de completar los campos marcados `PENDIENTE` (SHA congelado, plazos, contactos).
Ver [`README.md`](README.md)).

## 1. Resumen

OpenPassword es un gestor de contraseñas **sin conexión** (la app no declara permiso de red),
**Android primero**, con licencia GPL-3.0-or-later. Toda la criptografía está en una biblioteca Rust
(`op-core`) que la app Android carga a través de UniFFI (`op-ffi`). Un solo mantenedor; sin
servidores ni cuentas.

## 2. Objetivos y activos a proteger

Objetivo: que un tercero independiente evalúe si la implementación cumple lo que prometen la
[especificación criptográfica](../../crypto-spec.md)) y el [modelo de amenazas](../../threat-model.md)), y
encuentre fallos que permitan a un atacante dentro de ese modelo leer o alterar secretos.

| Activo | Ejemplos | Sensibilidad (según el modelo de amenazas) |
|---|---|---|
| Secretos | contraseñas, CVV, PINs, frases semilla, claves API | Crítica |
| Credenciales de acceso | contraseña maestra, clave secreta (SK) | Crítica |
| Respaldos | ficheros `.opvault` | igual que los secretos |
| Metadatos | títulos, URLs, qué servicios usa el usuario | Alta |

Atacantes relevantes (A1–A16 del modelo de amenazas): ladrón con el móvil, quien obtiene un
`.opvault` o lo manipula, proveedor de nube, app maliciosa sin privilegios, web o app de *phishing*
contra el autorrelleno, cadena de suministro, ficheros importados o QR maliciosos. Están **fuera**
(modelo de amenazas): root malicioso o firmware alterado, *keylogger* y coacción.

Importante: dos defensas tienen eficacia limitada **por diseño**. La detección de root (A10) solo
avisa y se puede eludir. El borrado de secretos en la JVM tiene residuos aceptados (ADR-AUD-02).
Nos interesa saber si las limitaciones documentadas son las reales, no solo que existan.

## 3. Versión, código y build

| Dato | Valor |
|---|---|
| Repositorio | <https://github.com/rldona/OpenPassword> |
| Versión | `v0.2.0` (rama `release/0.2`, etiqueta firmada) |
| Commit congelado | **PENDIENTE** (SHA de 40 caracteres; es lo que se audita, no el nombre de la etiqueta) |
| Cambios posteriores | `v0.2.N` firmadas; se entrega `git diff v0.2.(N-1)..v0.2.N` (ver [ADR-AUD-01](decisions.md#adr-aud-01--estrategia-de-congelación))) |
| Licencia | GPL-3.0-or-later |

### Obtener el código

```sh
git clone https://github.com/rldona/OpenPassword.git
cd OpenPassword
git checkout <SHA-congelado>      # PENDIENTE
git tag -v v0.2.0                 # cuando exista la etiqueta firmada
```

La pre-release de GitHub `v0.2.0` adjuntará: `git archive` con su SHA-256, el APK sin firmar de la CI
y su SHA-256, las SBOM y la atestación de procedencia (ADR-AUD-04, **por implementar**; mientras no
estén, no se prometen).

### Entorno de build

Las versiones exactas son las de estos ficheros; no se repiten aquí para no desincronizarlas:

- Rust: [`rust-toolchain.toml`](../../../rust-toolchain.toml)) (incluye los tres *targets* de Android).
- JDK 17, Android SDK (plataforma 37), NDK `30.0.16248370`, `cargo-ndk 4.1.2`:
  [`android/README.md`](../../../android/README.md)) y [`ci.yml`](../../../.github/workflows/ci.yml)).
- Gradle: *wrapper* del repositorio (`android/gradlew`), con `distributionSha256Sum`.

### Build reproducible

El APK sin firmar es reproducible **en Linux** (la CI usa `ubuntu-24.04`). En macOS no coincide byte a
byte con el de Linux, y está documentado el motivo en [`docs/fdroid/README.md`](../fdroid/README.md)).
Por eso:

```sh
cd android
./gradlew :app:assembleRelease --console=plain
sha256sum app/build/outputs/apk/release/app-release-unsigned.apk
```

Debe coincidir con el SHA-256 que imprime la CI del mismo commit. Confirmar que el APK que se
distribuye (firmado con la clave del proyecto) es el de la CI sin la firma es parte del alcance
(sección 4).

## 4. Dentro del alcance

| Componente | Dónde | Qué se pide revisar |
|---|---|---|
| `op-core` | `core/` (`src/crypto`, `src/vault`, `src/backup`, `src/import`, `src/totp.rs`) | Criptografía, formato, importadores, TOTP |
| `op-ffi` | `ffi/` | Frontera UniFFI: tipos de secretos (`SecretString`), panics, límites de la KDF, `Mutex` de la sesión |
| App Android | `android/app/src/main` | Sesión, autorrelleno, Keystore y biometría, portapapeles, anti-tapjacking, aviso de root, almacenamiento, manifiesto |
| Formato `.opvault` v1 | [`docs/opvault-format.md`](../../opvault-format.md)), [`docs/crypto-spec.md`](../../crypto-spec.md)) | Diseño: derivación de claves, AAD, STREAM, versionado |
| Builds reproducibles y firma | `android/`, `.github/workflows/ci.yml`, `scripts/sign-release.sh`, `rust-toolchain.toml` | Que el APK publicado corresponde al código, y que la cadena de firma es sana |

Cualquier dependencia de terceros se evalúa **en su uso** (cómo la llama OpenPassword), no se
audita su código; el inventario va en [`dependencies.md`](dependencies.md)) (en preparación).

## 5. Fuera del alcance

- CLI `opvault` (`cli/`). Comparte `op-core`, de modo que el código del núcleo sí se revisa.
- Fase 4 de la propuesta (funciones futuras).
- iOS y escritorio (no existen todavía).
- Android o hardware comprometidos (root malicioso, firmware), *keyloggers* y coacción
  ([modelo de amenazas](../../threat-model.md))).
- Código de las dependencias, el sistema operativo y el Keystore (se audita su uso).
- Infraestructura de terceros (GitHub, F-Droid).
- Ataques de ingeniería social contra el mantenedor.

## 6. Preguntas concretas para el auditor

Cada una enlaza con la fuente que debe leer. Queremos una respuesta explícita («correcto», «hallazgo
F-nn» o «no he podido evaluarlo»).

### Criptografía y formato

1. **Contexto y AAD del AEAD.** ¿Los dominios y las partes de la AAD (`op/wrap/v1`, `op/item/v1`, …;
   [`crypto-spec.md` §6.2](../../crypto-spec.md)), `core/src/crypto/aead.rs`) impiden intercambiar,
   reordenar o reutilizar bloques entre contextos (elementos, clave del baúl, respaldos, versiones)?
   ¿Hay algún campo que debería estar autenticado y no lo está? ¿Es correcta la gestión de *nonces*?
2. **STREAM.** ¿El troceado, la marca de final y la autenticación de la cabecera
   (`core/src/crypto/stream.rs`, `core/src/backup`) detectan truncado, reordenación y extensión? ¿Hay
   riesgos en los casos límite (cero bloques, bloque exacto)?
3. **KDF y su acotación.** Argon2id con `KdfParams::MAXIMUM` en el formato y un techo más bajo en
   `op-ffi` ([ADR-AUD-07](decisions.md#adr-aud-07--límites-de-la-kdf-y-denegación-de-servicio)),
   `core/src/crypto/kdf.rs`). ¿Es correcta la composición contraseña maestra + SK + NFKD? ¿Son
   adecuados los perfiles `MINIMUM` y `RECOMMENDED`? ¿Hay un camino a Argon2 que evite `check_bounds`?
   ¿Queda un DoS por memoria o tiempo alcanzable con un fichero ajeno?
4. **Importación KDBX.** `core/src/import/kdbx.rs` (KDBX 3.1 y 4.x, Argon2, AES-KDF, XML). ¿Hay
   errores de análisis, DoS por parámetros o por XML (expansión, profundidad) o fuga de valores
   protegidos? Aviso: la lectura de KDBX 4 aún no se ha probado con un fichero real
   (`android/README.md`).

### Android

5. **Autorrelleno: coincidencias y sufijos públicos.** `autofill/LoginMatcher.kt`,
   `PublicSuffix.kt`, `StructureParser.kt`, `SavePlanner.kt`. ¿Puede una web o app de *phishing*
   conseguir credenciales de otro sitio (A12)? ¿Es correcta y suficiente la gestión de la lista de
   sufijos públicos y de los *hosts* anómalos (IDN, puertos, esquemas, `androidapp://`)?
6. **Keystore y biometría.** `security/DeviceKeyStore.kt`, `BiometricKeyStore.kt`, `Biometrics.kt`;
   [`crypto-spec.md` §9](../../crypto-spec.md)). ¿Se usan bien los parámetros de las claves (AES-GCM,
   autenticación por uso, invalidación al cambiar biometría, StrongBox)? ¿Se puede saltar la
   autenticación o degradarla a credencial de dispositivo?
7. **Borrado de secretos.** Al cruzar UniFFI (`ffi/src/lib.rs`, `ffi/src/secret.rs`) y en la JVM
   (`session/VaultSession.kt`); [ADR-AUD-02](decisions.md#adr-aud-02--secretos-al-cruzar-uniffi)) y
   [`crypto-spec.md` §10](../../crypto-spec.md)). ¿Los residuos aceptados son los únicos? ¿Hay copias en
   Rust o Kotlin que el contrato de propiedad no cubre?
8. **Panics y estado de la sesión.** ¿Un fichero hostil puede matar el proceso, dejar la sesión en un
   estado incoherente o dejar la clave en memoria tras `lock()`?
   ([ADR-AUD-03](decisions.md#adr-aud-03--panics-en-la-frontera-ffi))).
9. **Portapapeles.** `security/SensitiveClipboard.kt`: marca de sensible, borrado a los 30 s,
   fugas hacia servicios de historial o de sincronización.
10. **Detección de root y anti-tapjacking.** `security/RootSignals.kt`, `AndroidDeviceProbe.kt`,
    `OverlayProtection.kt` ([ADR-AUD-06](decisions.md#adr-aud-06--defensas-a7-y-a10))). ¿La protección
    de ventanas y diálogos es completa? ¿La detección de root es solo informativa y no abre
    superficie (por ejemplo, el bloque `<queries>`)?
11. **Almacenamiento y manifiesto.** SQLite con `secure_delete`, `allowBackup=false`, permisos,
    componentes exportados, `FLAG_SECURE`, exclusión del autorrelleno de otros servicios.
12. **Cadena de suministro y firma.** ¿El APK distribuido equivale al de la CI? ¿Son sanos
    `ci.yml`, `scripts/sign-release.sh` y la gestión de la clave de firma?

### Preguntas abiertas

13. ¿Qué parte de lo que afirma el [modelo de amenazas](../../threat-model.md)) no se sostiene con el
    código?
14. ¿Qué haría falta antes de recomendar que usuarios reales guarden datos reales?

## 7. Cómo compilar y probar

Comandos reales del repositorio (CI: [`.github/workflows/ci.yml`](../../../.github/workflows/ci.yml))):

```sh
# Núcleo y FFI (Rust)
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked

# Vectores dorados del formato v1 (se ejecutan también con el comando anterior)
cargo test -p op-core --test vectors

# Android
cd android
./gradlew :app:lintDebug :app:testDebugUnitTest :app:assembleDebug :app:assembleRelease --console=plain
./gradlew :app:connectedDebugAndroidTest    # requiere móvil o emulador
```

**Vectores de prueba.** [`core/tests/vectors/op-v1.json`](../../../core/tests/vectors/op-v1.json)) fija
cada byte del formato v1 (AAD, derivación, bloques sellados, respaldos). Son datos de prueba: sus
claves no protegen nada. Cualquier otra implementación debe pasar el mismo fichero. No se
regeneran salvo con una versión nueva del formato (`core/tests/vectors.rs`).

**Fuzzing.** Objetivos en `fuzz/fuzz_targets/`; instrucciones y descripción en
[`fuzz/README.md`](../../../fuzz/README.md)) (requiere nightly y `cargo-fuzz`). El módulo `cfg(fuzzing)`
usa una clave fija **solo para pruebas** y no entra en ninguna compilación normal.

Nota de entorno: el APK de referencia se compara en Linux. En macOS se puede compilar y probar,
pero el SHA-256 no coincidirá.

## 8. Entregables esperados

| Entregable | Contenido |
|---|---|
| Informe preliminar | Hallazgos con severidad, descripción, impacto, ubicación (fichero y línea sobre el SHA congelado) y recomendación |
| PoC | Reproducción mínima de cada hallazgo de severidad Media o superior (fichero `.opvault`, test, APK o guion) |
| Re-test | Verificación por el auditor de cada corrección, sobre una etiqueta `v0.2.N`, con estado por hallazgo (corregido, parcial, no corregido, aceptado) |
| Informe final publicable | Versión pública del informe tras el re-test, incluyendo alcance, metodología, hallazgos y su estado final |
| Resumen para usuarios | Una página sin tecnicismos (opcional) |

Formato de los hallazgos y escala de severidad: [`findings-process.md`](findings-process.md)). Se
prefiere un identificador estable por hallazgo (`<PROVEEDOR>-01`, …).

## 9. Confidencialidad, comunicación y plazos

- **Código:** público; no hay secreto que proteger en el código.
- **Hallazgos:** confidenciales hasta que haya corrección publicada o hasta la fecha de publicación
  pactada. Canal: avisos privados de GitHub Security Advisories del repositorio
  (`https://github.com/rldona/OpenPassword/security/advisories`, el mismo canal de
  [`SECURITY.md`](../../../SECURITY.md))). Hallazgos críticos: aviso inmediato al contacto técnico, sin
  esperar al informe.
- **Publicación:** el proyecto quiere publicar el informe final. El contrato debe reconocer ese
  permiso por escrito (ver [`vendors.md`](vendors.md))).
- **Acuerdo de confidencialidad (NDA):** solo si el proveedor lo exige y solo para la información no
  pública (clave de firma de release, accesos). **PENDIENTE** de decidir.

| Hito | Fecha |
|---|---|
| Congelación (`v0.2.0` firmada) | **PENDIENTE** |
| Arranque | **PENDIENTE** |
| Informe preliminar | **PENDIENTE** |
| Re-test | **PENDIENTE** |
| Informe final | **PENDIENTE** |

Calendario completo y condiciones de salida: [`budget-timeline.md`](budget-timeline.md)).

### Contactos

| Rol | Contacto |
|---|---|
| Mantenedor y contacto técnico | `@rldona` en GitHub; correo **PENDIENTE** |
| Contacto de seguridad / hallazgos | Avisos privados de GitHub del repositorio (ver arriba) |
| Contacto contractual | **PENDIENTE** (persona o entidad que firma) |
| Clave PGP para correo cifrado | **PENDIENTE** (no existe ninguna publicada en el repositorio) |
