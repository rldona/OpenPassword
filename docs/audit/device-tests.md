# Pruebas manuales en dispositivo

Plan de pruebas para cerrar, antes de la auditoría externa, lo que la revisión interna dejó como «sin
verificar en dispositivo» ([`internal-review.md`](internal-review.md), [`hardening.md`](hardening.md),
[`threat-model.md`](../threat-model.md)) y que no se puede comprobar en la JVM ni en la CI. Está escrito
para que lo ejecute una persona sin contexto previo y sirva de **evidencia para el auditor**.

> **Estado: sesión cerrada el 30-oct-2026; lo pendiente requiere emulador o dispositivo API 28 y no bloquea la contratación de la auditoría.**
> Ejecución parcial en **un único dispositivo, API 37** (ver [«Sesión del 30-oct-2026»](#sesion-2026-10-30)
> y [«segunda parte»](#sesion-2026-10-30-b)). **Pasan** DT-01 (con límites), DT-04a, DT-05 (solo depuración),
> DT-07 y las pruebas instrumentadas (17 tests, sección 3.2). **Falla DT-04b**, que confirma
> [ID-INT-14](internal-review.md#id-int-14), **aceptado como riesgo residual** por el responsable el
> 30-oct-2026. **Pendientes, con su motivo** (resumen en [«Pendientes al cierre de la sesión»](#pendientes-al-cierre)):
> DT-02 y DT-03 (emulador API 28-30), DT-12 (emulador o dispositivo API 28), DT-11 (emulador `userdebug`),
> la variante R8 de DT-05, DT-06 (navegador real), DT-08 (navegador predeterminado) y el resto sin ejecutar
> (DT-04c, DT-04d, DT-09, DT-10, DT-13 a DT-17), cuyas celdas dicen «pendiente». Los «resultados
> esperados» describen lo que el código pretende hacer (con `fichero:línea`); no son resultados. Si el
> dispositivo hace otra cosa, eso es lo que se anota.

<a id="pendientes-al-cierre"></a>
### Pendientes al cierre de la sesión (30-oct-2026)

| Prueba | Estado | Motivo | Necesita |
|---|---|---|---|
| DT-02 | Pendiente (`bloqueado`) | Sin imágenes de sistema API 28/30 ni binario de emulador en el equipo | Emulador API 28-30 |
| DT-03 | Pendiente | Diálogos en API 28-30, sin ejecutar | Emulador API 28-30 |
| DT-04c, DT-04d | Pendiente | Pantalla apagada y marca de sensible, sin ejecutar; DT-04 en API 29, 33 y 36 tampoco | Dispositivos API 29, 33 y 36 |
| DT-05, variante R8 | Pendiente | Solo se ejecutó la build de depuración | Build de release con R8 |
| DT-06 | Pendiente | Navegador real (Chrome), sin ejecutar | Dispositivo con Chrome |
| DT-08 | Pendiente | Navegador predeterminado malicioso, sin ejecutar | Dispositivo físico |
| DT-09, DT-10 | Pendiente | Autorrelleno completo y «recordar», sin ejecutar | Dispositivo físico |
| DT-11 | Pendiente | Root: requiere emulador `userdebug` | Emulador `google_apis` `userdebug` |
| DT-12 | Pendiente (`bloqueado`) | Android 9: sin emulador ni imagen; el teléfono es API 37 | Emulador o dispositivo API 28 |
| DT-13 | Pendiente | KDBX 4 real, sin ejecutar | KeePassXC y dispositivo |
| DT-14, DT-15, DT-16, DT-17 | Pendiente | KDF/RAM, copias, bloqueo automático y TOTP, sin ejecutar | Dispositivo físico |

Redactado el 2026-10-30 sobre `HEAD` `6c9a587` («Docs: pausar la publicación en F-Droid»). Las líneas
citadas son de ese commit y se desplazan si el código cambia: el nombre del símbolo es la referencia
estable. La versión que se audita (`v0.2.0`, ver [`README.md`](README.md)) fija qué commit hay que
probar (sección 7, «Criterio de cierre»).

## Índice

1. [Reglas de seguridad](#1-reglas-de-seguridad)
2. [Preparación](#2-preparación)
3. [Registro de resultados](#3-registro-de-resultados)
4. [APKs de prueba](#4-apks-de-prueba)
5. [Pruebas](#5-pruebas): [DT-01](#dt-01) · [DT-02](#dt-02) · [DT-03](#dt-03) · [DT-04](#dt-04) ·
   [DT-05](#dt-05) · [DT-06](#dt-06) · [DT-07](#dt-07) · [DT-08](#dt-08) · [DT-09](#dt-09) ·
   [DT-10](#dt-10) · [DT-11](#dt-11) · [DT-12](#dt-12) · [DT-13](#dt-13) · [DT-14](#dt-14) ·
   [DT-15](#dt-15) · [DT-16](#dt-16) · [DT-17](#dt-17)
6. [Automatización](#6-automatización)
7. [Criterio de cierre](#7-criterio-de-cierre)
8. [Fuera del alcance de este plan](#8-fuera-del-alcance-de-este-plan)

### Qué cubre cada prueba

| Prueba | Qué se verifica | Hallazgo o amenaza |
|---|---|---|
| [DT-01](#dt-01) | Anti-tapjacking en Android 12+ (`setHideOverlayWindows`) | A7; [ID-INT-13](internal-review.md#id-int-13) |
| [DT-02](#dt-02) | Anti-tapjacking en API 28-30 (`filterTouchesWhenObscured`, aviso, toque parcialmente tapado) | A7; ID-INT-13 |
| [DT-03](#dt-03) | Lo mismo sobre diálogos (`ProtectedAlertDialog`) | A7; ID-INT-13 |
| [DT-04](#dt-04) | Borrado del portapapeles a los 30 s y marca de «sensible» | A7; [ID-INT-14](internal-review.md#id-int-14), [ID-INT-15](internal-review.md#id-int-15) |
| [DT-05](#dt-05) | La lista de sufijos públicos carga y se aplica en el dispositivo (con R8) | [ID-INT-20](internal-review.md#id-int-20); A12, A17 |
| [DT-06](#dt-06) | `webDomain` de un navegador real; token hasta la actividad correcta | A17; [ID-INT-16](internal-review.md#id-int-16) |
| [DT-07](#dt-07) | Una app que se declara navegador no recibe datasets web | A17; ID-INT-16 (segunda corrección) |
| [DT-08](#dt-08) | Navegador predeterminado malicioso (riesgo residual documentado) | A17 |
| [DT-09](#dt-09) | Autorrelleno de extremo a extremo y token tras rotar | A12, A18; [ID-INT-26](internal-review.md#id-int-26) |
| [DT-10](#dt-10) | «Recordar para esta app» solo en apps | ID-INT-26 (`AutofillAuthActivity.kt:102,124`) |
| [DT-11](#dt-11) | Aviso de root: aparece, no bloquea, se descarta | A10; ADR-AUD-06 |
| [DT-12](#dt-12) | Biometría en Android 9 (arreglo de `Biometrics.kt`) | Arreglo de `2c6ba2d` («biometría en Android 9»); clave biométrica en API 28-29, «sin verificar» en [`internal-review.md`](internal-review.md) §3 |
| [DT-13](#dt-13) | Importar KDBX 4 con un fichero real | README de Android; [ID-INT-02](internal-review.md#id-int-02) |
| [DT-14](#dt-14) | Techo de KDF y RAM sin cerrar la app | ADR-AUD-07; riesgo abierto de aborto por memoria |
| [DT-15](#dt-15) | Copia automática y restauración | A4, A5 (integridad de la copia); funcionalidad |
| [DT-16](#dt-16) | Bloqueo automático (5 min, 30 s, pantalla apagada) | A13 |
| [DT-17](#dt-17) | TOTP: QR, imagen y `otpauth://` | A16 |

---

## 1. Reglas de seguridad

**El teléfono del responsable tiene una bóveda con datos reales. Estas pruebas incluyen pasos
destructivos** (borrar elementos, limpiar los datos de la app, restaurar copias, cambiar el servicio de
autorrelleno y el navegador predeterminado, importar ficheros hostiles).

1. **Nunca se prueba sobre la bóveda real.** Antes de nada, se exporta una copia de la bóveda real
   (sección 2.3) y se guarda fuera del teléfono. Después se crea una **bóveda de pruebas** nueva y
   aislada (sección 2.4). Todas las pruebas se hacen sobre ella.
2. **Aislamiento por paquete.** La app de depuración se instala con otro identificador
   (`io.github.rldona.openpassword.debug`; `android/app/build.gradle.kts:52`, `applicationIdSuffix`), así
   que tiene sus propios datos y sus propias claves de Keystore y **no toca** la app oficial
   (`io.github.rldona.openpassword`). Pero:
   - **No instales el APK de release oficial** en el teléfono con datos reales para estas pruebas.
   - Si la bóveda real del teléfono vive **en el paquete `.debug`** (se usa la build de depuración a
     diario), **no se hacen las pruebas en ese teléfono**: usa otro dispositivo, un emulador o un usuario
     secundario de Android (Ajustes → Sistema → Varios usuarios, si el fabricante lo ofrece). Las
     comprobaciones de la sección 2.2 lo detectan.
3. **Sin root en el teléfono principal.** Ningún paso lo necesita. La prueba de root (DT-11) se hace en un
   emulador `userdebug` o en un dispositivo dedicado, nunca en el teléfono principal.
4. **Nada de apps de terceros dudosas.** Para las pruebas de superposición y de navegador falso se
   compilan dos APK propios y mínimos (sección 4). No se descarga ningún APK de ningún sitio. Las únicas
   herramientas externas son las oficiales (Android SDK, Chrome del sistema) y KeePassXC (DT-13).
5. **Cambios de ajustes del sistema que hay que deshacer** (ver 2.7): servicio de autorrelleno,
   navegador predeterminado, tiempo de apagado de pantalla y rotación. Se anota el valor original antes
   de cambiarlo.
6. **Las contraseñas de prueba son inventadas** y distintas de cualquier real. Si una captura o un
   `logcat` contiene un dato real (notificaciones, nombres de redes Wi-Fi, otras apps), se recorta o se
   descarta antes de entregarlo.

## 2. Preparación

### 2.1 Herramientas en el ordenador

- Android SDK con `adb` (`platform-tools`) y, para emuladores, `cmdline-tools` y `emulator`.
- JDK 17 o superior (el de [`android/README.md`](../../android/README.md) es 17), para compilar la app y
  los APK de prueba.
- Para compilar la app: Rust con los targets de Android, `cargo-ndk` y el NDK indicados en
  [`android/README.md`](../../android/README.md) («Compilar»).
- KeePassXC (DT-13) y, opcionalmente, `qrencode` (DT-17).

```sh
export OP_REPO="$HOME/workspace/OpenPassword"        # ajusta a tu clon
export PKG=io.github.rldona.openpassword.debug         # app de depuración (la que se prueba)
adb devices -l                                         # un solo dispositivo; apunta el serial
export ANDROID_SERIAL=<serial>                         # así adb y Gradle no se equivocan de dispositivo
```

> Con más de un dispositivo conectado, `adb` sin `ANDROID_SERIAL` falla o, peor, elige uno. Comprueba
> **siempre** que `adb devices` muestra solo el dispositivo de pruebas antes de ejecutar nada.

### 2.2 Qué hay instalado (antes de tocar nada)

```sh
adb shell pm list packages | grep -i openpassword
adb shell dumpsys package io.github.rldona.openpassword 2>/dev/null | grep -E "versionName|versionCode"
adb shell dumpsys package "$PKG" 2>/dev/null | grep -E "versionName|versionCode"
```

- Si aparece solo `io.github.rldona.openpassword` (oficial): la bóveda real está ahí y la app de
  depuración la dejará intacta. Sigue.
- Si aparece `io.github.rldona.openpassword.debug` con datos que no son de pruebas: **para** (regla 2).

### 2.3 Exportar una copia de la bóveda real

Solo si el dispositivo tiene datos reales.

1. Abre la app **oficial** → Ajustes → **Exportar copia cifrada**. Guarda el `.opvault` en una carpeta que
   puedas copiar al ordenador.
2. Cópiala al ordenador y comprueba que se lee su cabecera (no pide credenciales):
   ```sh
   cd "$OP_REPO" && cargo run -q -p opvault-cli -- inspect /ruta/a/openpassword-AAAA-MM-DD.opvault
   ```
3. Comprueba que la abres de verdad con tu contraseña y tu clave secreta (`opvault decrypt`, ver
   [`README.md`](../../README.md) del proyecto). Sin esta comprobación, no sigas: una copia que no se abre
   no es una copia.
4. Guárdala fuera del teléfono. Es la red de seguridad si algo sale mal.

### 2.4 Crear la bóveda de pruebas

1. Compila e instala la app de depuración (sección 2.5) y ábrela: aparece la bienvenida.
2. Crea una bóveda con una contraseña **de usar y tirar** (por ejemplo `prueba-dispositivo-1`) y apunta
   la clave secreta que muestra la app en un papel o fichero **etiquetado «PRUEBAS»**. No reutilices
   nada de la bóveda real.
3. Crea estos elementos de prueba (tipo «Login»). La URL se escribe tal cual:

   | Título | URL | Usuario | Contraseña | Se usa en |
   |---|---|---|---|---|
   | `alice.github.io` | `https://alice.github.io` | `alice` | `Prueba-pw-1` | DT-05 |
   | `Sufijo github.io` | `https://github.io` | `suffix` | `Prueba-pw-2` | DT-05 |
   | `GitHub` | `https://github.com` | `testuser` | `Prueba-pw-3` | DT-06 |
   | `Wikipedia` | `https://wikipedia.org` | `testwiki` | `Prueba-pw-4` | DT-05 (control), DT-06 |
   | `Banco falso` | `https://bank.example` | `victima` | `Prueba-pw-5` | DT-07, DT-08, DT-10 |
   | `Borra-me` | (vacía) | `x` | `Prueba-pw-6` | DT-03 |
   | `Portapapeles` | (vacía) | `clip` | `Prueba-pw-7` | DT-04 |

   Cada contraseña es distinta para saber, al verla aparecer, de qué elemento viene.

### 2.5 Compilar e instalar el APK de depuración

Desde el commit que se va a probar, con el árbol **limpio** (`git status --short` sin salida). El APK no
lleva el commit dentro (`BuildConfigInfo.kt` solo expone `versionName`), así que **se anota aquí**:

```sh
cd "$OP_REPO"
git status --short                    # debe estar vacío; si no, anótalo en la ficha
git rev-parse HEAD                    # commit probado: cópialo en la ficha
cd android
./gradlew :app:assembleDebug          # añade -PrustAbis=arm64-v8a para compilar solo esa ABI
shasum -a 256 app/build/outputs/apk/debug/app-debug.apk   # huella del APK: cópiala en la ficha
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell dumpsys package "$PKG" | grep -E "versionName|versionCode|lastUpdateTime"
```

`adb install -r` reinstala conservando los datos de la **misma** app (aquí, la de depuración). Para
partir de cero, `adb shell pm clear "$PKG"` (solo si el paquete `.debug` contiene únicamente la bóveda de
pruebas; ver 2.2).

Para comprobar que lo instalado es lo compilado (`sha256sum` existe en Android 9+; si no, `adb pull`):

```sh
adb shell pm path "$PKG"                                  # package:/data/app/.../base.apk
adb shell sha256sum "$(adb shell pm path "$PKG" | head -1 | cut -d: -f2 | tr -d '\r')"
```

### 2.6 Ficha del dispositivo

Una ficha por dispositivo, pegada en la tabla de la sección 3 o en un fichero `ficha-dispositivo.txt` junto
a la evidencia.

```sh
{
  echo "fecha: $(date -u +%FT%TZ)"
  for p in ro.product.manufacturer ro.product.model ro.build.version.release ro.build.version.sdk \
           ro.build.version.security_patch ro.product.cpu.abilist ro.build.type ro.build.tags \
           ro.build.fingerprint ro.config.low_ram; do
    echo "$p=$(adb shell getprop "$p" | tr -d '\r')"
  done
  adb shell grep MemTotal /proc/meminfo | tr -d '\r'
  adb shell pm list features | tr -d '\r' | grep -i -E "strongbox|fingerprint|face"
  echo "versión: $(adb shell dumpsys package "$PKG" | grep versionName | head -1 | tr -d '\r')"
  echo "commit: $(git -C "$OP_REPO" rev-parse HEAD)"
} | tee ficha-dispositivo.txt
```

Se anota: **modelo**, **versión de Android y API** (`ro.build.version.sdk`), **ABI**
(`ro.product.cpu.abilist`), **RAM** (`MemTotal`; con menos de 3 GiB la app usa el perfil de KDF `MINIMUM`,
`OpenPasswordApp.kt:88-91`), **StrongBox** (una línea `feature:android.hardware.strongbox_keystore` en la
salida; si no aparece, no hay), **`versionName`** (actualmente `0.1.0` en `android/app/build.gradle.kts:30`,
aunque el paquete se llame `v0.2.0`: se anota lo instalado, no lo esperado), **commit**, **huella SHA-256
del APK** y el idioma del sistema.

### 2.7 Ajustes del sistema que se cambian: anota el original

```sh
adb shell settings get secure autofill_service              # servicio de autorrelleno actual
adb shell cmd role get-role-holders android.app.role.BROWSER   # navegador predeterminado (API 29+)
adb shell settings get system screen_off_timeout            # ms
adb shell settings get system accelerometer_rotation
adb shell settings get system user_rotation
```

Al terminar todas las pruebas, restaura cada uno desde Ajustes del sistema: *Autocompletar* (vuelve a tu
servicio de siempre), *Apps predeterminadas → App de navegador*, tiempo de apagado de pantalla y rotación.

### 2.8 Evidencia

- **Capturas y vídeo de OpenPassword salen en negro**: la app usa `FLAG_SECURE` en sus tres actividades
  (`MainActivity.kt:26`, `AutofillAuthActivity.kt:81`, `SaveLoginActivity.kt:74`). Es el comportamiento
  esperado, no un fallo. Para fotografiar OpenPassword usa **otra cámara** (otro móvil) o una grabación
  del dispositivo con una cámara externa. Las capturas de otras apps (Chrome, los APK de prueba, el
  desplegable de autorrelleno del sistema) sí funcionan: `adb exec-out screencap -p > captura.png`.
- **`logcat`**: `adb logcat -d -t 500 > logcat-DT-XX.txt`. Para cierres inesperados,
  `adb logcat -b crash -d > crash-DT-XX.txt`. Revísalo antes de compartirlo (puede haber datos de otras
  apps). No uses `adb bugreport` como evidencia: incluye datos personales del teléfono.
- **Carpeta de evidencia**, fuera del repositorio (son binarios): `evidencia-dt/AAAA-MM-DD-<modelo>/` con
  ficheros nombrados `DT-XX-<n>-<descripción>.<ext>`. Al terminar:
  ```sh
  cd evidencia-dt && find . -type f ! -name SHA256SUMS -exec shasum -a 256 {} + > SHA256SUMS
  ```
  En la tabla se cita el nombre del fichero; el resumen y `SHA256SUMS` se pueden entregar al auditor.

### 2.9 Matriz mínima de dispositivos

Cada prueba dice qué API necesita. Mínimo recomendado (un dispositivo puede cubrir varias filas):

| Perfil | Para qué | Dispositivo |
|---|---|---|
| **API 33+** (Android 13+) real | DT-01, DT-03, DT-04 (marca de sensible), DT-06 a DT-10, DT-12 a DT-17 | Físico |
| **API 29** | DT-04 (ID-INT-14 pide API 29, 33 y 36) | Físico o emulador |
| **API 28-30** | DT-02, DT-03 | Físico o emulador (si es emulador, se marca así en la tabla) |
| **API 36** | DT-04 (ID-INT-14) | Físico o emulador |
| **API 28** con huella | DT-12 | Emulador con huella virtual o físico |
| **Emulador `userdebug`** | DT-11 | Emulador `google_apis` |

Emuladores (imagen «Google APIs», sin Play: son `userdebug`). En Mac con Apple Silicon, `arm64-v8a`; en
Intel o Linux, `x86_64` (la app incluye `arm64-v8a`, `armeabi-v7a` y `x86_64`; no `x86`):

```sh
SDK="$HOME/Library/Android/sdk"
"$SDK/cmdline-tools/latest/bin/sdkmanager" "system-images;android-30;google_apis;arm64-v8a"
"$SDK/cmdline-tools/latest/bin/avdmanager" create avd -n dt-api30 \
  -k "system-images;android-30;google_apis;arm64-v8a" -d pixel_5
"$SDK/emulator/emulator" -avd dt-api30 &
adb -e shell getprop ro.build.type        # userdebug
```

Hay imágenes `google_apis` para API 28, 29, 30, 33, 34 y 36 (comprobado con `sdkmanager --list`). Un
emulador es **evidencia secundaria**: se anota como tal. Lo que depende del hardware (huella real,
StrongBox, Chrome con su sincronización) se prueba en físico.

## 3. Registro de resultados

**Vocabulario de `resultado`**: `pasa` (coincide con el resultado esperado), `falla` (no coincide; se
describe qué pasó en `notas`) o `bloqueado` (no se pudo ejecutar: falta el dispositivo, la API, la
herramienta; se dice por qué). Una celda vacía significa «no ejecutada».

Reglas: una fila **por prueba y por dispositivo** (copia la fila si hay varios dispositivos). Nunca se
sobrescribe una fila: si se repite una prueba, se añade una fila nueva con la fecha nueva. `evidencia`
cita ficheros de la carpeta de evidencia (2.8).

### 3.1 Ficha de dispositivo (una por dispositivo)

| Campo | Valor |
|---|---|
| Alias del dispositivo (el que irá en la tabla) | |
| Modelo y fabricante | |
| Android (versión) y API | |
| ABI | |
| RAM (`MemTotal`) | |
| StrongBox (sí / no) | |
| Huella o cara inscrita (sí / no) | |
| Físico o emulador | |
| `ro.build.type` y `ro.build.tags` | |
| `versionName` instalado | |
| Commit probado (SHA completo) | |
| Árbol limpio (`git status --short` vacío) | |
| SHA-256 del APK | |
| Navegador predeterminado original | |
| Servicio de autorrelleno original | |
| Persona que ejecuta | |
| Fecha de inicio | |

### 3.2 Resultados

| ID | fecha | dispositivo/API | resultado | evidencia | notas |
|---|---|---|---|---|---|
| DT-01 | 2026-10-30 | SM-S948B, Android 17 (API 37), físico | **pasa** (con límites) | `/tmp/dt-00-launcher.png`, `/tmp/dt-01.png`, `/tmp/dt-02.png`, salida de `dumpsys window` (ver «Sesión del 30-oct-2026»; no archivada en la carpeta de evidencia) | Control positivo: overlay `full` visible sobre el lanzador. Con OpenPassword al frente (`MainActivity`, `FLAG_SECURE`): overlay con `Surface: shown=false`, `isVisible=false`, `isOnScreen=false` y SurfaceFlinger «hidden»; al volver al lanzador, `shown=true`. `HIDE_OVERLAY_WINDOWS` `granted=true`. Un toque sobre «Crear mi baúl» cambió de pantalla. Sin `FATAL EXCEPTION` ni errores de `AndroidRuntime`. **No** se observó el aviso de «toque tapado» (con `setHideOverlayWindows` el toque no llega tapado; límite conocido). **Límites**: solo `MainActivity` y un toque; no `AutofillAuthActivity` ni `SaveLoginActivity`, ni el overlay parcial, ni los pasos 4-8 completos con baúl desbloqueado |
| DT-02 | 2026-10-30 | — | **bloqueado** | — | Sin binario de emulador ni imágenes de sistema API 28/30 en el equipo (solo `android-36` y `android-37.0`); el teléfono es API 37 |
| DT-03 | — | — | **pendiente** | — | Emulador API 28-30; sin ejecutar |
| DT-04a (primer plano) | 2026-10-30 | SM-S948B, Android 17 (API 37), físico | **pasa** | Salida del lector de portapapeles (`CLIPBOARD_EMPTY`); sin fichero archivado (ver «segunda parte») | Copiar y esperar 35 s **con OpenPassword en primer plano**: `CLIPBOARD_EMPTY`. El borrado a los 30 s **sí** funciona con la app enfocada. Solo API 37 (ID-INT-14 pide también 29, 33 y 36). Método distinto del plan: el portapapeles se leyó con un lector propio, no pegando en `test.fakebrowser` |
| DT-04b (segundo plano) | 2026-10-30 | SM-S948B, Android 17 (API 37), físico | **falla** (confirma ID-INT-14; **aceptado como riesgo residual** por el responsable, 30-oct-2026) | Salida del lector de portapapeles (`CLIPBOARD_HAS_TEXT`); sin fichero archivado | Copiar la contraseña, pulsar Inicio, esperar 36 s y abrir el lector: **`CLIPBOARD_HAS_TEXT` a los 45 s**; el borrado **no** ocurre con la app en segundo plano. Controles: copiar y leer a los 5 s da `CLIPBOARD_HAS_TEXT` (el copiado funciona y el lector lee bien, en `onWindowFocusChanged`), y el 04a da `CLIPBOARD_EMPTY` (el borrado funciona en primer plano). **No** se probó el paso 5 del plan (volver a OpenPassword y ver si se borra al volver): lo que hace `onForeground` sigue **sin verificar en dispositivo**. No se distinguió cuál de las tres hipótesis de ID-INT-14 explica el síntoma (descripción `null`, `clearPrimaryClip()` denegado o `Handler` sin ejecutar); solo consta que, en API 37, el portapapeles sigue con texto tras salir de la app |
| DT-04c (pantalla apagada) | — | — | **pendiente** | — | Sin ejecutar |
| DT-04d (marca sensible) | — | — | **pendiente** | — | Sin ejecutar |
| DT-05 | 2026-10-30 | SM-S948B, Android 17 (API 37), físico; build de **depuración** (sin R8) | **pasa** (solo depuración; variante R8 sin ejecutar) | Salida de la sesión (tabla en «segunda parte»); sin capturas archivadas | Con `test.fakebrowser` como navegador predeterminado. `alice.github.io` → «COINCIDEN» solo `alice.github.io` (`github.io` en «OTROS LOGINS»); `evil.github.io` → «ELIGE UN LOGIN», sin coincidencias y con «Ningún login tiene guardado evil.github.io» (repetido con el baúl desbloqueado); `x.alice.github.io` → ofrece `alice.github.io`; `en.wikipedia.org` → ofrece `wikipedia`; `github.io` → ofrece `sufijo-github-io` (exacta). Los dos controles positivos (`x.alice.github.io`, `en.wikipedia.org`) ofrecen el elemento: **la lista se cargó y se aplicó**. No prueban que la app falle cerrada si la lista no cargara. Baúl de 4 logins, no los 7 de 2.4 |
| DT-06 | — | — | **pendiente** | — | Navegador real; sin ejecutar |
| DT-07 | 2026-10-30 | SM-S948B, Android 17 (API 37), físico | **pasa** | Salida de la sesión; sin capturas archivadas | Con Chrome como navegador predeterminado, `test.fakebrowser` declarando `bank.example` produce «Para: test.fakebrowser»; el `webDomain` se ignora y no hay coincidencias web. **No se anotó** si había casilla «Recordar…» ni se hicieron los pasos 4 (baúl bloqueado) y 5 (caché de 5 min) del plan |
| DT-08 | — | — | **pendiente** | — | Navegador predeterminado; sin ejecutar |
| DT-09a (guardar) | — | — | **pendiente** | — | Sin ejecutar |
| DT-09b (rellenar) | — | — | **pendiente** | — | Sin ejecutar |
| DT-09c (actualizar contraseña) | — | — | **pendiente** | — | Sin ejecutar |
| DT-09d (token y rotación) | — | — | **pendiente** | — | Sin ejecutar |
| DT-10 | — | — | **pendiente** | — | Sin ejecutar |
| DT-11 | — | — | **pendiente** | — | Requiere emulador `userdebug`; sin ejecutar |
| DT-12 | 2026-10-30 | — | **bloqueado** | — | Necesita Android 9 (API 28); no hay emulador ni imagen de sistema y el teléfono es API 37 |
| DT-13a (ChaCha20 + Argon2id) | — | — | **pendiente** | — | KDBX 4 real; sin ejecutar |
| DT-13b (AES-256 + Argon2d) | — | — | **pendiente** | — | KDBX 4 real; sin ejecutar |
| DT-13c (con archivo de clave) | — | — | **pendiente** | — | KDBX 4 real; sin ejecutar |
| DT-13d (Twofish: rechazo) | — | — | **pendiente** | — | KDBX 4 real; sin ejecutar |
| DT-13e (KDF demasiado costosa: rechazo) | — | — | **pendiente** | — | KDBX 4 real; sin ejecutar |
| DT-14a (por encima del techo) | — | — | **pendiente** | — | Sin ejecutar |
| DT-14b (en el techo) | — | — | **pendiente** | — | Sin ejecutar |
| DT-15 | — | — | **pendiente** | — | Sin ejecutar |
| DT-16a (inactividad 5 min) | — | — | **pendiente** | — | Sin ejecutar |
| DT-16b (30 s tras salir) | — | — | **pendiente** | — | Sin ejecutar |
| DT-16c (pantalla apagada) | — | — | **pendiente** | — | Sin ejecutar |
| DT-17a (QR con la cámara) | — | — | **pendiente** | — | Sin ejecutar |
| DT-17b (QR desde una imagen) | — | — | **pendiente** | — | Sin ejecutar |
| DT-17c (pegar `otpauth://` o secreto) | — | — | **pendiente** | — | Sin ejecutar |
| Instrumentados (`./gradlew :app:connectedDebugAndroidTest`) | 2026-10-30 | SM-S948B, Android 17 (API 37), arm64-v8a, físico | **pasa** | `android/app/build/outputs/androidTest-results/connected/debug/TEST-SM-S948B - 17.xml` (ver «Sesión del 30-oct-2026») | 17 tests, 0 fallos, 0 errores, 0 omitidos, 47 s: `EmergencyKitTest` (2), `OverlayProtectionTest` (4), `VaultSessionTest` (11). Sobre el commit `b2e18ca` con el árbol sucio (`fuzz/deny.toml` modificado). Versión instalada `0.1.0` (`io.github.rldona.openpassword.debug`). Los tests son de banderas y de sesión con baúles aislados: no sustituyen a las pruebas DT sobre comportamiento real |

<a id="sesion-2026-10-30"></a>
### 3.3 Sesión del 30-oct-2026

- **Dispositivo**: Samsung SM-S948B, Android 17 (API 37), `arm64-v8a`, físico.
- **App**: `versionName` 0.1.0, `io.github.rldona.openpassword.debug`, instalada desde el árbol de trabajo
  en el commit `b2e18ca`, **con `fuzz/deny.toml` modificado sin commit** (árbol no limpio; sin huella SHA-256
  del APK registrada).
- **Instrumentados**: `./gradlew :app:connectedDebugAndroidTest`, 17 tests, 0 fallos, 0 errores, 0
  omitidos, 47 s. `EmergencyKitTest` (2); `OverlayProtectionTest` (4: `mainActivityWindowIsProtected`,
  `autofillAuthActivityWindowIsProtected`, `saveLoginActivityWindowIsProtected`,
  `protectedAlertDialogWindowIsProtected`); `VaultSessionTest` (11, entre ellos `createLockAndUnlock`,
  `nothingIsStoredInClear`, `exportAndRestoreOnANewDevice`, `failedRestoreLeavesNoVaultBehind`,
  `wrongPasswordsTriggerTheWait`, `locksInTheBackgroundWithoutComingBack`, `itemsRoundTripAndKeepRevisions`,
  `importingAnOlderCopyOfTheSameVaultKeepsNewerItems`, `importingANewerCopyUpdatesAndAddsItems`,
  `importingAnotherVaultReencryptsItsItems`; el undécimo no se transcribió). Fichero de resultados:
  `android/app/build/outputs/androidTest-results/connected/debug/TEST-SM-S948B - 17.xml`.
- **DT-01**: `test.overlay` compilado en `~/openpassword-testapps` (AGP 9.4.1, JDK 17, `compileSdk 36`,
  `targetSdk 33`) y `SYSTEM_ALERT_WINDOW` concedido con `adb shell appops set test.overlay
  SYSTEM_ALERT_WINDOW allow`. Resultado y límites en la fila DT-01.
- **DT-02 y DT-12**: bloqueados (sin emulador ni imágenes API 28/30; el teléfono es API 37).
- **Estado del teléfono al terminar**: `test.overlay` desinstalado; OpenPassword instalada **sin baúl
  creado** (los instrumentados desinstalaron la app y se reinstaló limpia). No se tocó ningún baúl real.
- **Evidencia disponible** (fuera del repositorio): `/tmp/dt-00-launcher.png` (control positivo en el
  lanzador), `/tmp/dt-01.png` y `/tmp/dt-02.png` (OpenPassword al frente; salen negras a propósito por
  `FLAG_SECURE`) y la salida de `dumpsys window` (no guardada en fichero). **`/tmp` se puede limpiar**: si
  esta evidencia ha de entregarse al auditor, hay que copiarla antes a la carpeta de evidencia (2.8) y
  registrar su `SHA256SUMS`.

<a id="sesion-2026-10-30-b"></a>
### 3.4 Sesión del 30-oct-2026, segunda parte

- **Dispositivo**: el mismo Samsung SM-S948B, Android 17 (API 37), físico. **Commit probado y huella del
  APK: no registrados** (la app debug se instaló desde el árbol de trabajo, con cambios sin commit, entre
  ellos el texto del mensaje de copiado descrito abajo).
- **Método**: se creó una bóveda de pruebas con **4 logins** (no los 7 de 2.4; entre ellos `alice.github.io`,
  uno de sufijo `github.io` titulado `sufijo-github-io` y `wikipedia`) y se instaló `test.fakebrowser`
  (sección 4.3), que declara `webDomain` mediante una estructura de autorrelleno virtual. Para DT-05 se
  puso como navegador predeterminado; para DT-07, Chrome.
- **DT-05 · sufijos públicos: `pasa`** (build de depuración). Resultado por dominio declarado:

  | Dominio declarado | Observado |
  |---|---|
  | `alice.github.io` | «COINCIDEN» solo `alice.github.io`; `github.io` queda en «OTROS LOGINS» |
  | `evil.github.io` | «ELIGE UN LOGIN», sin coincidencias, con «Ningún login tiene guardado evil.github.io». Repetido con el baúl desbloqueado |
  | `x.alice.github.io` | Ofrece `alice.github.io` (control positivo: la lista cargó) |
  | `en.wikipedia.org` | Ofrece `wikipedia` (control positivo) |
  | `github.io` | Ofrece `sufijo-github-io` (coincidencia exacta) |

  Los controles positivos demuestran que la lista **se cargó y se aplicó**; no demuestran que la app falle
  cerrada si no cargara (eso solo lo cubren tests de JVM, sin ejecutar). **Sin ejecutar** la variante R8 (5.R8): la
  build de depuración no pasa por R8.
- **DT-07 · app que se declara navegador: `pasa`**. Con Chrome predeterminado, `test.fakebrowser` con
  `bank.example` produce «Para: test.fakebrowser»; el `webDomain` se ignora y no hay coincidencias web.
- **DT-08 (no ejecutada como tal)**: durante DT-05, con `test.fakebrowser` como predeterminado, su
  `webDomain` **se tomó en cuenta** (hubo coincidencias web por dominio). Es coherente con el riesgo
  residual de A17, pero no se siguió el procedimiento de DT-08 ni se anotó «Para:» ni la casilla
  «Recordar…»: la fila sigue vacía.
- **DT-04 · portapapeles: `falla` en segundo plano (confirma ID-INT-14)**. Se leyó el portapapeles con un
  lector propio que consulta el portapapeles en `onWindowFocusChanged` (cuando tiene foco) y escribe
  `CLIPBOARD_HAS_TEXT` o `CLIPBOARD_EMPTY`. Este método **sustituye** a pegar en el campo de
  `test.fakebrowser` del plan. Controles y resultados:

  | Secuencia | Resultado |
  |---|---|
  | Copiar la contraseña y abrir el lector a los 5 s | `CLIPBOARD_HAS_TEXT` (control positivo: el copiado funciona y el lector lee) |
  | Copiar, esperar 35 s con OpenPassword en primer plano, leer | `CLIPBOARD_EMPTY` (el borrado funciona con la app enfocada) |
  | Copiar, pulsar Inicio, esperar 36 s, abrir el lector | **`CLIPBOARD_HAS_TEXT` a los 45 s** (el borrado **no** ocurre en segundo plano) |

  Conclusión de la sesión: `clearPrimaryClip()` desde segundo plano no surte efecto en API 37; el
  mecanismo actual solo limpia con la app en primer plano. **Sin verificar**: que se borre al volver a la
  app (no se probó), DT-04c (pantalla apagada), DT-04d (marca de sensible) y las API 29, 33 y 36.
- **Cambio de código asociado (sin commit)**: el mensaje prometía «Se borrará del portapapeles en 30 s»
  también en segundo plano. Ahora dice «Se borrará en 30 s, o al volver a la app si sales.»
  (`ui/vault/ItemDetailScreen.kt:99,142,184`). Solo corrige el texto: **no** corrige el borrado, y la parte
  «o al volver a la app» describe el diseño de `onForeground`, **no verificado en dispositivo**.
- **Estado del teléfono al terminar**: servicio de autorrelleno devuelto a
  `com.google.android.gms/…AutofillService`; navegador predeterminado de vuelta a `com.android.chrome`;
  `test.fakebrowser` desinstalado; OpenPassword debug instalada con la bóveda de pruebas. No se tocó
  ninguna bóveda real.
- **Evidencia**: las lecturas del portapapeles y la salida de DT-05 y DT-07 son anotaciones de la sesión; **no
  hay ficheros archivados ni `SHA256SUMS`**. Antes de entregarlas al auditor hay que repetir la captura
  (2.8) o aceptar que son testimonio del proyecto.

---

## 4. APKs de prueba

Dos módulos mínimos en un proyecto Gradle **fuera del repositorio** (por ejemplo
`~/openpassword-testapps`), para no tocar el código ni sus comprobaciones de dependencias:

- `test.overlay`: dibuja una ventana `TYPE_APPLICATION_OVERLAY` translúcida que deja pasar los toques
  (`FLAG_NOT_TOUCHABLE`), desde un servicio. Es lo que haría una app de *tapjacking*.
- `test.fakebrowser`: declara un `intent-filter` `VIEW` `http`/`https` y, en su pantalla de acceso, un
  `webDomain` falso (`ViewStructure.setWebDomain`). Es lo que haría una app que se hace pasar por
  navegador.

No piden `INTERNET` ni nada más que `SYSTEM_ALERT_WINDOW` (el de superposición). Los dos son Java (sin
Kotlin) para depender de lo mínimo. Se compilan con el *wrapper* de Gradle y la versión de AGP del
repositorio ([`android/gradle/libs.versions.toml`](../../android/gradle/libs.versions.toml): `agp`), que
descarga de Google y Maven Central (sin verificación de dependencias: son APK desechables, no se
publican ni se entregan al usuario).

> Los dos módulos se compilaron con esta receta (JDK 21, AGP 9.4.1, Gradle 9.8.2 del *wrapper* del
> repositorio) y `assembleDebug` terminó con éxito. `test.overlay` se instaló y
> ejecutó el 30-oct-2026 (DT-01, con JDK 17 y `compileSdk 36`); `test.fakebrowser` se instaló y ejecutó el
> mismo día (segunda parte: DT-05 y DT-07) y se desinstaló al terminar. Que se comporten como se describe es
> parte de lo que las pruebas comprueban.

### 4.1 Crear el proyecto

```sh
mkdir -p ~/openpassword-testapps && cd ~/openpassword-testapps
mkdir -p gradle overlay/src/main/java/test/overlay fakebrowser/src/main/java/test/fakebrowser
cp -R "$OP_REPO/android/gradle/wrapper" gradle/wrapper
cp "$OP_REPO/android/gradlew" .

cat > settings.gradle.kts <<'EOF'
pluginManagement {
    repositories { google(); mavenCentral(); gradlePluginPortal() }
}
dependencyResolutionManagement {
    repositories { google(); mavenCentral() }
}
rootProject.name = "openpassword-testapps"
include(":overlay", ":fakebrowser")
EOF

cat > build.gradle.kts <<'EOF'
plugins {
    id("com.android.application") version "9.4.1" apply false
}
EOF

echo "android.useAndroidX=true" > gradle.properties
echo "sdk.dir=$HOME/Library/Android/sdk" > local.properties   # ajusta si tu SDK está en otra ruta

for m in overlay fakebrowser; do
cat > "$m/build.gradle.kts" <<EOF
plugins { id("com.android.application") }

android {
    namespace = "test.$m"
    compileSdk = 36
    defaultConfig {
        applicationId = "test.$m"
        minSdk = 28
        targetSdk = 33
        versionCode = 1
        versionName = "1"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
EOF
done
```

`targetSdk = 33` es deliberado: un servicio de superposición simple no necesita `foregroundServiceType`
y el APK se instala en Android 14 o posterior sin avisos de versión antigua. Si el SDK no tiene la
plataforma 36, cambia `compileSdk` a una que tengas (`ls "$HOME/Library/Android/sdk/platforms"`).

### 4.2 Módulo `overlay`

```sh
cat > overlay/src/main/AndroidManifest.xml <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" />
    <application android:label="Overlay de prueba" android:allowBackup="false">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        <service android:name=".OverlayService" android:exported="false" />
    </application>
</manifest>
EOF

cat > overlay/src/main/java/test/overlay/MainActivity.java <<'EOF'
package test.overlay;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.provider.Settings;
import android.widget.Button;
import android.widget.LinearLayout;

public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(48, 96, 48, 48);
        root.addView(button("1. Conceder permiso de superposición", v -> startActivity(
                new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION, Uri.parse("package:" + getPackageName())))));
        root.addView(button("2. Overlay COMPLETO (toda la pantalla)", v -> start("full")));
        root.addView(button("3. Overlay PARCIAL (franja inferior)", v -> start("partial")));
        root.addView(button("4. Quitar overlay", v -> start("off")));
        setContentView(root);
    }

    private Button button(String text, android.view.View.OnClickListener l) {
        Button x = new Button(this);
        x.setText(text);
        x.setOnClickListener(l);
        return x;
    }

    private void start(String mode) {
        if (!Settings.canDrawOverlays(this)) return;
        startService(new Intent(this, OverlayService.class).putExtra("mode", mode));
    }
}
EOF

cat > overlay/src/main/java/test/overlay/OverlayService.java <<'EOF'
package test.overlay;

import android.app.Service;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.PixelFormat;
import android.os.IBinder;
import android.view.Gravity;
import android.view.View;
import android.view.WindowManager;
import android.widget.TextView;

/** Draws a translucent TYPE_APPLICATION_OVERLAY window that lets touches through (FLAG_NOT_TOUCHABLE). */
public class OverlayService extends Service {
    private View view;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String mode = intent == null ? "off" : intent.getStringExtra("mode");
        remove();
        if ("full".equals(mode) || "partial".equals(mode)) {
            boolean full = "full".equals(mode);
            TextView v = new TextView(this);
            v.setText("OVERLAY DE PRUEBA (" + mode + ")");
            v.setTextSize(20);
            v.setGravity(Gravity.CENTER);
            v.setTextColor(Color.WHITE);
            v.setBackgroundColor(Color.RED);
            // 0.5 < 0.8: Android 12+ blocks touches through overlays above 0.8 opacity on its own;
            // we want to test OpenPassword's defences, not the system's.
            WindowManager.LayoutParams lp = new WindowManager.LayoutParams(
                    WindowManager.LayoutParams.MATCH_PARENT,
                    full ? WindowManager.LayoutParams.MATCH_PARENT : 300,
                    WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
                    WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE
                            | WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE
                            | WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
                    PixelFormat.TRANSLUCENT);
            lp.alpha = 0.5f;
            lp.gravity = Gravity.BOTTOM;
            getSystemService(WindowManager.class).addView(v, lp);
            view = v;
        } else {
            stopSelf();
        }
        return START_NOT_STICKY;
    }

    private void remove() {
        if (view != null) {
            getSystemService(WindowManager.class).removeView(view);
            view = null;
        }
    }

    @Override
    public void onDestroy() {
        remove();
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
EOF
```

Por qué `alpha = 0.5f`: desde Android 12 el sistema bloquea por sí mismo los toques que atraviesan una
superposición de otra app con opacidad mayor que 0,8. Con 0,5 el toque llega a la ventana de debajo y lo
que se prueba son las defensas de OpenPassword, no las del sistema.

### 4.3 Módulo `fakebrowser`

```sh
cat > fakebrowser/src/main/AndroidManifest.xml <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application android:label="Navegador falso" android:allowBackup="false">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
            <!-- Declarar esto no exige ningún permiso: es justo lo que un atacante haría. -->
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="http" />
                <data android:scheme="https" />
            </intent-filter>
        </activity>
    </application>
</manifest>
EOF

cat > fakebrowser/src/main/java/test/fakebrowser/MainActivity.java <<'EOF'
package test.fakebrowser;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.text.InputType;
import android.view.View;
import android.view.ViewStructure;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

/**
 * Pantalla de acceso que declara un dominio web falso (webDomain), como haría un WebView.
 * Dominio: extra "domain" (por defecto bank.example); se pasa al abrirla con
 * adb shell am start -n test.fakebrowser/.MainActivity --es domain bank.example
 */
public class MainActivity extends Activity {
    /** Un EditText que añade webDomain a la estructura de autorrelleno. */
    static class WebField extends EditText {
        private final String domain;

        WebField(Context c, String domain) {
            super(c);
            this.domain = domain;
        }

        @Override
        public void onProvideAutofillStructure(ViewStructure structure, int flags) {
            super.onProvideAutofillStructure(structure, flags);
            structure.setWebDomain(domain);
        }
    }

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        String domain = getIntent().getStringExtra("domain");
        if (domain == null) domain = "bank.example";
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(48, 96, 48, 48);

        TextView info = new TextView(this);
        info.setText("Navegador falso. Declara webDomain = " + domain);
        root.addView(info);

        EditText user = new WebField(this, domain);
        user.setHint("usuario");
        user.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS);
        user.setAutofillHints(View.AUTOFILL_HINT_USERNAME);
        root.addView(user);

        EditText pass = new WebField(this, domain);
        pass.setHint("contraseña");
        pass.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        pass.setAutofillHints(View.AUTOFILL_HINT_PASSWORD);
        root.addView(pass);

        Button send = new Button(this);
        send.setText("Enviar");
        send.setOnClickListener(v -> finish());
        root.addView(send);
        setContentView(root);
    }
}
EOF
```

Los campos de esta pantalla también sirven de **destino de pegado** en DT-04 (el portapapeles solo lo lee
la app con foco: un campo propio evita depender de otra app).

### 4.4 Compilar, instalar y conceder permisos

```sh
cd ~/openpassword-testapps
./gradlew assembleDebug
adb install -r overlay/build/outputs/apk/debug/overlay-debug.apk
adb install -r fakebrowser/build/outputs/apk/debug/fakebrowser-debug.apk
```

Permiso de superposición (`SYSTEM_ALERT_WINDOW`), que **hay que conceder a mano**: se pide desde el botón 1
de la app «Overlay de prueba» (abre la pantalla *Mostrar sobre otras apps*) o, sin root, con:

```sh
adb shell appops set test.overlay SYSTEM_ALERT_WINDOW allow
adb shell appops get test.overlay SYSTEM_ALERT_WINDOW        # debe decir: allow
```

Uso del overlay: abre «Overlay de prueba» y pulsa **2** (completo) o **3** (franja inferior de 300 px;
puede cambiarse en `OverlayService.java`), pulsa Inicio y abre OpenPassword: el overlay se queda
dibujado sobre cualquier app. El botón **4** lo quita. Comprueba siempre en el lanzador que el overlay
**se ve** (control positivo: sin él, no se ha probado nada).

Uso del navegador falso: `adb shell am start -n test.fakebrowser/.MainActivity --es domain bank.example`.

### 4.5 Desinstalar y limpiar

```sh
adb shell am force-stop test.overlay
adb uninstall test.overlay
adb uninstall test.fakebrowser
adb shell pm list packages | grep -E "package:test\." || echo "limpio"
```

Desinstalar `test.fakebrowser` también lo quita como navegador predeterminado si se había elegido (DT-08).
Los permisos concedidos se pierden con la desinstalación. Borra después `~/openpassword-testapps` si no
se va a repetir.

## 5. Pruebas

Convenciones de cada prueba: **Dispositivos** (qué API necesita), **Prerrequisitos**, **Pasos**,
**Resultado esperado** (lo que el código pretende; no es un resultado), y **Cubre** (hallazgo o amenaza).
Salvo que se diga otra cosa, la app de pruebas es `$PKG` con la bóveda de pruebas (2.4) **desbloqueada**.

Pasos comunes que se repiten:

- **Reiniciar el proceso** de OpenPassword (borra estados en memoria como el aviso «una vez por proceso»
  y la caché de navegadores): `adb shell am force-stop "$PKG"`.
- **Activar OpenPassword como servicio de autorrelleno**: en OpenPassword → Ajustes → *Autorrelleno*
  (abre el diálogo del sistema; `SettingsScreen.kt:236-253`). Anota antes el servicio original (2.7).
- **Lanzar el navegador falso**: `adb shell am start -n test.fakebrowser/.MainActivity --es domain <dominio>`.
- **Quitar el overlay**: botón 4 de «Overlay de prueba».

<a id="dt-01"></a>
### DT-01 · Anti-tapjacking, API 31+

**Objetivo.** Comprobar que, en Android 12 o posterior, `setHideOverlayWindows(true)` oculta una
superposición de otra app mientras OpenPassword está al frente, y que los toques funcionan con normalidad.

**Qué se verifica.** `OverlayProtection.kt:44-46` (`filterTouchesWhenObscured = true` y
`setHideOverlayWindows(true)` si `SDK_INT >= S`), aplicado en las tres actividades
(`MainActivity.kt:46`, `AutofillAuthActivity.kt:133`, `SaveLoginActivity.kt:112`); permiso
`HIDE_OVERLAY_WINDOWS` en `AndroidManifest.xml:12` (exigido por `VerifyManifest`).

**Dispositivos.** API 31 o superior, físico. Ver [2.9](#29-matriz-mínima-de-dispositivos).

**Prerrequisitos.** APK de `overlay` y `fakebrowser` instalados y permiso `SYSTEM_ALERT_WINDOW`
concedido (4.4). OpenPassword como servicio de autorrelleno (para las otras dos actividades).

**Pasos.**

1. Comprueba que el permiso está concedido (es de instalación):
   `adb shell dumpsys package "$PKG" | grep HIDE_OVERLAY_WINDOWS` debe mostrar `granted=true`.
2. Abre «Overlay de prueba» y pulsa **2** (completo). Pulsa Inicio. **Control positivo**: el rectángulo rojo
   «OVERLAY DE PRUEBA (full)» debe verse sobre el lanzador. Abre el navegador falso: el overlay también se
   ve sobre él. Foto.
3. Abre OpenPassword con el baúl **bloqueado** (pantalla de desbloqueo). Observa: **¿se ve el overlay?**
   Foto con otra cámara (las capturas salen negras: `FLAG_SECURE`).
4. Escribe la contraseña de pruebas y pulsa **Desbloquear**. Anota si responde al primer toque.
5. En la lista, toca un elemento y vuelve atrás. Anota si algún toque se pierde y si aparece un mensaje
   («Otra app está mostrando algo encima de OpenPassword…») o la tarjeta roja de aviso arriba.
6. Pulsa Inicio: **¿reaparece el overlay** sobre el lanzador? (Es el control de que sigue activo.)
7. Repite 2-6 con el overlay **parcial** (botón 3).
8. Con el overlay completo activo, repite 3-5 en las otras dos actividades:
   - `AutofillAuthActivity`: en el navegador falso (`--es domain bank.example`), toca el campo de usuario y
     el desplegable «Buscar en OpenPassword».
   - `SaveLoginActivity`: en el navegador falso escribe un usuario y una contraseña y pulsa **Enviar**;
     acepta «Guardar» del sistema.

**Resultado esperado.** El overlay **no se ve** mientras OpenPassword está al frente en ninguna de las tres
actividades, y se ve en el lanzador y en el navegador falso. Todos los toques funcionan al primer intento.
No hay aviso (no hay toque tapado).

**Límite conocido de esta prueba.** Con `setHideOverlayWindows` activo no llega ningún toque tapado, así
que **el aviso no se puede provocar en API 31+** sin tocar el código. El aviso se verifica en DT-02 (API
28-30) y su clasificación de banderas en la prueba JVM `OverlayProtectionTest`
(`android/app/src/test/…`). Si falta un dispositivo API 28-30, el aviso queda sin verificar en dispositivo
y se anota como `bloqueado` en DT-02.

**Cubre.** A7; [ID-INT-13](internal-review.md#id-int-13) (la implementación y sus pruebas no alcanzan lo
que describe el ADR).

<a id="dt-02"></a>
### DT-02 · Anti-tapjacking, API 28-30

**Objetivo.** Comprobar que sin `setHideOverlayWindows` (no existe antes de Android 12) el filtro
`filterTouchesWhenObscured` descarta los toques tapados del todo, que se avisa una vez, y qué pasa con un
toque **parcialmente** tapado (riesgo residual documentado).

**Qué se verifica.** `OverlayProtection.kt:17-31` (`Obscured.FULL`/`PARTIAL`), `:44` (filtro), `:57-62`
(`warnIfObscured`: `Toast` una vez por proceso, `OverlayWarning.report()` en `:39`), y la tarjeta
`OverlayWarningBanner` (`Components.kt:208-219`, montada en `AppRoot.kt:47`). El modelo de amenazas dice:
«un toque **parcialmente** tapado se entrega (con aviso)» ([`threat-model.md`](../threat-model.md), A7).

**Dispositivos.** API 28, 29 o 30 (físico o emulador; se anota). Ver 2.9.

**Prerrequisitos.** Como DT-01. Baúl desbloqueado, en una pantalla con un botón claro (por ejemplo, la
lista del baúl con el botón de añadir).

**Pasos.**

1. `adb shell am force-stop "$PKG"` y abre OpenPassword (el aviso «una vez por proceso» está sin disparar).
2. Overlay **completo** (botón 2). **Control positivo**: se ve sobre el lanzador. Abre OpenPassword: **el
   overlay se ve** encima (en API < 31 no se oculta). Foto.
3. Toca un botón de OpenPassword (por ejemplo, el de añadir elemento). Anota si **la acción se ejecuta**.
4. Anota si aparece el mensaje «Otra app está mostrando algo encima de OpenPassword. Por seguridad se
   ignoran los toques tapados.» (un `Toast` largo) y/o la tarjeta roja con ese texto arriba.
5. Toca otra vez el mismo botón: anota si sale un segundo `Toast` (no debería: una vez por proceso) y si la
   tarjeta sigue ahí.
6. Quita el overlay (botón 4). Anota si la tarjeta sigue (`OverlayWarning` no se reinicia hasta cerrar el
   proceso).
7. `adb shell am force-stop "$PKG"`, abre OpenPassword y activa el overlay **parcial** (botón 3; franja de
   300 px abajo).
8. Toca un botón **en la parte de arriba** (fuera de la franja, pero con la ventana parcialmente tapada).
   Anota si la acción se ejecuta y si sale el aviso.
9. Repite 8 pero toca **dentro** de la franja roja: debe comportarse como en el paso 3.

**Resultado esperado.**

- Overlay completo: el toque **no ejecuta la acción** (lo descarta el filtro) y se avisa **una vez**
  (`Toast`) más la tarjeta.
- Overlay parcial, toque fuera de la franja: el toque **sí se entrega** (la acción se ejecuta) y se avisa.
  Esto es el **riesgo residual documentado**, no un fallo: se anota que se ha observado.
- Toque dentro de la franja: como el completo.

Si el sistema no marca la bandera como el código supone (por ejemplo, no hay aviso en el parcial), se
anota tal cual y se abre hallazgo (sección 7).

**Cubre.** A7; ID-INT-13; la advertencia «solo queda el filtro» de `threat-model.md` A7.

<a id="dt-03"></a>
### DT-03 · Diálogos protegidos (`ProtectedAlertDialog`)

**Objetivo.** Repetir DT-01/DT-02 sobre ventanas de diálogo, que son ventanas distintas y no heredan la
protección de la actividad.

**Qué se verifica.** `ProtectedAlertDialog` (`Components.kt:187-205`) llama a `ProtectDialogWindow`
(`OverlayProtection.kt:67-78`), que busca la ventana del `DialogWindowProvider` y le aplica la misma
protección. Diálogos usados: «¿Borrar «…»?» (`ItemDetailScreen.kt:221-223`) e «Importar copia»
(`SettingsScreen.kt:429-431`, con campo de contraseña).

**Dispositivos.** API 31+ (físico) **y** API 28-30 (físico o emulador).

**Prerrequisitos.** DT-01/DT-02. Para el diálogo de importar, una copia de otra bóveda en el teléfono:
```sh
cd "$OP_REPO"
SK="$(cargo run -q -p opvault-cli -- new-secret-key)"; echo "$SK"        # apúntala: PRUEBAS
printf 'prueba-copia-1\n' | cargo run -q -p opvault-cli -- sample demo.opvault --password-stdin --secret-key "$SK"
adb push demo.opvault /sdcard/Download/demo.opvault
```

**Pasos (API 31+).**

1. Overlay completo (botón 2). Abre el elemento `Borra-me` y toca el icono de papelera: sale
   «¿Borrar «Borra-me»?». **¿Se ve el overlay sobre el diálogo?** Foto. Pulsa **Cancelar**.
2. Ajustes → **Importar copia** → elige `demo.opvault`: sale el diálogo «Importar copia». **¿Se ve el
   overlay?** Foto. Cancela.

**Pasos (API 28-30).**

3. `adb shell am force-stop "$PKG"`. Overlay completo. Abre `Borra-me` → papelera → diálogo. **Toca
   «Borrar»** (con el overlay encima). Anota si el elemento **se borra** (no debería) y si aparece el aviso.
   Si se borró, recréalo (2.4).
4. Quita el overlay y repite con el diálogo de importar: toca **Importar** con el overlay completo y el
   campo de contraseña relleno. Anota si se inicia la importación (no debería).
5. Overlay parcial: abre el diálogo y toca un botón **fuera** de la franja: debe entregarse (como DT-02).

**Resultado esperado.** API 31+: el overlay no se ve sobre ningún diálogo. API 28-30: un toque tapado del
todo sobre un botón del diálogo **no** ejecuta la acción y avisa; el parcial se entrega.

**Cubre.** A7; ID-INT-13 (el hallazgo señala que las pruebas instrumentadas actuales no cubren los
diálogos: `androidTest/…/OverlayProtectionTest.kt:12-16`).

<a id="dt-04"></a>
### DT-04 · Portapapeles: borrado a los 30 s y marca de «sensible»

**Objetivo.** Confirmar o refutar [ID-INT-14](internal-review.md#id-int-14): el borrado de los 30 s
probablemente **no actúa si OpenPassword ya no tiene el foco**, que es el uso normal (copiar y pegar en
otra app). Y comprobar la marca de sensible en Android 13+.

**Qué se verifica.** `SensitiveClipboard.kt:21-31` (`copy`: etiqueta `OpenPassword`, marca
`EXTRA_IS_SENSITIVE` en API 33+, temporizador de `CLEAR_AFTER_MS` = 30 000 ms),
`:34-39` (`clearIfOurs`: compara `primaryClipDescription?.label`; el propio comentario dice que desde
Android 10 puede ser `null` sin foco, y entonces no se borra nada) y `OpenPasswordApp.kt:75-80` (al apagar
la pantalla: `session.lock()` y `clipboard.clearIfOurs()`). ID-INT-14 pide probar en API 29, 33 y 36.

**Dispositivos.** API 29, 33 y 36 (se ejecuta en cada uno; la marca de sensible solo se ve en 33+).

**Prerrequisitos.** Elemento `Portapapeles` (contraseña `Prueba-pw-7`). El **navegador falso** instalado
(sus campos son el destino de pegado). Cronómetro (el del teléfono vale; o el del ordenador).

Cómo se «pega» sin dudas: abre el navegador falso, **mantén pulsado** su campo de contraseña →
**Pegar**. Si no hay nada en el portapapeles, no aparece «Pegar» o el campo queda vacío. Foto/captura del
campo (la captura del navegador falso sí funciona).

**DT-04a · Control en primer plano.**

1. Abre `Portapapeles` → revela y **copia** el campo de contraseña (`ItemDetailScreen.kt:98`).
2. **Sin salir de OpenPassword**, espera 35 s.
3. Ve al navegador falso y pega.

**DT-04b · Segundo plano (el caso de ID-INT-14).**

1. Copia la contraseña de `Portapapeles` en OpenPassword. Pon el cronómetro a 0.
2. Cambia **de inmediato** al navegador falso y deja que quede en primer plano (con el campo enfocado).
3. A los 35 s, **pega** en el campo.
4. Anota también: ¿el pegado muestra `Prueba-pw-7`?
5. Vuelve a OpenPassword (sigue desbloqueado si han pasado menos de 30 s de bloqueo; si no, desbloquea),
   espera otros 35 s **en primer plano** y vuelve a pegar. Anota si el portapapeles se borra al volver.

**DT-04c · Pantalla apagada.**

1. Copia la contraseña. Apaga la pantalla (botón de encendido). Espera 35 s.
2. Enciende, desbloquea el teléfono, abre el navegador falso y pega.

**DT-04d · Marca de sensible (API 33+).**

1. Copia la contraseña. Observa la vista previa del portapapeles que muestra el sistema (Android 13+: un
   recuadro abajo a la izquierda) y, si el teclado ofrece el contenido del portapapeles, su sugerencia.
2. **¿Se ve el texto `Prueba-pw-7` o se muestra oculto (puntos)?** Foto. En API 28-32 no hay marca
   (ID-INT-15, aceptado): anota qué se ve, pero no cuenta como fallo.

**Resultado esperado.** a) Al pegar no hay nada (se borró). b) y c) Por diseño, también se borra: el
`Runnable` y el receptor de pantalla llaman a `clearIfOurs`. **Si al pegar sale `Prueba-pw-7`, el borrado
no actuó: `falla` y ID-INT-14 queda confirmado** (la causa probable es la del comentario de
`SensitiveClipboard.kt:37`, aunque en Android 11+ también puede que el proceso en segundo plano esté
congelado y el `Runnable` no llegue a ejecutarse; solo se anota el síntoma). d) En API 33+ el contenido se
ve oculto.

**Cubre.** A7; ID-INT-14; ID-INT-15. Es la prueba que decide si «con borrado» sigue en la fila A7 de
`threat-model.md`.

<a id="dt-05"></a>
### DT-05 · Lista de sufijos públicos en el dispositivo

**Objetivo.** Confirmar que `public_suffix_list.dat` **se carga y se aplica** en el dispositivo (y con R8
en la build de release), y que un login guardado para un sufijo público no se ofrece en sus subdominios.

**Qué se verifica.** `PublicSuffix.kt:18-25` (carga por `classLoader.getResourceAsStream`; si falla,
`isAvailable` es falso y se falla cerrado), `LoginMatcher.kt:43-48` (un subdominio solo coincide si
`PublicSuffix.isAvailable` y el host guardado **no** es un sufijo público). Ver
[ID-INT-20](internal-review.md#id-int-20): la comprobación del recurso en el APK existe, la de carga en
dispositivo y con R8 no. **Limitación**: la build de depuración **no** pasa por R8
(`isMinifyEnabled = true` solo en `release`, `android/app/build.gradle.kts:55`); por eso hay una variante
con el APK de release.

**Dispositivos.** Cualquiera (física o emulador). La variante R8 solo en emulador o dispositivo **sin** la
app oficial instalada (ver 5.R8).

**Prerrequisitos.**
- Elementos del 2.4: `alice.github.io` (`https://alice.github.io`) y `Sufijo github.io`
  (`https://github.io`), `Wikipedia` (`https://wikipedia.org`).
- El **navegador falso como predeterminado**: Ajustes del sistema → Apps → Apps predeterminadas → **App
  de navegador** → «Navegador falso». Comprueba con
  `adb shell cmd role get-role-holders android.app.role.BROWSER` (debe listar `test.fakebrowser`).
  Después, `adb shell am force-stop "$PKG"` (la comprobación de navegador se cachea 5 min:
  `BrowserCheck.kt:76`).
- OpenPassword como servicio de autorrelleno.

Esto usa el navegador falso porque, siendo el predeterminado, su `webDomain` se acepta
(`BrowserCheck.kt:68-73`; es el riesgo residual de DT-08) y permite probar cualquier dominio sin depender
de una página real. El contraste con un navegador real está en DT-06.

**Pasos.** Para cada fila, lanza
`adb shell am start -n test.fakebrowser/.MainActivity --es domain <dominio>`, toca el campo de usuario y
anota **qué elementos ofrece el desplegable** (foto):

| Dominio declarado | Esperado | Qué demuestra |
|---|---|---|
| `alice.github.io` | `alice.github.io` (coincidencia exacta). **No** `Sufijo github.io` | Un login de sufijo no cubre sus subdominios (`LoginMatcher.kt:47`) |
| `evil.github.io` | **Ninguno** (solo «Buscar en OpenPassword») | El caso del enunciado: `github.io` es sufijo público, y `alice.github.io` es otro dominio |
| `x.alice.github.io` | `alice.github.io` | **Control positivo**: un subdominio de un dominio registrable coincide **solo si la lista cargó** |
| `en.wikipedia.org` | `Wikipedia` | Segundo control positivo (necesita la lista) |
| `github.io` | `Sufijo github.io` | Coincidencia exacta con el sufijo guardado |

**Resultado esperado.** Como en la tabla. **Interpretación**: si las dos filas de control positivo
(`x.alice.github.io`, `en.wikipedia.org`) **no** ofrecen nada, la lista **no se cargó** y la app está
fallando cerrado (coincidencia exacta): es el hallazgo de ID-INT-20, no una pasada. Una pasada exige que
**los controles ofrezcan** el elemento y **los negativos no**.

**5.R8 · Variante con el APK de release** (solo emulador o dispositivo sin la app oficial; el paquete es
`io.github.rldona.openpassword`, sin sufijo, y **chocaría con la app real** del teléfono principal):

```sh
cd "$OP_REPO/android" && ./gradlew :app:assembleRelease
ls app/build/outputs/apk/release/        # app-release.apk o app-release-unsigned.apk
BT="$HOME/Library/Android/sdk/build-tools/37.0.0"
"$BT/apksigner" verify --print-certs app/build/outputs/apk/release/app-release.apk   # ¿firmado?
```

Si no está firmado, fírmalo con una clave **desechable** (nunca la de release) e instálalo:

```sh
keytool -genkeypair -keystore dt-desechable.jks -alias dt -keyalg RSA -keysize 2048 -validity 30 \
  -storepass desechable -keypass desechable -dname "CN=dt-pruebas"
"$BT/zipalign" -p 4 app/build/outputs/apk/release/app-release-unsigned.apk dt-alineado.apk
"$BT/apksigner" sign --ks dt-desechable.jks --ks-pass pass:desechable --out dt-release.apk dt-alineado.apk
adb install -r dt-release.apk
```

Repite la tabla con `PKG=io.github.rldona.openpassword` (otra bóveda de pruebas, en ese dispositivo). Los
comandos de firma son los estándar del SDK y **no se han ejecutado** al redactar este plan.

**Cubre.** ID-INT-20; A12 y A17 (límite de subdominios).

<a id="dt-06"></a>
### DT-06 · `webDomain` de un navegador real (Chrome)

**Objetivo.** Comprobar con **Chrome** que el autorrelleno recibe un `webDomain` verosímil, que se acepta
(Chrome está en `KnownBrowsers`), que ofrece el login correcto y que el token abre la actividad correcta.

**Qué se verifica.** `StructureParser.kt:27-28` (`targetFor`), `BrowserCheck.kt:28` (`com.android.chrome`
en la lista), `LoginMatcher.kt:22-36`, y el camino por token (`AutofillAuthActivity.kt:87-98`,
`AutofillRequestTokens.kt`).

**Dispositivos.** Físico con Chrome del sistema (anota su versión:
`adb shell dumpsys package com.android.chrome | grep versionName`). Navegador predeterminado: Chrome.

**Prerrequisitos.** Elemento `GitHub` (`https://github.com`). Servicio de autorrelleno de Chrome:
Chrome → Ajustes → *Servicios de autocompletar* → **Autocompletar con otro servicio**
([`android/README.md`](../../android/README.md), «Autorrelleno»), y OpenPassword como servicio del sistema.
**No envíes** el formulario de GitHub: basta con rellenar.

**Pasos.**

1. En Chrome abre `https://github.com/login`. Toca el campo de usuario. **¿Aparece `GitHub`** en el
   desplegable? Tócalo: ¿se rellenan usuario (`testuser`) y contraseña? Foto.
2. Bloquea OpenPassword (icono del candado de la lista, `VaultListScreen.kt:87`). Recarga la página y toca el campo: debe salir
   «Desbloquear OpenPassword».
3. Tócalo: se abre la ventana de OpenPassword. Anota el texto «Para: …» (debe ser `github.com`) y la
   sección («Coinciden» con `GitHub`). Desbloquea, elige `GitHub`: la ventana se cierra y Chrome se rellena.
4. Negativo: abre `https://en.wikipedia.org/w/index.php?title=Special:UserLogin` y toca el campo de
   usuario: `GitHub` **no** debe aparecer; `Wikipedia` sí (si existe el elemento).
5. Anota si en alguna ventana aparece un login de otro sitio sin que lo hayas elegido a mano.

**Resultado esperado.** Pasos 1-3: el login de `github.com` se ofrece y rellena en Chrome; el destino en la
ventana es `github.com`. Paso 4: `GitHub` no se ofrece en Wikipedia.

**Cubre.** A17; [ID-INT-16](internal-review.md#id-int-16) (corrección: solo se cree el `webDomain` de un
navegador).

<a id="dt-07"></a>
### DT-07 · App que se declara navegador

**Objetivo.** Comprobar que una app que declara un `intent-filter` `VIEW` `http`/`https` **y** un
`webDomain` falso **no** recibe datasets web, porque no es un navegador conocido ni el predeterminado.

**Qué se verifica.** `BrowserCheck.kt:68-73` (`isBrowser`: está en `KnownBrowsers.PACKAGES` **o** es el
predeterminado y atiende `https` y `http`) y `:44` («declarar un filtro no basta: no exige permiso»). Es la
**segunda corrección** de ID-INT-16 (`internal-review.md`, «Segunda corrección»).

**Dispositivos.** Cualquiera con un navegador conocido como predeterminado (Chrome, Firefox…).

**Prerrequisitos.** Elemento `Banco falso` (`https://bank.example`). `fakebrowser` instalado y **no**
predeterminado: `adb shell cmd role get-role-holders android.app.role.BROWSER` no debe listar
`test.fakebrowser`. `adb shell am force-stop "$PKG"` (caché fría). OpenPassword como servicio de
autorrelleno.

**Pasos.**

1. `adb shell am start -n test.fakebrowser/.MainActivity --es domain bank.example`.
2. Toca el campo de usuario. Anota qué ofrece el desplegable (foto): ¿aparece **`Banco falso`**?
3. Toca «Buscar en OpenPassword». En la ventana anota: el texto «Para: …», el título de la sección
   («Coinciden» o «Elige un login») y si hay una casilla «Recordar el login elegido para esta app».
   **No elijas ningún login**; cierra con la X.
4. Bloquea OpenPassword y repite 1-2: debe ofrecer «Desbloquear OpenPassword».
5. Repite 1-3 sin reiniciar el proceso, tras esperar **más de 5 min** (la caché caduca,
   `BrowserCheck.kt:76`), para ver que el resultado no cambia.

**Resultado esperado.** El desplegable **no** ofrece `Banco falso`; solo «Buscar en OpenPassword» (o
«Desbloquear…»). En la ventana: «Para: test.fakebrowser» (el paquete, **no** `bank.example`), «Elige un
login» y la casilla «Recordar…» visible (porque se trata como una app).

**Cubre.** A17; ID-INT-16 (segunda corrección).

<a id="dt-08"></a>
### DT-08 · Navegador predeterminado

**Objetivo.** Documentar el comportamiento cuando el usuario elige una app como navegador
predeterminado: es el **riesgo residual** de A17 («un navegador que el propio usuario elija como
predeterminado y sea malicioso es creído»).

**Qué se verifica.** `BrowserCheck.kt:83-87` (`resolveActivity` de `ACTION_VIEW` `https` con
`MATCH_DEFAULT_ONLY`; el paquete `android`, el selector del sistema, se descarta) y `:72`
(`packageName == current.default && packageName in current.packages`); `AutofillAuthActivity.kt:102,124`
(`canRemember` falso en navegadores).

**Dispositivos.** Cualquiera. **Al terminar, restaura el navegador original** (2.7).

**Prerrequisitos.** Como DT-07 (haber hecho DT-07 primero, con el navegador falso aún no predeterminado).

**Pasos.**

1. Ajustes del sistema → Apps predeterminadas → **App de navegador** → «Navegador falso».
   `adb shell cmd role get-role-holders android.app.role.BROWSER` debe listar `test.fakebrowser`.
2. `adb shell am force-stop "$PKG"` y desbloquea OpenPassword.
3. `adb shell am start -n test.fakebrowser/.MainActivity --es domain bank.example`; toca el campo de
   usuario. Anota si el desplegable ofrece **`Banco falso`** (foto).
4. Toca «Buscar en OpenPassword» (o el otro desplegable) y anota «Para: …» y si hay casilla «Recordar…».
5. Restaura Chrome (o el navegador original) como predeterminado, `adb shell am force-stop "$PKG"`, y
   repite 3: debe volver al comportamiento de DT-07.

**Resultado esperado (documentado).** Con el navegador falso como predeterminado **se cree su `webDomain`**:
se ofrece `Banco falso` directamente, la ventana dice «Para: bank.example» y **no** hay casilla «Recordar…».
Eso **no es un fallo**: es el riesgo residual descrito. El resultado es `pasa` si coincide con esto y
`falla` si no (por ejemplo, si se ofrece sin ser el predeterminado, o no se ofrece siéndolo: ambos
contradicen `threat-model.md` A17).

**Cubre.** A17 (riesgo residual); ID-INT-16.

<a id="dt-09"></a>
### DT-09 · Autorrelleno de extremo a extremo

**Objetivo.** Recorrer en un navegador real: guardar un login, rellenarlo, actualizar su contraseña, y el
camino por token con el baúl bloqueado, incluyendo la rotación de pantalla.

**Qué se verifica.** `OpAutofillService.kt:37-45` (`SaveInfo`), `:55-70` (`onSaveRequest`: la contraseña
tecleada se queda en memoria y la ventana recibe solo un token), `SaveLoginActivity` («Guardar»,
«Actualizar «…»», «Guardar como nuevo»), `AutofillAuthActivity.kt:87-98` (extras antiguos descartados,
solicitud por token, falla cerrado) y `:159-162` (`RequestHolder` conserva la solicitud al rotar).

**Dispositivos.** Físico con Chrome, API 33+ (idealmente también uno de API 28-30).

**Prerrequisitos.** Una página de acceso **propia** (no envíes datos, ni siquiera inventados, a un sitio
ajeno). Con GitHub Pages: un repositorio público `<tu-usuario>.github.io` con un `login.html`
(`<form action="#">`: no hay servidor, no se envía nada):

```html
<!doctype html><meta charset="utf-8"><title>Login de prueba</title>
<form action="#">
  <input name="user" type="text" autocomplete="username" placeholder="usuario">
  <input name="pass" type="password" autocomplete="current-password" placeholder="contraseña">
  <button>Entrar</button>
</form>
```

Apunta la URL: `https://<tu-usuario>.github.io/login.html`. **Sin** elemento guardado para ese host.
Chrome con OpenPassword como servicio de autocompletar (DT-06). Borra el repositorio al terminar.

**DT-09a · Guardar.**

1. En Chrome abre la página; escribe `alice` y `Prueba-pw-A`; pulsa **Entrar**.
2. Debe aparecer el aviso del sistema «Guardar en OpenPassword». Acéptalo: se abre «Guardar en
   OpenPassword» con «Para: `<tu-usuario>.github.io`» y el usuario relleno. Pulsa **Guardar**.
3. Abre OpenPassword: el login existe con esa URL. Repite 1-2 pero **rechaza** el aviso: no debe
   guardarse nada.

**DT-09b · Rellenar.** Recarga la página y toca el campo de usuario: el desplegable ofrece el login nuevo;
tócalo: se rellenan `alice` y `Prueba-pw-A`.

**DT-09c · Actualizar contraseña.** Borra los campos, escribe `alice` y `Prueba-pw-B`, **Entrar**. El aviso
de guardado debe proponer **actualizar** el login existente («Actualizar «…»»). Acepta; en el elemento, la
contraseña es `Prueba-pw-B` y el historial de contraseñas conserva `Prueba-pw-A`.

**DT-09d · Token y rotación.**

1. Fija la rotación: `adb shell settings put system accelerometer_rotation 0` y
   `adb shell settings put system user_rotation 0`. Bloquea OpenPassword (candado de la lista).
2. En Chrome, recarga la página, toca el campo → **Desbloquear OpenPassword** → se abre su ventana.
3. **Rota la pantalla** con `adb shell settings put system user_rotation 1` **antes** de escribir la
   contraseña. Anota si la ventana sigue abierta.
4. Escribe la contraseña y desbloquea (aparece la lista «Coinciden»). Vuelve a rotar
   (`user_rotation 0`). Anota si sigue abierta.
5. Elige el login: la ventana se cierra y Chrome rellena los campos.
6. Restaura la rotación (2.7).

**Resultado esperado.** a) El login se guarda solo tras confirmar. b) Se rellena. c) Se propone
actualizar, no duplicar. d) La ventana **no se cierra** al rotar y el login se rellena (la solicitud
sobrevive a la rotación en el `ViewModel` aunque el token sea de un solo uso). Si la ventana se cierra
sola tras rotar, `falla`: el flujo por token pierde la solicitud.

**Cubre.** A12, A18; [ID-INT-26](internal-review.md#id-int-26); funcionalidad de guardado/actualización.

<a id="dt-10"></a>
### DT-10 · «Recordar para esta app»

**Objetivo.** Comprobar que la casilla «Recordar el login elegido para esta app» solo se ofrece (y solo
actúa) en apps normales, nunca en navegadores.

**Qué se verifica.** `AutofillAuthActivity.kt:102` (`isBrowserApp`), `:124`
(`canRemember = target is FillTarget.App && !isBrowserApp`) y `PickLogin` (`:195-198`: al elegir a mano un
login que no coincidía, con la casilla marcada, se le añade `androidapp://<paquete>` a sus URL), más el
texto de aviso para webs sin coincidencia («Ningún login tiene guardado …»).

**Dispositivos.** Cualquiera. Chrome predeterminado (como DT-07).

**Prerrequisitos.** Elementos `Banco falso` y `GitHub`. `fakebrowser` no predeterminado.

**Pasos.**

1. **App normal.** `adb shell am start -n test.fakebrowser/.MainActivity --es domain bank.example`; toca el
   campo → «Buscar en OpenPassword». Anota que la casilla «Recordar…» está visible y marcada.
2. Elige `Banco falso` con la casilla marcada. Vuelve a OpenPassword y abre `Banco falso`: sus URL
   incluyen ahora `androidapp://test.fakebrowser`.
3. Reabre el navegador falso y toca el campo: el desplegable debe ofrecer `Banco falso` **directamente**
   (coincidencia por paquete exacto).
4. **Navegador.** En Chrome abre `https://en.wikipedia.org/w/index.php?title=Special:UserLogin`, toca el campo
   de usuario → «Buscar en OpenPassword». Anota: **no** hay casilla «Recordar…» y se muestra el texto «Ningún
   login tiene guardado en.wikipedia.org. Comprueba que es el sitio que esperas antes de rellenar.»
5. Elige `GitHub` (a mano). Abre `GitHub` en OpenPassword: sus URL **no** deben haber ganado
   `androidapp://com.android.chrome` ni nada parecido.
6. Limpieza: quita la URL `androidapp://test.fakebrowser` de `Banco falso`.

**Resultado esperado.** Casilla visible solo en el paso 1; en Chrome, ausente y sin URL añadida.

**Cubre.** ID-INT-26 (`:102,124`); A12.

<a id="dt-11"></a>
### DT-11 · Aviso de root

**Objetivo.** Comprobar que el aviso aparece cuando hay una señal de root o de compilación de depuración,
que **no bloquea** nada y que el descarte funciona y persiste.

**Qué se verifica.** `RootSignals.kt:17-47` (`RootDetector.evaluate`: `SU_BINARY`, `ROOT_MANAGER_APP`,
`TEST_KEYS`, `DEBUG_BUILD` si `Build.TYPE` es `userdebug` o `eng`; `shouldWarn`; texto
`ROOT_WARNING_TEXT`), `AndroidDeviceProbe.kt`, `OpenPasswordApp.kt:38-56` (señales y descarte),
`Components.kt:226-235` (`RootWarning`), `UnlockScreen.kt:145` (descartable) y `SettingsScreen.kt:235`
(informativo, sin descarte). Decisión de diseño: [ADR-AUD-06](decisions.md); **nunca bloquea**.

**Dispositivos.** Un emulador `userdebug` (imagen «Google APIs», 2.9). **No** se hace root al teléfono
principal. Opcional: un dispositivo dedicado con Magisk (no es necesario: `DeviceProbe` es la frontera de
prueba; `RootDetectorTest` cubre cada señal en la JVM).

**Prerrequisitos.** Emulador arrancado, `ANDROID_SERIAL` apuntando a él
(`adb devices` solo debe listar el emulador). Instala el APK de depuración y crea una bóveda de pruebas.
```sh
adb -e shell getprop ro.build.type        # userdebug
adb -e shell getprop ro.build.tags        # normalmente test-keys en estas imágenes
adb -e shell ls /system/xbin/su /system/bin/su 2>&1
adb -e install -r "$OP_REPO/android/app/build/outputs/apk/debug/app-debug.apk"
```

**Pasos.**

1. Abre OpenPassword con el baúl bloqueado. Anota si la pantalla de desbloqueo muestra la tarjeta con «Este
   dispositivo parece tener root o una compilación de depuración…» y el botón **Entendido**.
2. **Sin descartar**, desbloquea con la contraseña. Anota si hay algún bloqueo o impedimento.
3. Ajustes → sección «Seguridad»: anota si el mismo texto aparece como bloque informativo **sin** botón
   «Entendido».
4. Bloquea, toca **Entendido** en la pantalla de desbloqueo: la tarjeta debe desaparecer.
5. `adb -e shell am force-stop "$PKG"`, vuelve a abrir: la tarjeta no debe reaparecer (el descarte se
   guarda con el conjunto de señales). Los Ajustes siguen mostrando el bloque.
6. **Control negativo** en un teléfono normal (`ro.build.type=user`, sin `su`): la tarjeta **no** debe
   aparecer (salvo ROM personalizada; se anota la causa).

**Resultado esperado.** 1: aparece. 2: no bloquea. 3: informativo. 4-5: el descarte funciona y persiste.
6: sin falsos positivos en un teléfono de serie.

**Cubre.** A10; ADR-AUD-06.

<a id="dt-12"></a>
### DT-12 · Biometría en Android 9

**Objetivo.** Comprobar el arreglo de biometría en API 28: Ajustes no se cae y la huella se ofrece.

**Qué se verifica.** `Biometrics.kt:22-49` (`availabilityCheckFor`: API 28 usa la rama `Fingerprint`),
`:63-74` (`FingerprintManager` por reflexión, porque ya no está en los stubs de `compileSdk` 37),
`:79-` (`authenticateBiometric`: en Android 9 el aviso es solo de huella y siempre pide confirmar),
`SettingsScreen.kt:83,254` (la fila «Desbloquear con huella» solo aparece si `strongBiometricsAvailable`)
y `UnlockScreen.kt` (botón de huella). Origen: commit `2c6ba2d` («biometría en Android 9»).

**Dispositivos.** API 28. Un teléfono con Android 9 con huella, o el emulador `system-images;android-28;
google_apis;arm64-v8a` (o `x86_64`) con **huella virtual**. Opcional: API 29 (rama `ManagerLegacy`).

**Prerrequisitos.** App instalada y bóveda de pruebas creada. El dispositivo con bloqueo de pantalla (PIN) y
**una huella inscrita**. En el emulador: Ajustes → Seguridad → Huella → inscribir; para «tocar el sensor»:
`adb -e emu finger touch 1`.

**Pasos.**

1. **Sin huella inscrita** (antes de inscribir): abre Ajustes de OpenPassword. Anota si la app se cae (no
   debe) y que la fila «Desbloquear con huella» **no** aparece.
2. Inscribe una huella. Vuelve a abrir Ajustes: anota si se cae y si la fila **aparece**.
3. Actívala: se muestra el aviso biométrico del sistema. «Toca» el sensor. Anota el resultado.
4. Bloquea y desbloquea con la huella (botón de la pantalla de desbloqueo). Anota si funciona.
5. `adb logcat -b crash -d` debe estar vacío de `OpenPassword`/`FingerprintManager`/`NoSuchMethod`.

**Resultado esperado.** Ajustes no se cae en ningún caso; la fila aparece solo con huella inscrita; la
huella activa y desbloquea. Una excepción por reflexión (p. ej. `NoSuchMethodException`) o un cierre de
Ajustes es `falla`.

**Cubre.** Arreglo de Biometrics (`2c6ba2d`); `internal-review.md` §3 (claves de Keystore en API 28-29).

<a id="dt-13"></a>
### DT-13 · Importación KDBX 4 con un fichero real

**Objetivo.** Cerrar lo que dice [`android/README.md`](../../android/README.md): «La lectura de KDBX 4 aún
no se ha probado con un fichero real». Y [`core/src/import/testdata/README.md`](../../core/src/import/testdata/README.md),
«Pendiente»: falta un KDBX 4 real creado desde la interfaz de KeePassXC.

**Qué se verifica.** `core/src/import/kdbx.rs` (ruta de KDBX 4: cabecera, HMAC por bloques, ChaCha20,
Argon2; límites en `:33-41` y `:544-561`) a través de la importación de la app
(`ExternalImport.kt`; mensajes en `:65-78`). Nota: `keepassxc-cli` solo crea KDBX 3.1 (comprobado con
KeePassXC 2.8.0: `db-create` escribe versión 3.1 con KDF «AES»), por lo que **el KDBX 4 se crea desde la
interfaz gráfica**.

**Dispositivos.** Cualquiera (con ≥ 1 GiB de RAM libre para 13a-13c).

**Prerrequisitos.** KeePassXC (se anota la versión: `keepassxc-cli --version`). Los datos son
**inventados**.

**Cómo generar los ficheros** (interfaz de KeePassXC; Base de datos → Configuración → Seguridad):

| Fichero | Cifrado | KDF | Credenciales |
|---|---|---|---|
| `kdbx4-a.kdbx` (13a) | ChaCha20 | Argon2id, 64 MiB, 10 iteraciones, 2 hilos | Contraseña `prueba-kdbx4-a` |
| `kdbx4-b.kdbx` (13b) | AES-256 | Argon2d, 64 MiB, 10 iteraciones, 2 hilos | Contraseña `prueba-kdbx4-b` |
| `kdbx4-c.kdbx` (13c) | ChaCha20 | Argon2id, 64 MiB | Contraseña `prueba-kdbx4-c` **y** archivo de clave (`kdbx4-c.keyx`, creado por KeePassXC) |
| `kdbx4-d.kdbx` (13d) | **Twofish** | Argon2d, 64 MiB | Contraseña `prueba-kdbx4-d` |
| `kdbx4-e.kdbx` (13e) | ChaCha20 | Argon2id, **1024 MiB** de memoria, 3 iteraciones | Contraseña `prueba-kdbx4-e` |

Contenido de 13a, 13b y 13c (el mismo en los tres): grupo raíz y estos apuntes.

| Apunte | Datos |
|---|---|
| `Login básico` | usuario `alice@example.com`, contraseña `Prueba-k-1`, URL `https://example.com`, notas «nota de prueba» |
| `Con TOTP` | un campo TOTP de KeePassXC (clic derecho → *Configuración de TOTP…*, secreto `JBSWY3DPEHPK3PXP`) |
| `Campo protegido` | un atributo personalizado **protegido** `PIN` = `4321` |
| `Espacios` | contraseña `  con espacios  ` (dos espacios al principio y al final) |
| `Unicode` | título `Ñandú ✓ — prueba` y usuario `ñ@example.com` |
| `Con historial` | edita la contraseña dos veces (la entrada guarda historial) |
| `En la papelera` | crea un apunte y **elimínalo** (va a la papelera) |

Comprueba el formato antes de llevarlo al teléfono. La versión está en los bytes 8-11 de la cabecera
(menor y mayor, en *little-endian*): un KDBX 3.1 de `keepassxc-cli` muestra `0100 0300`; un KDBX 4.0 debe
mostrar `0000 0400` (un 4.1, `0100 0400`). Y comprueba los parámetros:

```sh
xxd -l 12 kdbx4-a.kdbx                       # ... 0000 0400  => KDBX 4.0
keepassxc-cli db-info kdbx4-a.kdbx           # cifrado y KDF (en tu idioma: «Cifrado», «KDF»)
adb push kdbx4-a.kdbx kdbx4-b.kdbx kdbx4-c.kdbx kdbx4-c.keyx kdbx4-d.kdbx kdbx4-e.kdbx /sdcard/Download/
```

Foto o captura de la pantalla de seguridad de KeePassXC como evidencia de qué se probó.

**Pasos (cada fichero).** Ajustes → **Importar de otro gestor** → elige el fichero → escribe la contraseña
(y, en 13c, elige `kdbx4-c.keyx`).

- **13a, 13b, 13c**: anota el resumen que muestra la app antes de importar y pulsa importar. Después
  comprueba cada apunte en el baúl:
  - `Login básico`: título, usuario, contraseña, URL y notas idénticos.
  - `Con TOTP`: el detalle muestra un código de 6 dígitos con cuenta atrás, y coincide con
    `echo 'otpauth://totp/Prueba:alice?secret=JBSWY3DPEHPK3PXP' | cargo run -q --manifest-path "$OP_REPO/Cargo.toml" -p opvault-cli -- totp`
    en el mismo intervalo de 30 s.
  - `Campo protegido`: `PIN` = `4321`, oculto hasta revelarlo.
  - `Espacios`: la contraseña conserva los espacios del principio y del final.
  - `Unicode`: sin caracteres rotos.
  - `Con historial`: solo la contraseña **actual** (el README: «sin papelera ni historial»).
  - `En la papelera`: **no** se importa.
  - Contador total: el de apuntes visibles menos los de la papelera.
- **Reimportar** el mismo fichero (13a): no debe duplicar lo que ya existe.
- **Contraseña incorrecta** (13a): mensaje «Contraseña o archivo de clave incorrectos…»
  (`ExternalImport.kt:66-67`) y se puede reintentar sin volver a elegir el fichero.
- **13c sin el archivo de clave**: mismo mensaje.
- **13d (Twofish)**: «Esta base de KeePass usa Twofish. Cámbiala a AES-256 o ChaCha20 en la configuración de
  la base.» (`ExternalImport.kt:70-71`).
- **13e (1 GiB)**: «La protección de esta base de KeePass es demasiado costosa para un teléfono. Bájala en
  la configuración de la base.» (`:72-73`; el techo de KDBX está en `kdbx.rs:33-41`: 512 MiB de memoria y 3
  GiB·pasada). La app **no debe cerrarse** y debe rechazarlo **antes** de derivar (inmediato).

**Resultado esperado.** 13a-13c importan con el contenido anterior; 13d y 13e se rechazan con los mensajes
indicados; la app no se cierra en ningún caso. Cualquier diferencia en un campo es `falla` y se anota cuál.

**Cubre.** README de Android («KDBX 4 sin probar con un fichero real»); [ID-INT-02](internal-review.md#id-int-02)
(política de KDF de KeePass frente al techo móvil: lo que cubre aquí es el rechazo; la política queda
abierta). Si 13a y 13b pasan, el fichero puede añadirse a `core/src/import/testdata/` para una prueba de
Rust (ver 7).

<a id="dt-14"></a>
### DT-14 · Techo de KDF y de RAM

**Objetivo.** Importar copias `.opvault` con parámetros de KDF altos y comprobar el mensaje **sin que la app
se cierre**; y observar qué pasa justo en el techo.

**Qué se verifica.** `ffi/src/lib.rs:33` (`MOBILE_MAXIMUM` = 512 MiB, 6 pasadas, 8 hilos) y `:452-480`
(rechaza **antes** de derivar), `KdfMemory.kt:10-11` (`kdfMemoryFits`: la memoria no puede pasar de la mitad
de la RAM), `VaultSession.kt:128-131,141,170` (`checkKdfFits`), el mensaje en `VaultSession.kt:513-515`, y el
riesgo abierto: un fallo de memoria en Argon2 aborta el proceso
([`decisions.md`](decisions.md), «Riesgos que quedan abiertos»; `ffi`/`argon2` 0.5, asignación infalible).

**Dispositivos.** Todos los que haya; **la prueba 14b es más reveladora en el de menos RAM** (se anota
`MemTotal`).

**Prerrequisitos.** Una herramienta desechable, **fuera del repositorio**, que cree copias con una KDF a
medida (la CLI `opvault sample` solo usa `KdfParams::RECOMMENDED`, `cli/src/main.rs:168`). Se compiló con
esta receta (Rust estable, `Cargo.lock` del repositorio) y generó los dos ficheros de abajo:

```sh
mkdir -p ~/openpassword-kdfgen/src && cd ~/openpassword-kdfgen
cat > Cargo.toml <<EOF
[package]
name = "kdfgen"
version = "0.0.0"
edition = "2024"

[dependencies]
op-core = { path = "$OP_REPO/core" }
EOF
cp "$OP_REPO/Cargo.lock" .
cat > src/main.rs <<'EOF'
use op_core::{KdfParams, SecretKey, UnlockedVault, backup};

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let (m, t, p, out, sk) = (a[1].parse().unwrap(), a[2].parse().unwrap(), a[3].parse().unwrap(), &a[4], &a[5]);
    let sk = SecretKey::parse(sk).unwrap();
    let v = UnlockedVault::create("prueba-kdf-alto", &sk, KdfParams::argon2id(m, t, p)).unwrap();
    std::fs::write(out, backup::write(&v, &[], 0).unwrap()).unwrap();
}
EOF
cargo build --release

SK="$(cargo run -q --manifest-path "$OP_REPO/Cargo.toml" -p opvault-cli -- new-secret-key)"; echo "$SK"   # apúntala: PRUEBAS
./target/release/kdfgen 1048576 3 4 alto.opvault "$SK"     # 1 GiB, 3 pasadas, 4 hilos: por encima del techo
./target/release/kdfgen 524288 6 8 techo.opvault "$SK"     # 512 MiB, 6, 8: justo el techo
cargo run -q --manifest-path "$OP_REPO/Cargo.toml" -p opvault-cli -- inspect alto.opvault | grep -A4 '"kdf"'
adb push alto.opvault techo.opvault /sdcard/Download/
```

Cada copia se abre con la contraseña `prueba-kdf-alto` y la clave secreta `$SK`. Las copias están vacías
(sin elementos): lo que se prueba es la derivación. Ambas tardaron ~2 s en generarse en un ordenador.

**DT-14a · Por encima del techo.**

1. Anota el PID: `adb shell pidof "$PKG"`.
2. Ajustes → **Importar copia** → `alto.opvault`. Escribe la contraseña y la clave secreta, **Importar**.
3. Anota el mensaje y cuánto tarda en salir. Vuelve a ejecutar `pidof`.
4. `adb logcat -b crash -d` y `adb logcat -d | grep -i -E "lowmemory|lmkd.*openpassword|OOM"`.

**DT-14b · En el techo.**

1. Igual con `techo.opvault`. Mira el tiempo con un cronómetro y anota si la app responde, si se muestra
   algún mensaje, y el PID antes y después (`pidof`).
2. Si el dispositivo tiene ≥ 1 GiB de RAM el chequeo de Kotlin (`totalMem / 2`) lo deja pasar y se reservan
   512 MiB de verdad.

**Resultado esperado.**

- **14a**: sale de inmediato «Esta copia necesita 1024 MiB de memoria para abrirse y este dispositivo no
  puede darlos. Ábrela en un dispositivo con más memoria.»; el PID no cambia; el baúl sigue desbloqueado y
  sin cambios; sin entradas en el registro de cierres.
- **14b**: no hay un resultado «correcto» único. Es aceptable que abra (tarde unos segundos) o que se
  rechace con el mensaje anterior en un dispositivo con poca RAM. **Un cierre de la app (PID distinto,
  entrada de `lmkd`, ANR) es `falla`**: confirma el riesgo abierto «fallo de memoria en Argon2 = aborto» y
  se registra como hallazgo (sección 7), no se «arregla» aquí.

El caso «la RAM no alcanza» de `kdfMemoryFits` solo se da con menos de 1 GiB de RAM para un techo de 512
MiB; en un teléfono actual solo se puede provocar con 14a (que dispara el techo nativo, no el de RAM). El
chequeo de RAM lo cubre `KdfMemoryTest` en la JVM.

**Cubre.** ADR-AUD-07; riesgo abierto de aborto por memoria; ID-INT-02 (el techo en el camino `.opvault`).

<a id="dt-15"></a>
### DT-15 · Copia automática y restauración

**Objetivo.** Comprobar que la copia automática se escribe tras un cambio, que la rotación solo borra
copias propias, y que una copia automática se restaura en un baúl nuevo de pruebas.

**Qué se verifica.** `AutoBackup.kt:52` (`setFolder`: primera copia al elegir la carpeta), `:69-80`
(`onVaultChanged` con `DEBOUNCE_MS` = 5 s y `onUnlocked`), `:96-101` (con el baúl bloqueado se queda
pendiente), `:124-146` (`write` y rotación; `KEEP` = 10 en `:178`), `BackupNames.kt:8-20` (solo nombres
`openpassword-auto-AAAAMMDD-HHMMSS.opvault`), `VaultSession.kt:137` (`restore`: solo sin baúl en el
dispositivo) y `RestoreScreen.kt` (bienvenida).

**Dispositivos.** Físico, API 33+ (SAF y carpetas).

**Prerrequisitos.** Bóveda de pruebas con algunos elementos. Una **subcarpeta propia** en Documentos (por
ejemplo `OP-copias-prueba`; Android 11+ no deja elegir la raíz de «Download» ni «Documents»):

```sh
adb shell mkdir -p /sdcard/Documents/OP-copias-prueba
adb shell 'echo notas > /sdcard/Documents/OP-copias-prueba/notas-propias.txt'
adb push demo.opvault /sdcard/Documents/OP-copias-prueba/openpassword-2026-10-30.opvault
```

(`demo.opvault` de DT-03.) Estos dos ficheros no empiezan por `openpassword-auto-`: **no deben borrarse**.

**Pasos.**

1. Ajustes → **Copia automática** → elige `OP-copias-prueba`. Debe hacerse una primera copia al momento.
2. `adb shell ls -l /sdcard/Documents/OP-copias-prueba/`: anota los ficheros `openpassword-auto-…opvault`.
3. Cambia el título de un elemento (por ejemplo, `Banco falso` → `Banco falso 2`). Espera ≥ 10 s. Vuelve a
   listar: debe haber **una copia nueva**.
4. Comprueba que esa copia contiene el cambio (la CLI lee la copia con la clave secreta de la bóveda de
   pruebas; **solo datos de prueba**):
   ```sh
   adb pull /sdcard/Documents/OP-copias-prueba/<la-copia-nueva>.opvault .
   printf '<contraseña-de-pruebas>\n' | cargo run -q --manifest-path "$OP_REPO/Cargo.toml" -p opvault-cli -- \
     decrypt <la-copia-nueva>.opvault --password-stdin --secret-key '<clave-secreta-de-pruebas>' | grep -i "banco falso"
   ```
5. **Bloqueado**: bloquea el baúl, cambia nada (no se puede), y desbloquea. Anota si se hace una copia al
   desbloquear cuando había cambios pendientes.
6. **Rotación**: crea 10 copias falsas con nombres válidos y antiguos, y haz un cambio real:
   ```sh
   for i in 01 02 03 04 05 06 07 08 09 10; do
     adb shell "echo falsa > /sdcard/Documents/OP-copias-prueba/openpassword-auto-20200101-0000$i.opvault"
   done
   ```
   Cambia un elemento, espera ≥ 10 s y lista: deben quedar **10** ficheros `openpassword-auto-…` (los más
   nuevos, incluida la copia real) y **siguen** `notas-propias.txt` y `openpassword-2026-10-30.opvault`.
7. **Restaurar**: `adb shell pm clear "$PKG"` (solo la app de depuración, con la bóveda de pruebas; ver
   2.2). Abre la app: bienvenida → **Restaurar** → elige la copia automática más reciente → escribe la clave
   secreta de pruebas y la contraseña maestra de pruebas. Anota si restaura y si el cambio del paso 3 está.
8. Desbloquea con la contraseña de pruebas.

**Resultado esperado.** Copia al elegir la carpeta; copia nueva tras el cambio (con debounce de 5 s);
al desbloquear con cambios pendientes se hace la copia; la rotación deja 10 copias propias y no toca otros
ficheros; la restauración devuelve la bóveda de pruebas con el cambio.

**Cubre.** Funcionalidad de copia (A4, A5: la copia sale cifrada y autenticada, ver
[`threat-model.md`](../threat-model.md)); recuperación ante pérdida.

<a id="dt-16"></a>
### DT-16 · Bloqueo automático

**Objetivo.** Medir en el dispositivo los tres disparadores de bloqueo: inactividad de 5 min, 30 s tras
salir de la app, y pantalla apagada.

**Qué se verifica.** `VaultSession.kt:482-484` (`BACKGROUND_TIMEOUT_MS` = 30 s, `PICKER_TIMEOUT_MS` = 3 min,
`IDLE_TIMEOUT_MS` = 5 min), `:389-398` (`onAppBackgrounded`: temporizador con `Handler` que bloquea aunque
no se vuelva) y `:399-406` (`onAppForegrounded`: comprobación al volver, porque los `Handler` pueden no
ejecutarse con el dispositivo dormido), `:424-427` (`lockIfIdle`), `MainActivity.kt:33-37` (comprueba cada
15 s mientras la app está visible) y `OpenPasswordApp.kt:75-80` (receptor de `ACTION_SCREEN_OFF`: bloquea
al instante, para todo el proceso).

**Dispositivos.** Físico. Para DT-16a el apagado de pantalla debe ser mayor de 5 min:
`adb shell settings put system screen_off_timeout 600000` (restaura el original: 2.7).

**Prerrequisitos.** Bóveda de pruebas. Un cronómetro **externo** al teléfono (el del ordenador o un
reloj). Evidencia: vídeo con otra cámara que muestre el cronómetro y el teléfono.

**DT-16a · Inactividad.**

1. Desbloquea. **No toques la pantalla** y pon en marcha el cronómetro.
2. Mira a los 4:50 (sigue desbloqueado) y espera el bloqueo. Anota el instante en el que aparece la pantalla
   de desbloqueo.

**DT-16b · 30 s tras salir.**

1. Desbloquea. Pulsa Inicio (sale de la app). Cronómetro a 0.
2. **A los 20 s** vuelve a OpenPassword (por Recientes): debe seguir desbloqueado.
3. Sal otra vez, espera **40 s** y vuelve: debe pedir desbloqueo.
4. **Sin volver**: desbloquea, sal, espera 40 s, y sin abrir OpenPassword usa el autorrelleno del
   navegador falso (`--es domain bank.example`; OpenPassword como servicio): debe ofrecer **«Desbloquear
   OpenPassword»** y **no** `Banco falso`. (El bloqueo ocurre aunque no se vuelva a la app: A13.)
5. (Opcional) Ajustes → **Exportar copia cifrada**: el selector de ficheros alarga el margen a 3 min **una
   vez** (`beforeSystemPicker`, `PICKER_TIMEOUT_MS`): anota si pasados 40 s sigue desbloqueado.

**DT-16c · Pantalla apagada.**

1. Desbloquea y apaga la pantalla con el botón de encendido. Enciéndela a los 2-3 s y desbloquea el
   teléfono: OpenPassword debe pedir desbloqueo.
2. Repítelo en la pantalla del **autorrelleno**: con la ventana «Rellenar con OpenPassword» abierta, apaga y
   enciende: debe pedir desbloqueo (el receptor es de todo el proceso, no de una actividad).

**Resultado esperado.** a) Bloquea entre 5:00 y 5:15 (la comprobación va cada 15 s). b) A los 20 s sigue
abierto; a los 40 s, bloqueado; y bloqueado también sin volver. c) Bloqueado al instante en las dos
ventanas.

**Cubre.** A13.

<a id="dt-17"></a>
### DT-17 · TOTP: QR, imagen y pegado

**Objetivo.** Comprobar las tres entradas de un código TOTP y que el código mostrado es correcto.

**Qué se verifica.** `qr/QrScanner.kt` (cámara; `CAMERA` solo al pulsar «Escanear QR»; manifiesto
`required="false"`), `qr/QrDecoder.kt:45-51` (solo `otpauth://totp/`), `ItemEditorScreen.kt:116-120`
(validación al guardar) y `:156-169` (imagen; mensajes), `ItemDetailScreen.kt:141` (se copia el código,
nunca el secreto). Amenaza A16.

**Dispositivos.** Físico con cámara.

**Prerrequisitos.** Un QR de prueba, con un secreto inventado, y otro que **no** sea TOTP:

```sh
brew install qrencode          # o el gestor de paquetes de tu sistema
qrencode -s 10 -o totp.png 'otpauth://totp/Prueba:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Prueba'
qrencode -s 10 -o web.png  'https://example.com'
adb push totp.png web.png /sdcard/Download/
echo 'otpauth://totp/Prueba:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Prueba' \
  | cargo run -q --manifest-path "$OP_REPO/Cargo.toml" -p opvault-cli -- totp      # código esperado y segundos
```

Abre `totp.png` a pantalla completa en el ordenador para la cámara. Un login nuevo `TOTP prueba` con un
campo TOTP.

**DT-17a · QR con la cámara.**

1. Editor del login → campo TOTP → **Escanear QR**. Anota que el permiso de cámara se pide **ahora** y no
   antes. **Deniega** una vez: anota que la app no se cae y que sigue siendo posible leer desde imagen.
2. Concédelo y apunta al QR: el campo se rellena con el enlace. Guarda. En el detalle comprueba que el
   **código de 6 dígitos coincide** con el de `opvault totp` en el mismo intervalo de 30 s.
3. Apunta la cámara a `web.png`: debe rechazarlo («Ese QR no es de verificación en dos pasos.», visible en
   el editor) y no rellenar el campo.
4. Anota que la app no guarda fotogramas: `adb shell ls /sdcard/DCIM /sdcard/Pictures` sin ficheros nuevos.

**DT-17b · QR desde una imagen** (sin permiso de cámara).

1. Campo TOTP → **Desde una imagen** → `totp.png`: «Código QR leído.» y el campo se rellena.
2. Repite con `web.png`: «Ese QR no es de verificación en dos pasos.»
3. Repite con una imagen sin QR (cualquier foto): «No se encontró ningún código QR en esa imagen.»

**DT-17c · Pegar.**

1. Pega en el campo `otpauth://totp/Prueba:alice@example.com?secret=JBSWY3DPEHPK3PXP` (cópialo desde el
   navegador falso o una nota) y guarda; luego prueba solo el secreto `JBSWY3DPEHPK3PXP`.
2. Prueba un valor inválido (`hola`): al guardar, «El código TOTP no es válido. Pega el enlace otpauth://
   o el secreto que te dio el servicio.»
3. En el detalle, copia el código: pégalo en el navegador falso: deben ser **6 dígitos, no el secreto**.

**Resultado esperado.** Los tres caminos aceptan el TOTP válido y rechazan lo demás con los mensajes
indicados; el código coincide con el de la CLI; el secreto no se copia.

**Cubre.** A16; funcionalidad TOTP. (La coincidencia de código con la CLI usa la misma implementación de
`op-core::totp`; para una referencia independiente puede usarse `oathtool -b --totp JBSWY3DPEHPK3PXP`.)

---

## 6. Automatización

Hoy **no hay ninguna prueba instrumentada en la CI** (no hay referencias a `androidTest`, `connected` ni
`emulator` en `.github/workflows/`), y las tres clases de `android/app/src/androidTest/kotlin/…/` son:
`EmergencyKitTest`, `OverlayProtectionTest` (4 tests: las tres actividades y un `ProtectedAlertDialog`,
ver ID-INT-13) y `VaultSessionTest` (con un espacio de nombres aislado por prueba). Se ejecutaron a mano el
30-oct-2026 en un dispositivo (17 tests en verde, sección 3.2). Nota: la tabla de tests de
[ADR-AUD-06](decisions.md) habla de un toque `FLAG_WINDOW_IS_OBSCURED` inyectado; **no se ha comprobado**
aquí que los tests lo hagan, solo que pasan.

### Qué se puede convertir en `androidTest`

| Prueba | ¿Instrumentada? | Cómo / por qué |
|---|---|---|
| DT-01, DT-03 (banderas) | **Parcial** | Comprobar `filterTouchesWhenObscured` y `FLAG_SECURE` en `AutofillAuthActivity` y `SaveLoginActivity` (necesitan un token de `AutofillRequestTokens.shared`) y en la ventana de un `ProtectedAlertDialog` con un toque inyectado con `FLAG_WINDOW_IS_OBSCURED` (Compose UI test). **No** prueban el comportamiento real del compositor (que el overlay se oculte): eso es manual |
| DT-02 | **No** (manual) | Depende de cómo el sistema marca los toques ante una ventana real |
| DT-04 | **Sí, con matices** | Un test con `UiAutomator` que copie, lleve otra actividad al frente y a los 30 s lea el portapapeles. Es exactamente lo que pide ID-INT-14 (API 29, 33 y 36) y es **lo más rentable de automatizar** |
| DT-05 | **Sí** | `PublicSuffix.isAvailable` y `registrableDomain("x.alice.github.io")` contra el APK. La build de depuración no pasa por R8: para cubrir R8 hay que ejecutarlo contra `release` (`testBuildType`), que es un cambio de build |
| DT-06, DT-09 | **No** | Necesitan Chrome real y el marco de autorrelleno del sistema |
| DT-07 | **Sí, parcial** | Con `test.fakebrowser` instalado, `CachedBrowserCheck.forPackageManager(packageManager).isBrowser("test.fakebrowser")` debe ser `false` (y valida el bloque `<queries>`). El «predeterminado» no se puede fijar sin privilegios: DT-08 es manual |
| DT-10 | **No** | UI del autorrelleno |
| DT-11 | **Sí, parcial** | En un emulador `userdebug`, `RootDetector.evaluate(AndroidDeviceProbe(context))` contiene `DEBUG_BUILD`; la tarjeta y el descarte son de UI |
| DT-12 | **Sí, parcial** | En un emulador API 28, `strongBiometricsAvailable(context)` no lanza excepción (reflexión sobre `FingerprintManager`) |
| DT-13 | **Mejor en Rust** | Añadir el KDBX 4 real a `core/src/import/testdata/` y un test de `kdbx.rs` (sin dispositivo, en la CI). El dispositivo solo añade la ruta del selector de ficheros y FFI |
| DT-14 | **Sí (14a)** | Una prueba de `VaultSession.importBackup` con `alto.opvault` como recurso (674 bytes). 14b reserva 512 MiB: no es apta para una CI |
| DT-15 | **Parcial** | Rotación (`BackupNames`, ya en JVM). El selector de carpeta (SAF) hace difícil automatizar el resto |
| DT-16 | **No recomendable** | Tiempos de 5 min y 30 s y apagado de pantalla reales; un reloj inyectable en `VaultSession` en la JVM sería más barato |
| DT-17 | **No** (cámara) | La decodificación desde imagen y el análisis de `otpauth://` ya tienen pruebas JVM (`QrDecoderTest`) |

### Cómo ejecutar las instrumentadas, con seguridad

> **No ejecutes `connectedAndroidTest` en el teléfono con datos reales.** Instala el APK de la app y el de
> pruebas en el dispositivo conectado y, según la versión de AGP, los desinstala al terminar (lo que borra
> los datos de la app de depuración). Además, `OverlayProtectionTest` lanza `MainActivity`, que toca el
> baúl real del paquete (su propio comentario lo advierte). Usa **solo un emulador o un dispositivo sin
> datos**.

```sh
adb devices -l                                   # solo debe listar el emulador
export ANDROID_SERIAL=emulator-5554              # el serial del emulador
cd "$OP_REPO/android"
./gradlew :app:connectedDebugAndroidTest
```

Antes, comprueba que `ANDROID_SERIAL` apunta al emulador. Este comando se ejecutó el 30-oct-2026 en un
dispositivo físico sin baúl (SM-S948B, API 37): 17 tests, todos en verde (ver «Sesión del 30-oct-2026»).
Los tests instrumentados desinstalaron la app de depuración al terminar, como advierte el aviso anterior.

---

## 7. Criterio de cierre

### 7.1 Cuándo se puede escribir «verificado en dispositivo»

Una afirmación de `internal-review.md` o `threat-model.md` pasa de «sin verificar / sin probar en
dispositivo» a «verificado en dispositivo» **solo si** se cumple todo lo siguiente para su prueba:

1. El `resultado` es **`pasa`**, con `evidencia` citada y archivada (2.8), en la fila de la tabla (3.2).
2. Se ha ejecutado sobre el **commit que se audita** (el SHA de `v0.2.0`, ver [`README.md`](README.md)) o
   sobre uno posterior sin cambios en los ficheros que la prueba verifica (`git diff --stat
   <commit-probado>..<commit-auditado> -- android/app/src/main core ffi`). Si hay cambios, se repite o se
   etiqueta como «indicativo, otro commit».
3. Cumple la **cobertura de dispositivos** de la tabla siguiente.
4. No hay ninguna fila **`falla`** abierta de esa misma prueba sin hallazgo asociado (7.2).

| Afirmación que se cierra | Pruebas y cobertura mínima |
|---|---|
| A7: anti-tapjacking (`threat-model.md`) | DT-01 `pasa` en ≥ 1 dispositivo físico API 31+; DT-02 `pasa` en ≥ 1 dispositivo API 28-30 (un emulador cuenta, anotado); DT-03 `pasa` en un dispositivo de cada tramo |
| A7: portapapeles con borrado / ID-INT-14 | DT-04a-c ejecutadas en **API 29, 33 y 36**; si 04b o 04c **fallan**, ID-INT-14 queda **confirmado** (no «verificado»): la afirmación «con borrado» **se quita** de A7 hasta corregirlo. DT-04d en ≥ 1 dispositivo API 33+ |
| ID-INT-20: lista de sufijos en el dispositivo | DT-05 `pasa` (con los **dos controles positivos**) en la build de depuración **y** en la variante R8 (5.R8) |
| A17 / ID-INT-16: `webDomain` | DT-06 en un dispositivo físico con Chrome; DT-07 `pasa`; DT-08 ejecutada y su resultado anotado (el riesgo residual queda «verificado», no «eliminado») |
| ID-INT-26: token, rotación y «recordar» | DT-09d y DT-10 `pasan` en ≥ 1 dispositivo físico |
| A10: aviso de root | DT-11 `pasa` en emulador `userdebug` **y** el control negativo en un teléfono de serie |
| Biometría en API 28 | DT-12 `pasa` en un dispositivo o emulador API 28. Sin él, queda «sin verificar en API 28» |
| README de Android: KDBX 4 | DT-13a, 13b y 13c `pasan`, 13d y 13e rechazan con los mensajes indicados |
| Techo de KDF | DT-14a `pasa` en todos los dispositivos; 14b ejecutada, anotando tiempo y estado de la app |
| Copia automática, bloqueo, TOTP | DT-15, DT-16 y DT-17 `pasan` en ≥ 1 dispositivo físico |

`bloqueado` **no cuenta** como verificado: la afirmación sigue «sin verificar» y se dice por qué.

**Estado del cierre a 30-oct-2026** (un solo dispositivo, API 37, build de depuración; ninguna fila está cerrada del todo):

| Afirmación | Estado |
|---|---|
| A7: portapapeles / ID-INT-14 | **Confirmado como fallo** en API 37 (DT-04b `falla`): «con borrado» **se quita** de A7 (regla 7.2.5). DT-04c, DT-04d y API 29, 33 y 36 sin ejecutar. No hay fila `pasa` que cerrar |
| ID-INT-20: lista de sufijos | DT-05 `pasa` en depuración con los dos controles positivos; **falta la variante R8**: sigue abierto |
| A17 / ID-INT-16: `webDomain` | DT-07 `pasa`; **faltan** DT-06 (Chrome real) y DT-08 (formal); la hipótesis del `iframe` sigue sin probar |
| El resto (A7 anti-tapjacking, ID-INT-26, A10, KDBX, KDF, copia, bloqueo, TOTP) | Como antes de esta parte: ver la tabla 3.2 |

En todos los casos falta además archivar la evidencia (2.8) y fijar el commit probado (7.1, punto 2).

Al cerrar, los textos que se actualizan **(salvo lo ya registrado de ID-INT-14, 16, 20 y A7/A17 tras la sesión del 30-oct-2026, no se han tocado en este plan)**: filas de `internal-review.md`
para ID-INT-14, 16, 20 y 26 («sin probar en dispositivo»); `threat-model.md` A7 («sin verificar en
dispositivo») y A17 («Sin probar en dispositivo»); y los «sin verificar» de [`hardening.md`](hardening.md) y
[`README.md`](README.md) (índice). Cada cambio cita el ID de la prueba y el commit. Si DT-13 pasa,
también se actualiza la frase del README de Android y el «Pendiente» de
`core/src/import/testdata/README.md`.

### 7.2 Si una prueba falla

**No se parchea en caliente.** Ni durante la prueba ni «para que pase».

1. Se deja la fila con `falla`, la evidencia y una descripción exacta de lo observado (no de lo que se
   interpreta). No se borra ni se sobrescribe: si se repite, es una fila nueva.
2. Se **abre un hallazgo**:
   - Antes de la congelación: un hallazgo nuevo en [`internal-review.md`](internal-review.md) (el siguiente
     libre es `ID-INT-27`, o se actualiza el existente, p. ej. ID-INT-14) con la prueba como evidencia, su
     severidad según [`findings-process.md`](findings-process.md#1-escala-de-severidad) y una fila en
     [`hardening.md`](hardening.md) §4.1.
   - Durante la auditoría: un aviso privado de GitHub según
     [`findings-process.md`](findings-process.md#2-registro-github-security-advisories-privados).
3. La corrección sigue el flujo normal de [`findings-process.md`](findings-process.md#3-corrección): rama,
   cambio, **test en la JVM cuando sea posible**, revisión, y las reglas de
   [ADR-AUD-01](decisions.md#adr-aud-01--estrategia-de-congelación) para `release/0.2`.
4. Se **repite la prueba** sobre el commit corregido (fila nueva) antes de cambiar el texto de «sin
   verificar».
5. Si lo observado **contradice un texto de `threat-model.md`** (por ejemplo, «con borrado»), el texto se
   corrige a lo observado aunque la corrección del código llegue después.
6. **No se cambian las pruebas ni sus resultados esperados** para que pasen: si el resultado esperado de
   este plan era incorrecto, se anota la discrepancia y se corrige este documento en un commit aparte.

---

## 8. Fuera del alcance de este plan

| Qué queda fuera | Por qué |
|---|---|
| Root real en el teléfono principal; Magisk | Regla de seguridad 3. DT-11 se hace con un emulador `userdebug`; las señales `SU_BINARY` y `ROOT_MANAGER_APP` las cubre `RootDetectorTest` con un `DeviceProbe` falso |
| La hipótesis del `iframe` de otro origen en un navegador ([ID-INT-16](internal-review.md#id-int-16), riesgo residual) | Necesita una página con dos orígenes y un navegador real; es una prueba nueva que no estaba en la lista. Candidata a un DT-18 |
| Que una app inyecte extras en el `PendingIntent` mutable ([ID-INT-26](internal-review.md#id-int-26)) | El `IntentSender` lo guarda el marco de autorrelleno y no llega a código de una app normal; reproducirlo exige un cliente de autorrelleno modificado. El token y la rotación sí se prueban (DT-09d); la lógica del token, en la JVM (`AutofillRequestTokensTest`) |
| Invalidación de la clave biométrica al inscribir una huella nueva (`BiometricKeyStore.kt:40-56`); modo de diario de SQLite (`-journal`, [`threat-model-review.md`](threat-model-review.md)) | No estaban en la lista pedida. Son verificaciones razonables en dispositivo; candidatas a DT-19/DT-20 |
| Rendimiento, tiempos de KDF por ABI y dispositivos de gama baja | La decisión de techo por ABI está sin tomar (ADR-AUD-07, decisión nº 3). DT-14 anota `MemTotal` y tiempos, pero no mide un catálogo de dispositivos |
| Build reproducible, firma, SBOM y cadena de suministro | No dependen del dispositivo: ver [`dependencies.md`](dependencies.md) y `docs/fdroid/README.md` |
| Pruebas sobre iOS, escritorio y la CLI `opvault` | Fuera del alcance de la auditoría ([`scope.md`](scope.md)). La CLI se usa aquí solo como herramienta |
| Las pruebas de Kotlin en la JVM y los fuzzers | Se ejecutan en la CI o localmente (`./gradlew testDebugUnitTest`, [`fuzzing.md`](fuzzing.md)); este plan es lo que **no** puede hacerse allí |
| Versiones de Android no incluidas en la matriz (2.9) | Se cubren API 28, 29, 30, 33 y 36 como mínimo. Cada API adicional es una fila nueva en la tabla, no una prueba nueva |
