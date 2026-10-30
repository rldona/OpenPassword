# App Android

Kotlin, Jetpack Compose y Material 3. Toda la criptografía la hace `op-core` (Rust), que la app carga como `libop_ffi.so` a través de los bindings de UniFFI.

## Qué hace ya

- Alta: contraseña maestra con indicador de fortaleza y clave secreta para anotar en papel.
- Desbloqueo con contraseña maestra; espera creciente tras 4 intentos fallidos.
- Desbloqueo con huella (biometría fuerte). La contraseña maestra se pide cada 14 días y tras cada reinicio.
- Baúl: lista, búsqueda sin acentos, filtros por tipo y favoritos.
- Tarjetas: el número se valida con Luhn y se muestra la red (Visa, Mastercard, American Express…).
- Historial de contraseñas en logins, Wi-Fi y secretos: las 10 anteriores, con la fecha del cambio, para verlas o copiarlas.
- Logins, tarjetas, cuentas bancarias, PINs, documentos, redes Wi-Fi, secretos y notas seguras: crear, ver, editar y borrar.
- Cuentas bancarias: el IBAN se valida (longitud del país y dígitos de control) y se guarda agrupado de cuatro en cuatro; la lista solo muestra el banco y los cuatro últimos dígitos.
- Documentos (DNI, pasaporte, carné…): las fechas se guardan como DD/MM/AAAA aunque se escriban sin barras.
- Wi-Fi: el detalle muestra un QR estándar (`WIFI:T:WPA;…`) para que otro teléfono se conecte con la cámara. Sin contraseña se trata como red abierta.
- Revelar campo a campo y copiar al portapapeles marcado como sensible, que se borra a los 30 s.
- Generador de contraseñas, PINs y frases de paso (lista larga de la EFF, 7776 palabras). En el alta puede sugerir una frase de 6 palabras como contraseña maestra.
- Kit de emergencia en PDF para imprimir, con la clave secreta y cómo restaurar. Se ofrece en el alta y en Ajustes, tras confirmar la contraseña.
- Exportar una copia cifrada `.opvault` donde elija el usuario. Se abre con `opvault decrypt`.
- Copia automática a una carpeta elegida por el usuario (de su nube, Syncthing o tarjeta SD): unos segundos después de cada cambio y al desbloquear si la última tiene más de un día. Guarda las 10 últimas y solo borra sus propias copias (`openpassword-auto-…opvault`). Como cifrar exige el baúl abierto, con el baúl bloqueado no se hacen copias: las pendientes se hacen al desbloquear.
- Salud del baúl, sin conexión: contraseñas débiles, contraseñas repetidas entre logins, logins sin modificar en más de un año tarjetas caducadas o que caducan en los próximos 2 meses y documentos caducados o que caducan en los próximos 3. Aparece un aviso encima de la lista solo cuando hay algo que corregir.
- Importar de otro gestor: KeePass (`.kdbx` 3.1 y 4.x con contraseña, archivo de clave o ambos; sin papelera ni historial), `.1pux` de 1Password (logins con TOTP y campos extra, contraseñas sueltas, tarjetas y notas), JSON sin cifrar de Bitwarden y CSV de Chrome / Google, Firefox, Bitwarden y 1Password (las columnas se reconocen por su nombre). La lectura de KDBX 4 aún no se ha probado con un fichero real. No duplica lo que ya existe y, como la exportación tiene las contraseñas en claro, ofrece borrar el fichero al terminar.
- Restaurar una copia en un teléfono nuevo desde la bienvenida, con la clave secreta del kit y la contraseña maestra.
- Importar una copia en el baúl actual: si es del mismo baúl se fusiona por revisión; si es de otro, sus elementos se vuelven a cifrar con las claves de este.
- Ver la clave secreta de nuevo, tras volver a pedir la contraseña maestra.
- Bloqueo automático: 5 min sin uso, 30 s después de salir de la app (aunque no vuelvas) o al apagar la pantalla. Mientras está abierto un selector de ficheros o carpetas que el usuario ha pedido (exportar, importar, kit, carpeta de copias), el margen es de 3 minutos, solo para esa vez.
- Códigos TOTP (verificación en dos pasos): se escanea el QR con la cámara, se lee de una captura o imagen, o se pega el enlace `otpauth://` o el secreto; el detalle muestra el código actual con su cuenta atrás. Se copia el código, nunca el secreto. El QR se decodifica en el teléfono con ZXing; los fotogramas no se guardan y la copia de luminancia se borra tras analizarla.
- Guardar logins nuevos desde el autorrelleno: al enviar un formulario con contraseña, Android ofrece «Guardar en OpenPassword». Si ya existe un login de ese sitio con el mismo usuario, se ofrece actualizar su contraseña. La contraseña tecleada se queda en la memoria de la app; la ventana de confirmación solo recibe un token, y nada se guarda sin confirmar.
- Autorrelleno en otras apps y en el navegador (Chrome: *Ajustes → Servicios de autocompletar → Autocompletar con otro servicio*).

**Publicación en F-Droid: en pausa** por decisión del responsable del proyecto (30-oct-2026). La funcionalidad prevista para la v0.1.0 está hecha y la receta, los metadatos y el flujo de firma están preparados; no hay etiqueta `v0.1.0` ni release publicada. Al retomarlo, empezar por [`docs/fdroid/README.md`](../docs/fdroid/README.md), que tiene los pasos y lo que queda por confirmar.

## Seguridad que impone la build

- `verify<Variant>Manifest` hace fallar la compilación si el manifiesto final declara `INTERNET` o `ACCESS_NETWORK_STATE`, si falta `HIDE_OVERLAY_WINDOWS`, si se declara `QUERY_ALL_PACKAGES`, o si `allowBackup` no es `false`.
- Anti-tapjacking: `filterTouchesWhenObscured` y `setHideOverlayWindows` en las tres actividades y en todos los diálogos (`ProtectedAlertDialog`); si un toque llega tapado, se avisa.
- Aviso (nunca bloqueo) si el dispositivo parece tener root o una compilación de depuración: heurísticas locales sin red; el manifiesto declara en `<queries>` solo los nombres de los paquetes de gestores de root.
- `FLAG_SECURE` en la actividad: sin capturas, grabación ni miniatura en recientes.
- La clave secreta se guarda sellada con una clave AES-256-GCM de Android Keystore (StrongBox si existe).
- Huella: la clave del baúl se sella con otra clave de Keystore que exige una autenticación biométrica fuerte en cada uso, solo funciona con el teléfono desbloqueado y Android la destruye si se añade una huella o cara nueva. Los únicos permisos del manifiesto son `USE_BIOMETRIC`, `CAMERA` y `HIDE_OVERLAY_WINDOWS` (permiso normal de Android 12+ que oculta las ventanas superpuestas de otras apps; anti-tapjacking); la cámara se pide solo al pulsar «Escanear QR» y es opcional (`required="false"`): leer el QR de una imagen no necesita ningún permiso. CameraX arrastra `ACCESS_NETWORK_STATE` desde media3 y el manifiesto lo elimina.
- Los elementos se guardan en SQLite como blobs opacos con `secure_delete`. Se usa SQLite directo en lugar de Room para no depender de procesadores de anotaciones.
- Nada sensible se guarda en el estado de instancia de Compose (`rememberSaveable`).
- Las ventanas de la app se excluyen de todos los servicios de autorrelleno, así que ni el de Google ni ningún otro puede leer u ofrecer guardar lo que se escribe en el baúl.

## Autorrelleno

- Android muestra las sugerencias y solo rellena la que el usuario toca.
- **Coincidencia estricta**:
  - En webs, solo el host guardado o sus subdominios: `google.com` vale para `accounts.google.com`, pero nunca para `google.com.phishing.net` ni para `evilgoogle.com`.
  - En apps, solo el nombre de paquete exacto, que Android verifica, guardado como `androidapp://paquete`.
  - Un login de una web nunca vale para una app, ni al revés.
- Con el baúl bloqueado solo se ofrece «Desbloquear OpenPassword», que abre una ventana con contraseña o huella.
- Si no hay coincidencia, el usuario puede elegir un login a mano. En apps puede recordarlo para esa app; en webs se le avisa de que compruebe el sitio.
- Los campos se detectan en `autofill/FieldClassifier.kt` (pistas de autorrelleno, tipo de entrada, atributos HTML y nombres en español e inglés). La lógica de detección y de coincidencia tiene tests unitarios.

## Verificación de dependencias

`gradle/verification-metadata.xml` guarda el SHA-256 de cada artefacto Maven (dependencias, plugins y herramientas de build). Gradle lo comprueba en cada resolución y el build falla si una suma no coincide o falta.

**Una dependencia nueva, o una subida de versión, exige actualizar ese fichero.** Con JDK 17, desde `android/`:

    ./gradlew --write-verification-metadata sha256 :app:lintDebug :app:testDebugUnitTest :app:assembleDebug :app:assembleRelease :app:cyclonedxDirectBom

Revisa el diff del XML (solo deben aparecer los artefactos nuevos) y súbelo en el mismo commit. Es la misma lista de tareas que ejecuta la CI.

Limitación: hay artefactos que dependen de la plataforma. En macOS, Gradle solo resuelve `aapt2-<versión>-osx.jar`; la CI (Linux) necesita también `aapt2-<versión>-linux.jar`, que se añade a mano con el SHA-256 del fichero descargado de `https://dl.google.com/dl/android/maven2/com/android/tools/build/aapt2/<versión>/`. Si la CI falla con «Dependency verification failed» tras una subida de AGP, empieza por ahí; si no, regenera el fichero en Linux (`--write-verification-metadata` fusiona con lo que ya hay).

## Compilar

Requisitos: JDK 17, Android SDK con la plataforma 37, NDK `30.0.16248370`, Rust con los targets de Android y `cargo-ndk`.

```sh
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
cargo install cargo-ndk --locked --version 4.1.2
sdkmanager "ndk;30.0.16248370"
cd android
./gradlew :app:assembleDebug
```

La tarea `cargoBuild` compila `op-ffi` con `cargo ndk` (siempre en release, porque Argon2id es demasiado lento sin optimizar) y `uniffiBindings` genera el código Kotlin a partir de la librería. Para compilar solo una ABI y ganar tiempo: `./gradlew :app:assembleDebug -PrustAbis=arm64-v8a`.

Las librerías nativas están alineadas a 16 KB, como exige Android 15+ en dispositivos con páginas de 16 KB.

## Tests

```sh
./gradlew :app:testDebugUnitTest            # JVM: generadores, lista EFF, fortaleza, campos, espera tras fallos
./gradlew :app:connectedDebugAndroidTest    # en un móvil o emulador: sesión completa con op-core, Keystore y SQLite reales
```

Los tests instrumentados usan un espacio de nombres propio por test (ficheros, base de datos y clave de Keystore) y lo borran al terminar: nunca tocan los datos de la app. Gradle desinstala la app de depuración al acabar.

## Firma de release

La clave no está en el repositorio. Gradle la usa solo si existe `~/.openpassword/release-signing.properties` (o el fichero que indiques con `-PsigningProperties=…`):

```properties
storeFile=/ruta/a/openpassword-release.p12
storePassword=…
keyAlias=openpassword
keyPassword=…
```

Sin ese fichero, `assembleRelease` produce un APK sin firmar, como en la CI. Se firma con el esquema v3, que permite rotar la clave en el futuro.

Certificado de las releases oficiales (compruébalo con `apksigner verify --print-certs`):

```
CN=OpenPassword, O=rldona · RSA 4096
SHA-256: c8:7c:49:b9:b2:57:11:1a:e9:49:07:a8:e1:43:80:2a:1c:22:83:26:81:e7:1c:96:f3:9c:ae:50:ef:7d:7b:57
```
