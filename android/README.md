# App Android

Kotlin, Jetpack Compose y Material 3. Toda la criptografía la hace `op-core` (Rust), que la app carga como `libop_ffi.so` a través de los bindings de UniFFI.

## Qué hace ya (Fase 1, primera iteración)

- Alta: contraseña maestra con indicador de fortaleza y clave secreta para anotar en papel.
- Desbloqueo con contraseña maestra; espera creciente tras 4 intentos fallidos.
- Desbloqueo con huella (biometría fuerte). La contraseña maestra se pide cada 14 días y tras cada reinicio.
- Baúl: lista, búsqueda sin acentos, filtros por tipo y favoritos.
- Logins, tarjetas, PINs, secretos y notas seguras: crear, ver, editar y borrar.
- Revelar campo a campo y copiar al portapapeles marcado como sensible, que se borra a los 30 s.
- Generador de contraseñas, PINs y frases de paso (lista larga de la EFF, 7776 palabras). En el alta puede sugerir una frase de 6 palabras como contraseña maestra.
- Kit de emergencia en PDF para imprimir, con la clave secreta y cómo restaurar. Se ofrece en el alta y en Ajustes, tras confirmar la contraseña.
- Exportar una copia cifrada `.opvault` donde elija el usuario. Se abre con `opvault decrypt`.
- Copia automática a una carpeta elegida por el usuario (de su nube, Syncthing o tarjeta SD): unos segundos después de cada cambio y al desbloquear si la última tiene más de un día. Guarda las 10 últimas y solo borra sus propias copias (`openpassword-auto-…opvault`). Como cifrar exige el baúl abierto, con el baúl bloqueado no se hacen copias: las pendientes se hacen al desbloquear.
- Salud del baúl, sin conexión: contraseñas débiles, contraseñas repetidas entre logins, logins sin modificar en más de un año y tarjetas caducadas o que caducan en los próximos 2 meses. Aparece un aviso encima de la lista solo cuando hay algo que corregir.
- Importar de otro gestor: CSV de Chrome / Google, Firefox, Bitwarden y 1Password (las columnas se reconocen por su nombre) y JSON sin cifrar de Bitwarden (logins, tarjetas y notas). No duplica lo que ya existe y, como la exportación tiene las contraseñas en claro, ofrece borrar el fichero al terminar.
- Restaurar una copia en un teléfono nuevo desde la bienvenida, con la clave secreta del kit y la contraseña maestra.
- Importar una copia en el baúl actual: si es del mismo baúl se fusiona por revisión; si es de otro, sus elementos se vuelven a cifrar con las claves de este.
- Ver la clave secreta de nuevo, tras volver a pedir la contraseña maestra.
- Bloqueo automático: 5 min sin uso, 30 s después de salir de la app (aunque no vuelvas) o al apagar la pantalla. Mientras está abierto un selector de ficheros o carpetas que el usuario ha pedido (exportar, importar, kit, carpeta de copias), el margen es de 3 minutos, solo para esa vez.
- Códigos TOTP (verificación en dos pasos): se pega el enlace `otpauth://` o el secreto y el detalle muestra el código actual con su cuenta atrás. Se copia el código, nunca el secreto.
- Autorrelleno en otras apps y en el navegador (Chrome: *Ajustes → Servicios de autocompletar → Autocompletar con otro servicio*).

Pendiente (Fase 2): guardar logins nuevos desde el autorrelleno, escanear QR de TOTP, importar KeePass (KDBX) y 1Password (1PUX), y publicar en F-Droid.

## Seguridad que impone la build

- `verify<Variant>Manifest` hace fallar la compilación si el manifiesto final declara `INTERNET` o `ACCESS_NETWORK_STATE`, o si `allowBackup` no es `false`.
- `FLAG_SECURE` en la actividad: sin capturas, grabación ni miniatura en recientes.
- La clave secreta se guarda sellada con una clave AES-256-GCM de Android Keystore (StrongBox si existe).
- Huella: la clave del baúl se sella con otra clave de Keystore que exige una autenticación biométrica fuerte en cada uso, solo funciona con el teléfono desbloqueado y Android la destruye si se añade una huella o cara nueva. El único permiso del manifiesto es `USE_BIOMETRIC`.
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

## Compilar

Requisitos: JDK 17, Android SDK con la plataforma 37, NDK `30.0.16248370`, Rust con los targets de Android y `cargo-ndk`.

```sh
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
cargo install cargo-ndk --locked
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
