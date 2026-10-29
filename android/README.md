# App Android

Kotlin, Jetpack Compose y Material 3. Toda la criptografía la hace `op-core` (Rust), que la app carga como `libop_ffi.so` a través de los bindings de UniFFI.

## Qué hace ya (Fase 1, primera iteración)

- Alta: contraseña maestra con indicador de fortaleza y clave secreta para anotar en papel.
- Desbloqueo con contraseña maestra; espera creciente tras 4 intentos fallidos.
- Baúl: lista, búsqueda sin acentos, filtros por tipo y favoritos.
- Logins, tarjetas, PINs, secretos y notas seguras: crear, ver, editar y borrar.
- Revelar campo a campo y copiar al portapapeles marcado como sensible, que se borra a los 30 s.
- Generador de contraseñas y PINs.
- Exportar una copia cifrada `.opvault` donde elija el usuario. Se abre con `opvault decrypt`.
- Ver la clave secreta de nuevo, tras volver a pedir la contraseña maestra.
- Bloqueo automático: 5 min sin uso, 30 s en segundo plano o al apagar la pantalla.

Pendiente para las siguientes iteraciones: desbloqueo biométrico, importar copias, autorrelleno, TOTP y kit de emergencia en PDF.

## Seguridad que impone la build

- `verify<Variant>Manifest` hace fallar la compilación si el manifiesto final declara `INTERNET` o `ACCESS_NETWORK_STATE`, o si `allowBackup` no es `false`.
- `FLAG_SECURE` en la actividad: sin capturas, grabación ni miniatura en recientes.
- La clave secreta se guarda sellada con una clave AES-256-GCM de Android Keystore (StrongBox si existe).
- Los elementos se guardan en SQLite como blobs opacos con `secure_delete`. Se usa SQLite directo en lugar de Room para no depender de procesadores de anotaciones.
- Nada sensible se guarda en el estado de instancia de Compose (`rememberSaveable`).

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
