# App Android

Kotlin, Jetpack Compose y Material 3. Toda la criptografía la hace `op-core` (Rust), que la app carga como `libop_ffi.so` a través de los bindings de UniFFI.

## Qué hace ya (Fase 1, primera iteración)

- Alta: contraseña maestra con indicador de fortaleza y clave secreta para anotar en papel.
- Desbloqueo con contraseña maestra; espera creciente tras 4 intentos fallidos.
- Desbloqueo con huella (biometría fuerte). La contraseña maestra se pide cada 14 días y tras cada reinicio.
- Baúl: lista, búsqueda sin acentos, filtros por tipo y favoritos.
- Logins, tarjetas, PINs, secretos y notas seguras: crear, ver, editar y borrar.
- Revelar campo a campo y copiar al portapapeles marcado como sensible, que se borra a los 30 s.
- Generador de contraseñas y PINs.
- Exportar una copia cifrada `.opvault` donde elija el usuario. Se abre con `opvault decrypt`.
- Restaurar una copia en un teléfono nuevo desde la bienvenida, con la clave secreta del kit y la contraseña maestra.
- Importar una copia en el baúl actual: si es del mismo baúl se fusiona por revisión; si es de otro, sus elementos se vuelven a cifrar con las claves de este.
- Ver la clave secreta de nuevo, tras volver a pedir la contraseña maestra.
- Bloqueo automático: 5 min sin uso, 30 s en segundo plano o al apagar la pantalla.

Pendiente para las siguientes iteraciones: autorrelleno, TOTP y kit de emergencia en PDF.

## Seguridad que impone la build

- `verify<Variant>Manifest` hace fallar la compilación si el manifiesto final declara `INTERNET` o `ACCESS_NETWORK_STATE`, o si `allowBackup` no es `false`.
- `FLAG_SECURE` en la actividad: sin capturas, grabación ni miniatura en recientes.
- La clave secreta se guarda sellada con una clave AES-256-GCM de Android Keystore (StrongBox si existe).
- Huella: la clave del baúl se sella con otra clave de Keystore que exige una autenticación biométrica fuerte en cada uso, solo funciona con el teléfono desbloqueado y Android la destruye si se añade una huella o cara nueva. El único permiso del manifiesto es `USE_BIOMETRIC`.
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
