# OpenPassword

Gestor de contraseñas, tarjetas, PINs y secretos, offline y sin servidor. Android primero.

> **Proyecto personal.** Lo uso yo en mi propio teléfono: no se publica en ninguna tienda, no tiene
> usuarios externos ni soporte, y **no ha pasado una auditoría de seguridad externa**. Si alguien más
> lo usa, lo hace por su cuenta y riesgo. Lo que sí está hecho y probado es lo que protege la bóveda:
> cifrado, copias automáticas, restauración y un conjunto de tests y fuzzing que han encontrado fallos
> reales.

## Qué hace

- Baúl de logins, tarjetas, cuentas bancarias, PINs, documentos, redes Wi-Fi, secretos y notas, con
  búsqueda sin acentos, filtros y favoritos.
- Autorrelleno en otras apps y en el navegador, con comprobación de dominio (lista de sufijos públicos
  incluida) y sin aceptar el dominio que declare una app que no sea un navegador.
- Desbloqueo con contraseña maestra o huella, bloqueo automático y `FLAG_SECURE` (sin capturas).
- Códigos TOTP: escaneados con la cámara, leídos de una imagen o pegados desde `otpauth://`.
- Imágenes cifradas (DNI, tarjetas, pólizas) adjuntas a cualquier elemento, hechas con la cámara de la
  app o elegidas de la galería. Solo se ven dentro de OpenPassword: no se comparten ni se guardan fuera.
- Generador de contraseñas, PINs y frases de paso (lista EFF).
- Copia automática cifrada a una carpeta que elijas (nube, Syncthing o tarjeta SD) y exportación
  manual `.opvault`.
- Importación desde KeePass, 1Password, Bitwarden, Chrome, Firefox y CSV.
- Kit de emergencia en PDF para imprimir, con la clave secreta.

Detalle completo en [`android/README.md`](android/README.md).

## Empezar a usarla

Requisitos: JDK 17, Android SDK con la plataforma 37 y el NDK `30.0.16248370`, Rust con los targets de
Android y `cargo-ndk 4.1.2`, como se explica en [`android/README.md`](android/README.md).

```sh
cd android
./gradlew :app:installDebug     # instala io.github.rldona.openpassword.debug
```

Para uso diario sirve la build de depuración: tiene su propio identificador, sus propios datos y sus
propias claves, y no choca con una build de release instalada.

## Lo que más importa: no perder la bóveda

El riesgo real no es un ataque: es perder el teléfono, olvidar la contraseña maestra o quedarte sin la
clave secreta. Tres cosas lo cubren:

1. **Kit de emergencia en papel.** La app lo genera en el alta y en Ajustes. Contiene la clave secreta.
   Guárdalo con tus documentos importantes. Sin esa clave, una copia de seguridad no se puede abrir.
2. **Copia automática.** Se escribe cifrada en la carpeta que elijas, guarda las 10 últimas y solo
   borra las suyas (`openpassword-auto-…opvault`). Con el baúl bloqueado no se hacen copias: las
   pendientes se hacen al desbloquear.
3. **Restauración probada.** Una vez al año, o al cambiar de teléfono: exporta una copia, instala en un
   teléfono limpio y restaura con la clave secreta del kit. Si no lo has probado, no tienes copia.

   > Ciclo completo verificado el 30-oct-2026 en un SM-S948B (Android 17): exportar, desinstalar,
   > reinstalar y restaurar. Los cuatro elementos de prueba volvieron con su contraseña, usuario y URL
   > intactos, y la copia exportada se descifró además con `opvault decrypt` desde el ordenador.

**No desinstales la app para actualizarla**: instala la nueva versión encima (`./gradlew :app:installDebug`
o `adb install -r`). Desinstalar borra la bóveda y las claves del Keystore, y ni una copia `.opvault`
basta sin la clave secreta.

## Actualizar

```sh
git pull
cd android && ./gradlew :app:installDebug
```

El formato `.opvault` v1 no cambia entre versiones: si algún día cambia, será una versión nueva del
formato, no una reinterpretación de la anterior (ver los vectores en `core/tests/vectors/op-v1.json`).

## Desarrollo

Usa la versión de Rust fijada en [`rust-toolchain.toml`](rust-toolchain.toml); rustup la instala sola.

```sh
cargo test --workspace          # unitarios, vectores oficiales y vectores dorados v1
cargo clippy --workspace --all-targets -- -D warnings
cargo deny --locked check       # avisos, licencias, duplicados y orígenes
cargo build --release -p opvault-cli
```

Android:

```sh
cd android
./gradlew :app:lintDebug :app:testDebugUnitTest :app:assembleDebug
```

### Probar la CLI

```sh
SK=$(./target/release/opvault new-secret-key)
./target/release/opvault sample demo.opvault --secret-key "$SK"
./target/release/opvault inspect demo.opvault
./target/release/opvault decrypt demo.opvault --secret-key "$SK"
```

### Vectores de prueba

`core/tests/vectors/op-v1.json` fija cada byte del formato v1. Si un cambio los rompe, es incompatible
con los baúles existentes: hay que crear una versión nueva del formato, no regenerarlos. Cualquier otra
implementación (Kotlin, Swift) debe pasar el mismo fichero.

## Qué hay en el repositorio

| Ruta | Contenido |
|---|---|
| [`core/`](core) | `op-core`, el núcleo en Rust: derivación de claves, cifrado por elemento y formato `.opvault` |
| [`ffi/`](ffi) | `op-ffi`, bindings UniFFI de `op-core` para Kotlin |
| [`cli/`](cli) | `opvault`, herramienta para inspeccionar y descifrar copias sin la app |
| [`fuzz/`](fuzz) | Objetivos de `cargo-fuzz` para los parsers que leen datos no confiables. Ver [fuzz/README.md](fuzz/README.md) |
| [`android/`](android) | App Android: Kotlin + Jetpack Compose. Ver [android/README.md](android/README.md) |
| [`docs/crypto-spec.md`](docs/crypto-spec.md) | Especificación criptográfica v1 (normativa) |
| [`docs/opvault-format.md`](docs/opvault-format.md) | Formato del fichero de copia |
| [`docs/threat-model.md`](docs/threat-model.md) | Modelo de amenazas |
| [`docs/archive/`](docs/archive) | Material de cuando el proyecto se planteaba como producto público: propuesta, planes de distribución y paquete de auditoría. **No se mantiene.** |

## Resumen del diseño

- La contraseña maestra (Argon2id, 256 MiB) se combina con una **clave secreta** de 128 bits. Una copia
  robada no se puede atacar por fuerza bruta sin ella.
- Cada elemento tiene su propia clave. Todo va cifrado con XChaCha20-Poly1305, metadatos incluidos.
- Cada imagen adjunta es un registro cifrado aparte, sellado con la clave de su elemento y dentro de
  las copias `.opvault` v2. Se reescala y recodifica al guardarla, así que pierde EXIF y GPS.
- Cada bloque cifrado está ligado a su contexto (baúl, elemento, revisión, parte) mediante datos
  asociados.
- La app no tiene permiso de Internet. Las copias se escriben cifradas en la carpeta que elijas.

## Seguridad

No hay auditoría externa. La revisión interna, los hallazgos y su estado están en el archivo
([`docs/archive/audit/internal-review.md`](docs/archive/audit/internal-review.md)); los fallos conocidos
que se aceptaron como riesgo residual están en [`docs/threat-model.md`](docs/threat-model.md).

Si encuentras un fallo, ábrelo como issue normal del repositorio: no hay usuarios a los que proteger.

## Licencia

GPL-3.0-or-later. Ver [LICENSE](LICENSE).

### Componentes de terceros

- Lista de palabras para frases de paso: [EFF Large Wordlist](https://www.eff.org/dice) de la
  Electronic Frontier Foundation, bajo [CC BY 3.0 US](https://creativecommons.org/licenses/by/3.0/us/).
  Se incluye solo la columna de palabras (`android/app/src/main/assets/eff_large_wordlist.txt`).
- Lista de sufijos públicos: [Public Suffix List](https://publicsuffix.org/list/public_suffix_list.dat)
  de Mozilla y colaboradores, bajo [MPL 2.0](https://mozilla.org/MPL/2.0/). Se incluye sin modificar
  (`android/app/src/main/resources/public_suffix_list.dat`); el autorrelleno la usa para no ofrecer una
  credencial de `github.io` o `co.uk` a cualquier subdominio.
