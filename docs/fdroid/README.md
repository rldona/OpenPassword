# Publicar OpenPassword en F-Droid

F-Droid compila la app desde el código fuente. Con la **build reproducible** compila el APK y,
si es idéntico al que publicas tú en GitHub (salvo la firma), distribuye el tuyo, firmado con tu
clave. Así los usuarios reciben siempre la misma firma, vengan de F-Droid o de GitHub.

## Lo que ya está preparado en el repositorio

- Metadatos de tienda en `fastlane/metadata/android/` (español y inglés): título, descripciones y
  notas de la versión 1. F-Droid los lee directamente del repositorio. El icono se toma del APK.
- APK reproducible, comprobado en macOS: dos copias del código en carpetas distintas generan el
  mismo APK byte a byte (`./gradlew :app:assembleRelease -PsigningProperties=/nonexistent`).
  - Las rutas de las dependencias (`~/.cargo/registry/…`) se reescriben a `/cargo/…`, así que el
    APK no incluye el nombre de usuario de quien compila.
  - El compilador de Rust está fijado en `rust-toolchain.toml` (1.99.1), y el NDK y Gradle están
    fijados en la build.
  - No se incluye el bloque de dependencias firmado por Google (`dependenciesInfo`).
- Borrador de receta: `io.github.rldona.openpassword.yml`, en esta misma carpeta.
- Requisitos de inclusión de F-Droid:
  - Todas las dependencias son libres y vienen de Maven Central, Google o crates.io.
  - No hay rastreadores, anuncios ni servicios de Google.
  - La app no usa la red. No hace falta ningún *anti-feature*.

## Pasos que te tocan a ti

1. **Copia de seguridad de la clave de firma**, si aún no la tienes: guarda `~/.openpassword/`
   (el `.p12` y su `release-signing.properties`) fuera del ordenador. Si pierdes esa clave, no podrás
   publicar actualizaciones con la misma firma.
2. **Etiqueta la versión** en el commit que quieras publicar:
   ```sh
   git tag -a v0.1.0 -m "OpenPassword 0.1.0"
   git push origin v0.1.0
   ```
3. **Compila y firma el APK** desde esa etiqueta, en una copia limpia:
   ```sh
   cd android && ./gradlew :app:assembleRelease
   cp app/build/outputs/apk/release/app-release.apk openpassword-0.1.0.apk
   ```
4. **Crea la release en GitHub** con ese APK, con el nombre exacto que espera la receta:
   ```sh
   gh release create v0.1.0 android/openpassword-0.1.0.apk --title "OpenPassword 0.1.0" --notes-file fastlane/metadata/android/es-ES/changelogs/1.txt
   ```
5. **Envía la receta a F-Droid**: haz un fork de https://gitlab.com/fdroid/fdroiddata con tu cuenta de
   GitLab, copia `io.github.rldona.openpassword.yml` a `metadata/` y abre una *merge request*. Su
   CI compilará la app y te dirá si la receta necesita ajustes.

## Por confirmar antes de enviar la receta

- **NDK r30 en el servidor de F-Droid**: si aún no lo ofrecen, habrá que bajar `ndkVersion` (y el
  campo `ndk:`) a la versión más reciente que tengan y volver a comprobar la build.
- **Versión del *srclib* `rustup`** disponible en fdroiddata (`rustup@1.28.2` es una suposición).
- **Reproducibilidad entre Linux y macOS**: la CI de GitHub (Linux) imprime el SHA-256 del APK
  sin firmar. Si coincide con el de una build local en macOS del mismo commit, lo más probable es
  que el servidor de F-Droid también lo reproduzca.
- **Capturas de pantalla**: la app bloquea las capturas (`FLAG_SECURE`), así que no hay. Se pueden
  añadir más adelante en `fastlane/metadata/android/<idioma>/images/phoneScreenshots/`, generadas
  con datos de ejemplo.
