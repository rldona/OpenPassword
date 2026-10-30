# Publicar OpenPassword en F-Droid

> **Estado: pausado** por decisión del responsable del proyecto el **30-oct-2026**. No hay etiqueta
> `v0.1.0` ni release publicada, y no se ha enviado ninguna receta a `fdroiddata`. Este documento
> es el punto de retorno: todo lo preparado sigue en el repositorio y los pasos manuales no han
> cambiado. No hace falta deshacer nada para retomarlo; basta con empezar por «Pasos que te tocan a
> ti».
>
> La auditoría externa (Fase 3) **no depende** de esta publicación.

F-Droid compila la app desde el código fuente. Con la **build reproducible** compila el APK y,
si es idéntico al que publicas tú en GitHub (salvo la firma), distribuye el tuyo, firmado con tu
clave. Así los usuarios reciben siempre la misma firma, vengan de F-Droid o de GitHub.

## Lo que ya está preparado en el repositorio

- Metadatos de tienda en `fastlane/metadata/android/` (español y inglés): título, descripciones y
  notas de la versión 1. F-Droid los lee directamente del repositorio. El icono se toma del APK.
- APK reproducible **en Linux**, que es donde compila F-Droid: dos ejecuciones de la CI en máquinas
  distintas generan el mismo APK byte a byte. En macOS también es reproducible entre carpetas, pero
  **no coincide con el de Linux**: el enlazador del NDK guarda su propia ruta de compilación y Cargo
  mezcla el sistema anfitrión en sus identificadores, y eso cambia `libop_ffi.so`. Por eso **el APK
  que se publica es el que compila la CI**, firmado después en tu ordenador.
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
3. **Firma el APK de la CI** cuando termine la ejecución de la etiqueta (búscala con
   `gh run list -R rldona/OpenPassword --branch v0.1.0`). El script descarga el APK sin firmar,
   lo firma con tu clave local (v2 + v3, como Gradle) y comprueba el certificado:
   ```sh
   scripts/firmar-release.sh <id-de-la-ejecución> 0.1.0
   ```
   El artefacto de la CI caduca a los 14 días (`retention-days: 14` en `ci.yml`): firma el APK dentro de ese plazo
   o tendrás que relanzar la ejecución.
   No compiles el APK de la release en macOS: no coincidiría con el de F-Droid.
4. **Crea la release en GitHub** con ese APK, con el nombre exacto que espera la receta:
   ```sh
   gh release create v0.1.0 openpassword-0.1.0.apk --title "OpenPassword 0.1.0" --notes-file fastlane/metadata/android/es-ES/changelogs/1.txt
   ```
5. **Envía la receta a F-Droid**: haz un fork de https://gitlab.com/fdroid/fdroiddata con tu cuenta de
   GitLab, copia `io.github.rldona.openpassword.yml` a `metadata/` y abre una *merge request*. Su
   CI compilará la app y te dirá si la receta necesita ajustes.

## Por confirmar antes de enviar la receta

- **NDK r30 en el servidor de F-Droid**: si aún no lo ofrecen, habrá que bajar `ndkVersion` (y el
  campo `ndk:`) a la versión más reciente que tengan y volver a comprobar la build.
- **Versión del *srclib* `rustup`** disponible en fdroiddata (`rustup@1.28.2` es una suposición).
- **Que el servidor de F-Droid reproduzca el APK de la CI**: ambos son Linux con el mismo NDK, Rust
  y Gradle, y dos máquinas de la CI ya coinciden, pero solo se confirma cuando F-Droid lo compile.
  Su CI lo dirá en la *merge request*.
- **Capturas de pantalla**: la app bloquea las capturas (`FLAG_SECURE`), así que no hay. Se pueden
  añadir más adelante en `fastlane/metadata/android/<idioma>/images/phoneScreenshots/`, generadas
  con datos de ejemplo.
