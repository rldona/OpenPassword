# Archivo

Material de una etapa anterior, cuando OpenPassword se planteaba como **producto público**: propuesta
funcional, publicación en F-Droid, auditoría externa y cadena de suministro para distribuir binarios.

El proyecto es de **uso personal**. Nada de esto se mantiene, se actualiza ni se ejecuta. Se conserva
porque contiene trabajo útil —la revisión interna, el modelo de amenazas ampliado, el análisis de la
superficie de ataque y los resultados de las pruebas en dispositivo— y porque explica por qué el
código tiene las defensas que tiene.

| Ruta | Contenido | Estado |
|---|---|---|
| [`propuesta.html`](propuesta.html) | Propuesta funcional y técnica con prototipos y hoja de ruta | Histórico |
| [`audit/`](audit) | Paquete de auditoría: alcance, proveedores, presupuesto, revisión interna, superficie de ataque, dependencias, fuzzing y pruebas en dispositivo | Congelado el 30-oct-2026 |
| [`fdroid/`](fdroid) | Receta y pasos para publicar en F-Droid | Pausado |
| [`releases/`](releases) | Notas de la fallida `v0.1.0` | Histórico |
| [`fastlane/`](fastlane) | Metadatos de tienda | Histórico |
| [`scripts/firmar-release.sh`](scripts/firmar-release.sh) | Firma del APK compilado por la CI | Histórico |

## Qué sigue siendo útil para uso personal

- [`audit/internal-review.md`](audit/internal-review.md): los 26 hallazgos y su estado, incluidos los
  aceptados como riesgo residual.
- [`audit/attack-surface.md`](audit/attack-surface.md): por dónde entra cada dato no confiable.
- [`audit/dependencies.md`](audit/dependencies.md): `cargo-deny`, licencias y verificación de Gradle.
- [`audit/device-tests.md`](audit/device-tests.md): el plan de pruebas en teléfono y lo que falta.
- [`audit/decisions.md`](audit/decisions.md): por qué el núcleo se comporta como se comporta.

## Qué no hay que retomar salvo que el proyecto vuelva a ser público

Proveedores, presupuesto, NDA, OSTIF, NLnet, atestaciones Sigstore, SBOM, receta de F-Droid y notas de
release. Para instalar la app en un teléfono propio no aportan nada.
