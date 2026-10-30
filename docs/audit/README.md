# Paquete de auditoría externa

Este directorio reúne todo lo que un auditor externo necesita para revisar OpenPassword, y lo que el
proyecto necesita para contratar, seguir y cerrar esa auditoría. Cubre la Fase 3 de la
[propuesta](../propuesta.html).

> Estado del proyecto: **sin auditoría externa**. [`SECURITY.md`](../../SECURITY.md) y las notas de
> release lo advierten: no guardes datos reales todavía.

## Qué se audita

| Dato | Valor |
|---|---|
| Versión | `v0.2.0`, congelada tras el endurecimiento ([ADR-AUD-01](decisions.md#adr-aud-01--estrategia-de-congelación)) |
| Rama | `release/0.2` (todavía no existe) |
| Commit base inspeccionado al redactar las decisiones | `3e94bce` («CI: fuzzing con el target gnu del runner») |
| Commit de `main` al redactar este paquete | `3725741` («Fase 3: frontera FFI robusta y defensas A7/A10»), con cambios sin confirmar en el árbol de trabajo |
| **Commit que se auditará** | **PENDIENTE**: SHA de 40 caracteres de la punta de `release/0.2` etiquetada `v0.2.0`. Se rellena al crear la etiqueta firmada |
| Etiqueta firmada | **PENDIENTE** (`git tag -l` no muestra ninguna etiqueta en el clon local; la clave de firma está pendiente de aprobación, ver [decisions.md](decisions.md#decisiones-que-requieren-aprobación-humana)) |
| Dentro del alcance | `op-core`, `op-ffi`, app Android, formato `.opvault` v1, builds reproducibles y firma |
| Fuera del alcance | CLI `opvault`, Fase 4, iOS y escritorio |

Cuando se cree la etiqueta, hay que actualizar **este fichero y [`scope.md`](scope.md)** con el SHA.
Lo que se audita es el SHA, no el nombre de la etiqueta.

## Índice y estado

Estados: **hecho** (escrito y contrastado con el repositorio), **pendiente** (falta contenido que
solo el proyecto puede aportar), **sin verificar** (contiene datos externos no comprobados),
**en preparación** (lo redacta otra persona o agente).

| Documento | Para qué sirve | Estado |
|---|---|---|
| [`decisions.md`](decisions.md) | ADR-AUD-01 a 07: decisiones técnicas previas a la auditoría | **hecho** como propuesta; su cabecera aún dice «ninguna decisión está implementada», pero el commit `3725741` ya incluye cambios de ADR-AUD-03 y ADR-AUD-06. Hay 10 decisiones que esperan aprobación humana |
| [`scope.md`](scope.md) | *Scope of work* para el auditor | **pendiente**: faltan el SHA congelado, los plazos y los contactos. El resto está contrastado con el repositorio |
| [`vendors.md`](vendors.md) | Shortlist de proveedores y vías de financiación | **sin verificar** en disponibilidad y precios; especialidades e informes públicos contrastados en las webs de cada proveedor (fuente y fecha en el documento) |
| [`budget-timeline.md`](budget-timeline.md) | Plantilla de presupuesto por proveedor y calendario | **pendiente**: todos los importes y fechas son huecos a propósito |
| [`findings-process.md`](findings-process.md) | Severidad, seguimiento, correcciones, re-test y criterios de `1.0.0` | **hecho** como propuesta; los plazos y criterios nuevos necesitan aprobación |
| [`attack-surface.md`](attack-surface.md) | Superficie de ataque por componente | **en preparación** |
| [`threat-model-review.md`](threat-model-review.md) | Revisión del [modelo de amenazas](../threat-model.md) antes de la auditoría | **en preparación** |
| [`internal-review.md`](internal-review.md) | Revisión interna previa | **en preparación** |
| [`dependencies.md`](dependencies.md) | Inventario y política de dependencias | **en preparación** |
| [`fuzzing.md`](fuzzing.md) | Cobertura y resultados de fuzzing | **en preparación** (los objetivos existentes ya se describen en [`fuzz/README.md`](../../fuzz/README.md)) |
| [`hardening.md`](hardening.md) | Endurecimiento aplicado y pendiente | **en preparación** |

Los enlaces a los seis documentos «en preparación» apuntan a ficheros que pueden no existir todavía.

Documentos del repositorio que el auditor debe leer y que **no** se copian aquí:

- [`docs/crypto-spec.md`](../crypto-spec.md): primitivas, claves, AAD, STREAM, KDF.
- [`docs/opvault-format.md`](../opvault-format.md): formato `.opvault` v1.
- [`docs/threat-model.md`](../threat-model.md): activos, atacantes A1–A16 y riesgos residuales.
- [`SECURITY.md`](../../SECURITY.md): cómo se notifican vulnerabilidades y plazos.
- [`android/README.md`](../../android/README.md) y [`docs/fdroid/README.md`](../fdroid/README.md): compilación y build reproducible.
- [`core/tests/vectors/op-v1.json`](../../core/tests/vectors/op-v1.json): vectores dorados del formato.

## Cómo se usa el paquete con un proveedor

1. **Antes del contacto.** Comprueba que la tabla «Qué se audita» no tiene `PENDIENTE` y que
   `scope.md` tiene SHA, plazos y contactos. Sin eso no se envía nada.
2. **Primer contacto.** Se envía solo `scope.md`, el enlace al repositorio público y el SHA. No hay
   nada secreto en el código (GPL-3.0-or-later, repositorio público); la confidencialidad afecta a
   los hallazgos, no al código.
3. **Presupuesto.** Se pide la oferta usando la plantilla de [`budget-timeline.md`](budget-timeline.md)
   y se compara con los criterios de [`vendors.md`](vendors.md). Se exigen por escrito el re-test
   incluido y el permiso para publicar el informe.
4. **Contratación.** Se firma con el alcance de `scope.md` como anexo. Se concede al auditor acceso de
   lectura al repositorio y, para los hallazgos, a los avisos privados de GitHub según
   [`findings-process.md`](findings-process.md).
5. **Durante la auditoría.** Solo se aceptan en `release/0.2` los cambios permitidos por ADR-AUD-01.
   Los hallazgos siguen el flujo de `findings-process.md`.
6. **Cierre.** Re-test, informe final publicable, avisos y criterios de `1.0.0`
   (ver `findings-process.md`).

## Mantenimiento

- Este índice es la única fuente de verdad del estado de cada documento. Si cambia uno, cambia aquí.
- Las cifras técnicas (versiones de toolchain, límites de la KDF) no se copian: se enlazan a su
  fuente (`rust-toolchain.toml`, `docs/crypto-spec.md`, `decisions.md`).
