# Paquete de auditoría externa

Este directorio reúne todo lo que un auditor externo necesita para revisar OpenPassword, y lo que el
proyecto necesita para contratar, seguir y cerrar esa auditoría. Cubre la Fase 3 de la
[propuesta](../propuesta.html)).

## Resumen de cierre (30-oct-2026)

> **Preparación de la Fase 3 completa; auditoría externa pendiente.** El endurecimiento está aplicado, los
> hallazgos internos están tratados y el paquete de auditoría está escrito, pero **no se ha contratado ni
> realizado ninguna auditoría externa**. Por eso el proyecto **no** está en 1.0 y la advertencia de
> [`SECURITY.md`](../../../SECURITY.md)) sigue vigente: no guardes datos reales todavía.

Este apartado es la puerta de entrada para retomar el trabajo.

### Qué está hecho

- **Endurecimiento**: los 19 pasos de ADR-AUD, con 3 pendientes o parciales (9, 18 y 19), en [`hardening.md`](hardening.md)).
- **Revisión interna**: 26 hallazgos en [`internal-review.md`](internal-review.md)): **19 corregidos, 1 parcial (ID-INT-23), 4 aceptados (entre ellos ID-INT-14, como riesgo residual) y 2 abiertos (ID-INT-20 e ID-INT-22)**.
- **Paquete de auditoría**: alcance, proveedores, presupuesto, proceso de hallazgos, superficie de ataque, revisión del modelo de amenazas, dependencias y fuzzing (índice más abajo).
- **Pruebas**: 102 tests de Rust en verde (ejecutados); 17 tests instrumentados en un SM-S948B (API 37) en verde; pruebas manuales en dispositivo en parte (tabla siguiente). Los 186 `@Test` de Kotlin en la JVM **sí** se han ejecutado (macOS, JDK 17): 186 pasan, 0 fallan.

### Qué falta

- **Contratar la auditoría externa** (nada contratado): elegir proveedor con [`vendors.md`](vendors.md)), pedir oferta con [`budget-timeline.md`](budget-timeline.md)) y firmar con [`scope.md`](scope.md)) como anexo.
- **Presupuesto**: todos los importes y fechas de [`budget-timeline.md`](budget-timeline.md)) son huecos a propósito; y los plazos y contactos de `scope.md`, sin rellenar.
- **Congelar la versión**: subir a `0.2.0`, crear `release/0.2`, etiquetar `v0.2.0` con firma y anotar el SHA aquí y en `scope.md` (todavía no hay rama ni etiqueta). Pasos 9 (parcial), 18 (parcial) y 19 de [`hardening.md`](hardening.md)); ejecutar una vez el job `release` y `fuzz-nightly.yml`.
- **Decisiones humanas aún abiertas** de [`decisions.md`](decisions.md)): solo la nº 1 (qué clave firma las etiquetas y cuándo se crea `release/0.2`). Las demás se aprobaron el 30-oct-2026.
- **Pruebas en dispositivo pendientes**: no bloquean la contratación (ver la tabla).

### Pruebas en dispositivo (SM-S948B, Android 17 / API 37, 30-oct-2026)

Detalle y evidencia en [`device-tests.md`](device-tests.md)). Sesión cerrada el 30-oct-2026; lo pendiente
requiere emulador o dispositivo API 28 y **no bloquea la contratación de la auditoría**.

| Prueba | Resultado | Motivo o límite |
|---|---|---|
| DT-01 (anti-tapjacking, API 31+) | **Pasa** | Solo `MainActivity` y un toque |
| DT-04a (borrado a los 30 s, primer plano) | **Pasa** | Solo API 37 |
| **DT-04b (borrado en segundo plano)** | **Falla** | Confirma ID-INT-14; **aceptado como riesgo residual** |
| DT-05 (lista de sufijos públicos) | **Pasa** | Solo build de depuración; **variante R8 pendiente** |
| DT-07 (app no navegador con `webDomain`) | **Pasa** | Faltan los pasos 4 y 5 del plan |
| Instrumentados (`connectedDebugAndroidTest`) | **Pasan** (17 tests) | Un único dispositivo |
| DT-02, DT-03 (anti-tapjacking API 28-30 y diálogos) | Pendiente | Requieren emulador API 28-30 (no hay imágenes en el equipo) |
| DT-06 (Chrome real) | Pendiente | Navegador real, sin ejecutar |
| DT-08 (navegador predeterminado malicioso) | Pendiente | Sin ejecutar |
| DT-09, DT-10 (autorrelleno completo y «recordar») | Pendiente | Sin ejecutar |
| DT-11 (aviso de root) | Pendiente | Requiere emulador `userdebug` |
| DT-12 (biometría en Android 9) | Pendiente | Requiere emulador o dispositivo API 28 |
| DT-13 (KDBX 4 real) | Pendiente | Sin ejecutar |
| DT-14, DT-15, DT-16, DT-17 (KDF/RAM, copias, bloqueo automático, TOTP) | Pendiente | Sin ejecutar |
| DT-04c, DT-04d (pantalla apagada, marca de sensible) | Pendiente | Sin ejecutar |

### Decisiones tomadas

- **Licencia NCSA** (`libfuzzer-sys`, solo en `fuzz/deny.toml`; ID-INT-23): **aprobada por el responsable el 30-oct-2026**. ID-INT-23 sigue «parcial».
- **ID-INT-06** (un elemento ilegible): se omite y se avisa en la lista, en lugar de impedir el desbloqueo (`EntryLoading.kt`).
- **ID-INT-14** (portapapeles): **aceptado como riesgo residual** al cerrar la fase. Limitación de Android: `clearPrimaryClip()` no surte efecto en segundo plano. Mitigaciones: marca de sensible, borrado a los 30 s con la app en primer plano, borrado al volver a la app y al apagar pantalla, y mensaje honesto en la UI. No se quita el botón de copiar. Ver [DT-04](device-tests.md#dt-04)).
- **Publicación en F-Droid: en pausa** por decisión del responsable (30-oct-2026); se retoma desde [`docs/fdroid/README.md`](../fdroid/README.md)).

> Nota sobre «sin commit»: varios documentos del paquete hablan de trabajo «sin commit» sobre `2bd56ce`.
> Ese trabajo está ya en `b2e18ca` («Fase 3: cerrar los hallazgos que no dependen del dispositivo») y
> `0ff88be`; el texto conserva la redacción original.

## Qué se audita

| Dato | Valor |
|---|---|
| Versión | `v0.2.0`, congelada tras el endurecimiento ([ADR-AUD-01](decisions.md#adr-aud-01--estrategia-de-congelación))) |
| Rama | `release/0.2` (todavía no existe; se crea al contratar la auditoría) |
| Commit base inspeccionado al redactar las decisiones | `3e94bce` («CI: fuzzing con el target gnu del runner») |
| Commit de `main` que contiene este paquete | `0ff88be` (pruebas en dispositivo y cierre), sobre `b2e18ca` (hallazgos que no dependen del dispositivo), `2bd56ce` (endurecimiento, cadena de suministro y paquete), `3725741` (frontera FFI y A7/A10) y `2c6ba2d` (cierre de la `v0.1.0`) |
| **Commit que se auditará** | **PENDIENTE**: SHA de 40 caracteres de la punta de `release/0.2` etiquetada `v0.2.0`. Se rellena al crear la etiqueta firmada |
| Etiqueta firmada | **PENDIENTE** (`git tag -l` no muestra ninguna etiqueta en el clon local; la clave de firma está pendiente de aprobación, ver [decisions.md](decisions.md#decisiones-que-requieren-aprobación-humana))) |
| Dentro del alcance | `op-core`, `op-ffi`, app Android, formato `.opvault` v1, builds reproducibles y firma |
| Fuera del alcance | CLI `opvault`, Fase 4, iOS y escritorio |

Cuando se cree la etiqueta, hay que actualizar **este fichero y [`scope.md`](scope.md))** con el SHA.
Lo que se audita es el SHA, no el nombre de la etiqueta.

## Índice y estado

Estados: **hecho** (escrito y contrastado con el repositorio), **pendiente** (falta contenido que
solo el proyecto puede aportar), **sin verificar** (contiene datos externos no comprobados).

| Documento | Para qué sirve | Estado |
|---|---|---|
| [`decisions.md`](decisions.md)) | ADR-AUD-01 a 07: decisiones técnicas previas a la auditoría | **hecho** como propuesta; su cabecera refleja ya que `3725741` y `2bd56ce` implementan ADR-AUD-02 a 07 (ver [`hardening.md`](hardening.md))), con el texto de los ADR sin tocar. Hay 10 decisiones que esperan aprobación humana |
| [`scope.md`](scope.md)) | *Scope of work* para el auditor | **pendiente**: faltan el SHA congelado, los plazos y los contactos. El resto está contrastado con el repositorio |
| [`vendors.md`](vendors.md)) | Shortlist de proveedores y vías de financiación | **sin verificar** en disponibilidad y precios; especialidades e informes públicos contrastados en las webs de cada proveedor (fuente y fecha en el documento) |
| [`budget-timeline.md`](budget-timeline.md)) | Plantilla de presupuesto por proveedor y calendario | **pendiente**: todos los importes y fechas son huecos a propósito |
| [`findings-process.md`](findings-process.md)) | Severidad, seguimiento, correcciones, re-test y criterios de `1.0.0` | **hecho** como propuesta; los plazos y criterios nuevos necesitan aprobación |
| [`attack-surface.md`](attack-surface.md)) | Superficie de ataque por componente | **hecho**, sin recontrastar línea a línea tras `2bd56ce` (se corrigieron las afirmaciones de ID-INT-01, 16, 25 y 26) |
| [`threat-model-review.md`](threat-model-review.md)) | Revisión del [modelo de amenazas](../../threat-model.md)) antes de la auditoría | **hecho**, con una nota de actualización posterior a `2bd56ce`: se aplicó parte de su sección 5 a `threat-model.md`, y las secciones que describen ID-INT-01 e ID-INT-16 reflejan el estado anterior a su corrección |
| [`internal-review.md`](internal-review.md)) | Revisión interna previa | **hecho**: 26 hallazgos (2 Alta, 3 Media, 11 Baja, 10 Info): 19 corregidos (los de `2bd56ce`: ID-INT-01, 05, 07, 24 y 25; el resto, en `b2e18ca`, incluidos 16 y 26), 1 parcial (ID-INT-23; la licencia NCSA está aprobada), **4 aceptados (ID-INT-04, 15, 19 y **ID-INT-14, riesgo residual aceptado**)** y 2 abiertos (ID-INT-20 y 22). Verificados en dispositivo el 30-oct-2026 (SM-S948B, API 37): ID-INT-13, los tests instrumentados de ID-INT-05, 08 y 09, la parte de ID-INT-16 sobre apps no navegador (DT-07) y la carga de la lista de sufijos de ID-INT-20 en la build de depuración (DT-05). ID-INT-14 se **confirmó como fallo** (el portapapeles no se borra con la app en segundo plano, DT-04) y se **acepta como riesgo residual**. Pendiente de dispositivo: 16 (Chrome real, DT-08, `iframe`), 18, 20 (R8) y 26 (y DT-02, DT-03 y DT-12, bloqueados o sin ejecutar); aprobadas el 30-oct-2026 la política de KDBX de ID-INT-02, la licencia NCSA de ID-INT-23 y la aceptación de ID-INT-14. Rust: 102 tests en verde; Kotlin en la JVM: 186 pasan, 0 fallan; instrumentadas: 17 pasan |
| [`dependencies.md`](dependencies.md)) | Inventario y política de dependencias | **hecho** (`cargo-deny`, verificación de Gradle, SBOM y Actions por SHA ya implementados; falta ejecutar el job `release` y una compilación con la verificación activa) |
| [`fuzzing.md`](fuzzing.md)) | Cobertura y resultados de fuzzing | **hecho** (11 objetivos, nocturno); sin ninguna ejecución del workflow nocturno ni cifras de ejecuciones de los objetivos nuevos |
| [`hardening.md`](hardening.md)) | Endurecimiento aplicado y pendiente | **hecho** (estado final de los 19 pasos de ADR-AUD); pasos pendientes: 9 en parte, 18 en parte y 19 |
| [`device-tests.md`](device-tests.md)) | Plan de pruebas manuales en dispositivo (DT-01 a DT-17) para lo que no se puede verificar en la JVM ni en la CI; sirve de evidencia para el auditor | **parcial**, sesión cerrada el 30-oct-2026: plan con resultados en un único dispositivo (SM-S948B, API 37): DT-01 `pasa` (con límites), DT-04 (04a `pasa`, **04b `falla`**: ID-INT-14, aceptado como riesgo residual), DT-05 `pasa` (solo depuración) y DT-07 `pasa`; DT-02 y DT-12 `bloqueado`; el resto **pendiente** (resumen de cierre arriba). Evidencia sin archivar (ver sección 3.4) |

Todos los documentos del índice existen.

Documentos del repositorio que el auditor debe leer y que **no** se copian aquí:

- [`docs/crypto-spec.md`](../../crypto-spec.md)): primitivas, claves, AAD, STREAM, KDF.
- [`docs/opvault-format.md`](../../opvault-format.md)): formato `.opvault` v1.
- [`docs/threat-model.md`](../../threat-model.md)): activos, atacantes A1–A18 y riesgos residuales.
- [`SECURITY.md`](../../../SECURITY.md)): cómo se notifican vulnerabilidades y plazos.
- [`android/README.md`](../../../android/README.md)) y [`docs/fdroid/README.md`](../fdroid/README.md)): compilación y build reproducible.

> **Publicación en F-Droid: en pausa** por decisión del responsable del proyecto (30-oct-2026). No bloquea
> el paquete de auditoría: la versión que se audita se entrega como pre-release de GitHub, no desde
> F-Droid. Ver [`docs/fdroid/README.md`](../fdroid/README.md)) para retomarla.
- [`core/tests/vectors/op-v1.json`](../../../core/tests/vectors/op-v1.json)): vectores dorados del formato.

## Cómo se usa el paquete con un proveedor

1. **Antes del contacto.** Comprueba que la tabla «Qué se audita» no tiene `PENDIENTE` y que
   `scope.md` tiene SHA, plazos y contactos. Sin eso no se envía nada.
2. **Primer contacto.** Se envía solo `scope.md`, el enlace al repositorio público y el SHA. No hay
   nada secreto en el código (GPL-3.0-or-later, repositorio público); la confidencialidad afecta a
   los hallazgos, no al código.
3. **Presupuesto.** Se pide la oferta usando la plantilla de [`budget-timeline.md`](budget-timeline.md))
   y se compara con los criterios de [`vendors.md`](vendors.md)). Se exigen por escrito el re-test
   incluido y el permiso para publicar el informe.
4. **Contratación.** Se firma con el alcance de `scope.md` como anexo. Se concede al auditor acceso de
   lectura al repositorio y, para los hallazgos, a los avisos privados de GitHub según
   [`findings-process.md`](findings-process.md)).
5. **Durante la auditoría.** Solo se aceptan en `release/0.2` los cambios permitidos por ADR-AUD-01.
   Los hallazgos siguen el flujo de `findings-process.md`.
6. **Cierre.** Re-test, informe final publicable, avisos y criterios de `1.0.0`
   (ver `findings-process.md`).

## Mantenimiento

- Este índice es la única fuente de verdad del estado de cada documento. Si cambia uno, cambia aquí.
- Las cifras técnicas (versiones de toolchain, límites de la KDF) no se copian: se enlazan a su
  fuente (`rust-toolchain.toml`, `docs/crypto-spec.md`, `decisions.md`).
