# Proceso de hallazgos

Cómo se registran, corrigen, verifican y publican los hallazgos de la auditoría de `v0.2.0`, y qué
hace falta para publicar `1.0.0`.

Estado: **propuesta**. Respeta [`SECURITY.md`](../../../SECURITY.md)) (acuse a 3 días, valoración a 10,
corrección a 90 como máximo) y la política de ramas de
[ADR-AUD-01](decisions.md#adr-aud-01--estrategia-de-congelación)). Lo que **añade** a `SECURITY.md`
(severidades con plazo, criterios de `1.0.0`) necesita aprobación y se lista en la sección 9.

## 1. Escala de severidad

Se usa **CVSS 4.0** como puntuación y una etiqueta cualitativa de cinco niveles. Los rangos son los
de las valoraciones cualitativas de CVSS (*Critical* 9.0–10.0, *High* 7.0–8.9, *Medium* 4.0–6.9,
*Low* 0.1–3.9, *None* 0.0; <https://www.first.org/cvss/>).

| Etiqueta | CVSS 4.0 | Criterio en OpenPassword (ejemplos) |
|---|---|---|
| **Crítica** | 9.0–10.0 | Se obtienen secretos o la contraseña maestra/SK sin conocerlas, o se rompe la confidencialidad o integridad del formato; ejecución de código con un fichero (`.opvault` o importado) |
| **Alta** | 7.0–8.9 | El autorrelleno entrega credenciales a un sitio o app equivocados; una defensa descrita en el modelo de amenazas no existe o se salta; clave en memoria tras bloquear con el proceso vivo |
| **Media** | 4.0–6.9 | Denegación de servicio repetible con un fichero hostil; fuga de metadatos; residuo de secretos no documentado |
| **Baja** | 0.1–3.9 | Defensa en profundidad que falta; mensaje que filtra información sin consecuencia práctica |
| **Info** | 0.0 | Observación, mejora de robustez o documentación sin impacto de seguridad directo |

Reglas:

- El auditor propone la severidad; el proyecto la discute con el auditor **por escrito en el
  hallazgo**. Si no hay acuerdo, prevalece la más alta hasta el re-test, y el desacuerdo consta en el
  informe público.
- El vector CVSS se calcula considerando el [modelo de amenazas](../../threat-model.md)): un ataque que
  exige root malicioso (A10) está fuera de alcance y se clasifica Info salvo que el auditor
  justifique otro impacto.
- Se anotan también el componente (`op-core`, `op-ffi`, Android, formato, build) y la **versión
  afectada** (`v0.1.0`, `v0.2.0` o ambas).

### Plazos (alineados con `SECURITY.md`)

`SECURITY.md` fija 3 días (acuse), 10 días (primera valoración) y un máximo de 90 días a la
corrección publicada, «antes si es grave». Para los hallazgos de auditoría se propone concretar el
plazo de corrección por severidad. **Son objetivos propuestos, a aprobar**; el tope de 90 días no
cambia.

| Severidad | Acuse | Valoración | Corrección en `release/0.2` (objetivo) |
|---|---|---|---|
| Crítica | 3 días | 3 días | 14 días |
| Alta | 3 días | 10 días | 30 días |
| Media | 3 días | 10 días | 60 días |
| Baja | 3 días | 10 días | 90 días |
| Info | 3 días | 10 días | Sin plazo; se decide en el re-test |

El reloj empieza cuando el proyecto recibe el hallazgo (informe preliminar o aviso anterior, si el
auditor lo notifica antes). Si un plazo no se puede cumplir, se escribe el motivo en el hallazgo y se
comunica al auditor; no se amplía en silencio.

## 2. Registro: GitHub Security Advisories privados

- **Un aviso privado por hallazgo**, creado desde el repositorio en la pestaña *Security →
  Advisories*, con el mismo canal que usa [`SECURITY.md`](../../../SECURITY.md)). No se abren issues
  públicos ni se comentan hallazgos en PR públicos.
- El auditor se añade como colaborador del aviso (o lo crea con *Report a vulnerability*).
- Título: `AUD-nn · <resumen>`. El identificador `AUD-nn` es el del informe del auditor si lo tiene;
  si no, el proyecto asigna el siguiente número.
- Contenido mínimo del aviso:

| Campo | Contenido |
|---|---|
| Identificador | `AUD-nn` |
| Severidad y vector CVSS 4.0 | Etiqueta y vector |
| Componente y fichero | Ruta y línea sobre el SHA congelado |
| Versiones afectadas | `v0.1.0`, `v0.2.0` |
| Descripción, impacto y PoC | Del auditor |
| Decisión | Aceptado, rechazado con motivo, aceptado como riesgo residual |
| Corrección | Enlace al PR en `main` y *commit* del `cherry-pick -x` |
| Test de regresión | Ruta del test |
| Estado | Nuevo → Aceptado → En corrección → Corregido → Verificado por el auditor → Publicado |

- Las **correcciones de hallazgos bajo embargo** se desarrollan en el *fork privado temporal* del
  aviso y se fusionan el mismo día que se publica la versión corregida (excepción de ADR-AUD-01).
- Al terminar, el aviso se publica (sección 6) y el estado queda reflejado en el informe público.

## 3. Corrección

Cada hallazgo aceptado se corrige con:

1. **Un PR a `main`** cuyo título empieza por `AUD-nn:`. Cuerpo: enlace al aviso privado (o su
   identificador, si es público), causa raíz, alcance del cambio y por qué no es otra cosa.
2. **Un test de regresión** que **falla sin la corrección** y pasa con ella. Nombre o comentario con
   `AUD-nn`. Tipos admitidos:
   - Rust: test en el crate afectado (`core/`, `ffi/`); vector nuevo en `core/tests/vectors/op-v1.json`
     solo si la corrección no cambia el formato v1. Si lo cambia, es **versión nueva del formato** y
     se decide aparte (los vectores existentes no se regeneran);
   - Kotlin: test unitario (JUnit 4) o instrumentado;
   - un nuevo objetivo de *fuzzing* o una semilla en `fuzz/seeds/` cuando el fallo es de análisis de
     datos no confiables;
   - si es imposible automatizarlo (p. ej. un ajuste de manifiesto), una comprobación en la build
     (como `VerifyManifest`) o, como última opción, un paso manual escrito en el hallazgo.
3. **Cambio de documentación** si el hallazgo desmiente una afirmación de
   [`docs/threat-model.md`](../../threat-model.md)), [`docs/crypto-spec.md`](../../crypto-spec.md)) o
   [`android/README.md`](../../../android/README.md)): se corrige el texto **o** el código.
4. **`cherry-pick -x` a `release/0.2`** (política de ADR-AUD-01) y etiqueta firmada `v0.2.N`.
5. **Entrega al auditor** del diff `git diff v0.2.(N-1)..v0.2.N` y del enlace al test de regresión.

Cuando el auditor está en desacuerdo con la corrección, se discute en el aviso, no en un canal aparte.

## 4. Verificación por el auditor (re-test)

- El auditor comprueba cada hallazgo sobre la etiqueta `v0.2.N`, no sobre `main`.
- Estados finales: **Corregido**, **Parcial** (con lo que falta), **No corregido** o **Aceptado como
  riesgo** (decisión del proyecto, con motivo, aprobada por el auditor como «entendida»).
- Un hallazgo no se cierra sin la confirmación **escrita** del auditor.
- Una corrección que introduce un problema nuevo es un hallazgo nuevo.
- El re-test cubre solo lo que cambió. Cambios de otra naturaleza en `release/0.2` están prohibidos por
  la política de ADR-AUD-01; no se cuelan correcciones «de paso».

## 5. Aceptación de riesgo

Un hallazgo puede cerrarse sin corregir solo si:

- es Baja o Info, **o** es el residuo ya documentado en [`decisions.md`](decisions.md)) (p. ej. `String`
  de JVM, `RustBuffer` de salida, aborto por falta de memoria en Argon2);
- consta el motivo, el impacto residual y quién lo decide (el mantenedor);
- se enumera en «Riesgos residuales» del [modelo de amenazas](../../threat-model.md)) y en el informe
  público;
- el auditor ha tenido ocasión de discrepar.

**Crítica y Alta no se aceptan como riesgo** sin una decisión explícita registrada y visible en el
informe público; en ese caso `1.0.0` queda bloqueada hasta revisarla (sección 7).

## 6. Publicación

1. **Informe.** El informe final (sección 8 de [`scope.md`](scope.md))) se publica con el
   permiso del proveedor, en el repositorio o en la release. Debe incluir alcance, metodología,
   hallazgos con su estado final y las limitaciones. Si OSTIF o un financiador lo pide, se coordina
   su calendario (ver [`vendors.md`](vendors.md))).
2. **Orden.** Se publica **después** de que las correcciones estén en una versión firmada y publicada y
   de que los avisos se hayan publicado. Un hallazgo no corregido y no acordado no se publica con
   detalle técnico sin la fecha pactada con el auditor.
3. **Avisos y CVE.** Para cada hallazgo que afecte a una versión **ya publicada** (p. ej. `v0.1.0`)
   y sea Media o superior, el aviso se publica con el [GitHub Security
   Advisory](https://docs.github.com/en/code-security/security-advisories) y se solicita CVE desde el
   propio aviso (GitHub actúa como CNA; sin verificar en detalle de plazo). Los hallazgos que solo
   afectan a `v0.2.0` pre-release no tienen usuarios afectados: se publican en el informe y, si se
   considera útil, también como aviso sin CVE. Los hallazgos Bajos o Info no necesitan CVE.
4. **Notas de versión.** Cada `v0.2.N` indica qué hallazgos corrige (por `AUD-nn`) en
   `docs/releases/` y en los *changelogs* de `fastlane/`.
5. **Aviso en el repositorio.** Se actualizan `SECURITY.md`, `README.md` y las notas de release para
   retirar o matizar el aviso «sin auditoría externa» **solo** cuando se cumpla la sección 7.

## 7. Criterios para la `1.0.0`

Propuesta, a aprobar. `1.0.0` solo se etiqueta cuando se cumple **todo**:

| # | Criterio | Cómo se comprueba |
|---|---|---|
| 1 | Todos los hallazgos **Críticos y Altos** están Corregidos y **Verificados por el auditor** | Estado en los avisos y en el informe final |
| 2 | Los **Medios** están Corregidos o Aceptados con motivo escrito y visible | Informe final; sección «Riesgos residuales» |
| 3 | Cada hallazgo corregido tiene test de regresión referenciado | Revisión de los PR `AUD-nn` |
| 4 | Informe final **publicado** con permiso del proveedor | Enlace en el repositorio |
| 5 | Avisos y CVE publicados para lo que afecta a versiones publicadas | Pestaña *Security* del repositorio |
| 6 | La CI de la etiqueta `1.0.0` está en verde, el APK es reproducible en Linux y el SHA-256 coincide con el de una build independiente | `ci.yml`, [`docs/fdroid/README.md`](../fdroid/README.md)) |
| 7 | [`docs/threat-model.md`](../../threat-model.md)), [`docs/crypto-spec.md`](../../crypto-spec.md)) y [`android/README.md`](../../../android/README.md)) coinciden con el código | Revisión final; nada «previsto» descrito como hecho |
| 8 | Las decisiones pendientes de aprobación de [`decisions.md`](decisions.md)) están resueltas | Lista final de `decisions.md` sin elementos abiertos |
| 9 | `SECURITY.md` actualizado (versiones con soporte, referencia al informe) | Revisión |
| 10 | Una persona independiente del mantenedor revisa la lista de comprobación (si existe esa persona; si no, se anota) | Constancia en el PR de la release |

Si un criterio no se cumple, no se publica `1.0.0` y se etiqueta `0.x` con las correcciones; se
decide caso por caso si hace falta nueva ronda de re-test.

## 8. Agradecimientos

- El informe final y las notas de release citan al proveedor y a las personas auditoras con su permiso.
- Los avisos publicados incluyen los créditos de GitHub (aviso → *Credits*).
- Se citan también a quienes envíen hallazgos por fuera de la auditoría, salvo que prefieran no
  aparecer (ya lo promete [`SECURITY.md`](../../../SECURITY.md))).
- No hay programa de recompensas por ahora.

## 9. Cambios propuestos (no se han aplicado)

Este paquete **no modifica** `SECURITY.md` ni el código. Cambios propuestos, a aprobar:

| Fichero | Cambio |
|---|---|
| `SECURITY.md`, «Versiones con soporte» | Añadir «la rama `release/0.2` hasta el cierre de la auditoría» (ya lo exige ADR-AUD-01) |
| `SECURITY.md`, «Qué esperar» | Añadir la tabla de objetivos de corrección por severidad (sección 1) y mantener el máximo de 90 días |
| `SECURITY.md`, «Dentro del alcance» | Comprobar que lo que figura ahí coincide con [`scope.md`](scope.md)); al redactar esto coincidía en lo esencial |
| `SECURITY.md`, aviso inicial | Sustituir «El proyecto aún no ha pasado una auditoría externa» por un enlace al informe publicado **solo** al cumplir la sección 7 |
| `docs/threat-model.md` | Enlazar al informe y reflejar los riesgos residuales aceptados |
| Repositorio (GitHub) | Activar la notificación privada de vulnerabilidades si no lo está (ver `SECURITY.md`) y definir las etiquetas `security`, `AUD` |

## 10. Contactos y responsabilidades

| Rol | Persona |
|---|---|
| Responsable de hallazgos y correcciones | `@rldona` |
| Verificación independiente de la `1.0.0` | **PENDIENTE** |
| Contacto del auditor | **PENDIENTE** |
