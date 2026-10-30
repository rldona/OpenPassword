# Presupuesto y calendario

Plantilla para comparar ofertas y planificar la auditoría de `v0.2.0`
([`scope.md`](scope.md)).

**Todos los importes y fechas son huecos (`___`) a propósito.** No hay presupuesto asignado, no se
ha pedido ninguna oferta y ningún proveedor publica tarifas (ver [`vendors.md`](vendors.md)). Se
rellena cuando lleguen las ofertas, y cada cifra debe llevar su fuente (oferta con fecha y referencia).

## 1. Plantilla por proveedor

Copiar un bloque por proveedor (`### <Proveedor>`) y rellenar. Los componentes son los de
[`scope.md`](scope.md#4-dentro-del-alcance).

### `<Proveedor>`

| Dato | Valor |
|---|---|
| Fuente de la oferta (fecha, referencia) | `___` |
| Moneda e impuestos (IVA incluido sí/no) | `___` |
| Validez de la oferta | `___` |
| Tarifa por día-persona | `___` |
| Perfil del equipo (personas, experiencia en Rust/Android/criptografía) | `___` |

**Esfuerzo por componente** (días-persona):

| Componente | Días-persona | Notas |
|---|---|---|
| `op-core`: criptografía, formato, STREAM, KDF | `___` | |
| `op-core`: importadores (KDBX, 1Password, Bitwarden, CSV) y TOTP | `___` | |
| `op-ffi`: UniFFI, secretos, panics, límites de la KDF | `___` | |
| App Android: sesión, Keystore y biometría | `___` | |
| App Android: autorrelleno (coincidencias, sufijos públicos, guardado) | `___` | |
| App Android: portapapeles, anti-tapjacking, aviso de root, almacenamiento | `___` | |
| Formato `.opvault` (revisión de diseño) | `___` | |
| Builds reproducibles y firma | `___` | |
| Gestión del proyecto y reuniones | `___` | |
| **Subtotal auditoría** (días × tarifa) | `___` | |

**Costes adicionales:**

| Concepto | Importe | Notas |
|---|---|---|
| Informe preliminar | `___` | ¿incluido en el subtotal? |
| Re-test (rondas incluidas: `___`) | `___` | Cada ronda adicional: `___` |
| Informe final publicable | `___` | ¿Revisión por el proveedor incluida? |
| Resumen para usuarios (opcional) | `___` | |
| Gastos (viajes, licencias, dispositivos de prueba) | `___` | |
| Impuestos | `___` | |
| **Total** | `___` | |

**Condiciones** (obligatorias salvo que se indique):

| Condición | ¿La cumple? | Notas |
|---|---|---|
| Permiso por escrito para publicar el informe completo | `___` | **Obligatoria** |
| Re-test incluido | `___` | **Obligatoria** (al menos una ronda) |
| Hallazgos críticos notificados de inmediato | `___` | |
| Entrega de PoC | `___` | |
| Idioma del informe | `___` | |
| Plazo desde la firma hasta el arranque | `___` | |
| Duración de la auditoría (semanas) | `___` | |
| Forma de pago y calendario de pagos | `___` | |

**Financiación** (ver [`vendors.md` §3](vendors.md#3-vías-de-financiación)):

| Vía | Importe solicitado | Importe concedido | Estado y fecha | Condiciona al proveedor |
|---|---|---|---|---|
| OSTIF | `___` | `___` | `___` | `___` |
| OTF Security Lab | `___` | `___` | `___` | `___` |
| NLnet Restack | `___` | `___` | `___` | `___` |
| Fondos propios | `___` | `___` | `___` | no |
| **Total cubierto** | `___` | | | |
| **Diferencia por cubrir** | `___` | | | |

### Comparativa

| Proveedor | Total | Cubierto | Por cubrir | Re-test | Publicación | Arranque | Duración |
|---|---|---|---|---|---|---|---|
| `___` | `___` | `___` | `___` | `___` | `___` | `___` | `___` |

## 2. Calendario

Las duraciones son huecos. Cada hito tiene una **condición de salida**: no se pasa al siguiente sin
cumplirla. Las políticas de rama y de cambios durante la auditoría están en
[ADR-AUD-01](decisions.md#adr-aud-01--estrategia-de-congelación).

| # | Hito | Fecha objetivo | Duración | Condición de salida |
|---|---|---|---|---|
| 1 | Financiación y proveedor decididos | `___` | `___` | Oferta aceptada; contrato con permiso de publicación y re-test; importe cubierto |
| 2 | **Congelación**: `release/0.2` y etiqueta firmada `v0.2.0` | `___` | `___` | Pasos 1–18 del plan de [`decisions.md`](decisions.md) hechos y en verde; CI de la etiqueta en verde; SHA-256 del APK coincide con una build independiente en Linux; SHA anotado en [`README.md`](README.md) y [`scope.md`](scope.md); paquete adjunto a la pre-release |
| 3 | **Arranque** | `___` | `___` | Reunión inicial hecha; acceso al repositorio y a los avisos privados; contactos confirmados |
| 4 | Auditoría activa | `___` | `___` | Hallazgos críticos notificados al momento; el proyecto responde a las preguntas en `___` días |
| 5 | **Informe preliminar** | `___` | `___` | Informe recibido; cada hallazgo registrado en un aviso privado |
| 6 | **Correcciones** | `___` | `___` | Cada hallazgo aceptado tiene corrección con test de regresión en `main` y, tras `cherry-pick -x`, en `release/0.2`; etiqueta firmada `v0.2.N`; diff entregado |
| 7 | **Re-test** | `___` | `___` | El auditor marca cada hallazgo como corregido, parcial, no corregido o aceptado |
| 8 | **Informe final** | `___` | `___` | Informe final recibido; texto público revisado; fecha de publicación pactada |
| 9 | Publicación | `___` | `___` | Informe y avisos publicados ([`findings-process.md`](findings-process.md)) |
| 10 | **`1.0.0`** | `___` | `___` | Criterios de [`findings-process.md`](findings-process.md#7-criterios-para-la-100) cumplidos |

Dependencias a vigilar:

- El hito 2 depende de decisiones pendientes de aprobación humana (lista final de
  [`decisions.md`](decisions.md#decisiones-que-requieren-aprobación-humana)).
- Si hay varios proveedores o financiación, el hito 1 puede retrasarse; las convocatorias de NLnet
  son cada ~2 meses (ver [`vendors.md`](vendors.md)).
- El hito 6 puede repetirse (`v0.2.N`) antes del re-test; el auditor decide cuántas rondas caben.
- Los márgenes de seguridad (vacaciones, disponibilidad del mantenedor, un solo mantenedor) se
  anotan en `___`.
