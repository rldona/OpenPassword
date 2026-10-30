# Proveedores y financiación

Shortlist para la auditoría externa de `v0.2.0` ([`scope.md`](scope.md)) y vías para pagarla.

**Regla de este documento:** solo se afirma lo que se ha leído en la fuente citada. Lo demás figura
como «sin verificar». **No hay precios**: ningún proveedor publica tarifas y no se ha pedido ninguna
oferta. Las cifras se rellenan en [`budget-timeline.md`](budget-timeline.md) cuando haya ofertas.

Fecha de la consulta: 2026-10-30. Las páginas pueden haber cambiado desde entonces.

## 1. Qué se puede decir de cada proveedor

«Informes públicos» = el proveedor publica informes de clientes en su web (con permiso del cliente).
«Disponibilidad» = capacidad y plazos reales de arranque: **ninguna se ha podido comprobar sin
contactar**, así que figura «sin verificar» en todos los casos.

| Proveedor | Web | Especialidad (según su web) | Informes públicos | Disponibilidad | Sede / idioma |
|---|---|---|---|---|---|
| **Cure53** | <https://cure53.de/> | Pentests y auditorías de código; auditorías de «infraestructura, plataformas y criptografía» (evalúan algoritmos y su implementación, gestión de claves) | **Sí**: lista de informes públicos (p. ej. *Proton Pass* Browser Addon, Apps & API, 05–06.2023; *1Password Mobile Apps*, 02–03.2022; *ExpressVPN Android Client*, 08.2022; *Gem Wallet Rust Wallet Core*, 09.2026) | Sin verificar | Alemania; inglés (la web está en inglés) |
| **Trail of Bits** | <https://trailofbits.com/services/software-assurance/> | Revisiones multidisciplinares con equipo de criptografía y *appsec*; declaran 661 auditorías y 993 publicaciones | **Sí**: repositorio [`trailofbits/publications`](https://github.com/trailofbits/publications) con informes por proyecto (ej. `sigstore-rust`, oct. 2026) | Sin verificar | EE. UU.; inglés. Experiencia Android: sin verificar |
| **NCC Group** | <https://www.nccgroup.com/> | La web lista *Application Security*, *Cryptography & Encryption* y *Penetration Testing* como servicios | Sin verificar (no se ha localizado una lista de informes en la consulta) | Sin verificar | Internacional; inglés. Android/Rust: sin verificar |
| **Radically Open Security (ROS)** | <https://www.radicallyopensecurity.com/> | Consultora de seguridad **sin ánimo de lucro**; la web lista auditorías de código y de criptografía y protocolos | Sin verificar en esta consulta (su web no enumera informes en las páginas consultadas) | Sin verificar | Países Bajos; inglés. Rust/Android: sin verificar |
| **X41 D-Sec** | <https://x41-dsec.de/> | Auditorías de código fuente, pentests, *fuzzing*, investigación | **Sí**: lista de auditorías públicas, muchas para OSTIF (incluye *Hickory DNS*, un proyecto en Rust; también *Mullvad VPN* y *SecureDrop*) | Sin verificar | Alemania; inglés. Android: sin verificar |
| **7ASecurity** | <https://7asecurity.com/> | Pentests y auditorías de código, incluidas apps móviles; socio del Security Lab de OTF; «EU-based» | **Sí**: [`/publications`](https://7asecurity.com/publications) (incluye informes con *Android app* y *Crypto & Privacy Audit*, p. ej. *Noghteha*, 02.2026; y varios para OSTIF y OTF) | Sin verificar | UE; inglés. Rust: sin verificar |
| **Include Security** | <https://includesecurity.com/> | Evaluaciones de aplicaciones asistidas por código fuente; su web lista *Mobile App Assessments* y *Fuzzing* | Sin verificar (no se ha localizado una lista de informes) | Sin verificar | Brooklyn (EE. UU.); inglés |
| **Quarkslab** | <https://www.quarkslab.com/> | Ingeniería inversa y seguridad; su blog tiene categorías de criptografía, Android y *fuzzing*; «desde 2026 forma parte de Airbus Defence and Space» (según su web) | **Parcial**: su blog describe una auditoría de *mbedTLS* realizada a petición de OSTIF (2026-10-20); si publican un informe por cliente: sin verificar | Sin verificar | Francia; inglés y francés |

Notas:

- La columna «Sede / idioma» es orientativa (aviso legal, dominio, direcciones o teléfonos de la web;
  en Trail of Bits y NCC Group no se comprobó en la consulta). Confirmarla antes de contratar.
- La presencia de un informe de un proyecto parecido (Proton Pass, 1Password) **no** implica
  experiencia con el stack de OpenPassword (Rust + UniFFI + Compose). Hay que preguntarlo.
- «Rust» y «Android» se marcan «sin verificar» cuando la web no lo dice explícitamente, aunque el
  proveedor pueda tener experiencia.
- Cada ficha debe completarse con la respuesta del proveedor a la plantilla de
  [`budget-timeline.md`](budget-timeline.md).

## 2. Criterios de comparación

| Criterio | Qué preguntar o comprobar | Peso |
|---|---|---|
| Criptografía y Rust | ¿Auditores con experiencia en AEAD, KDF y *constructions* tipo STREAM? ¿Han revisado código Rust y UniFFI? | **PENDIENTE** (decide el proyecto) |
| Android | ¿Keystore, biometría, autorrelleno (`AutofillService`) y *tapjacking*? ¿Informes previos de apps Android? | **PENDIENTE** |
| Informes públicos | ¿Publican informes? ¿De proyectos de este tipo? | **PENDIENTE** |
| Re-test incluido | ¿El presupuesto incluye la verificación de las correcciones? ¿Cuántas rondas y en qué plazo? | **PENDIENTE** |
| Permiso para publicar | ¿El contrato permite publicar el informe completo sin condiciones? ¿Con qué retraso? | **PENDIENTE** (condición obligatoria: sí) |
| Plazos | Fecha de arranque, duración y fecha del informe preliminar | **PENDIENTE** |
| Coste | Importe total e historial de descuentos para proyectos abiertos | **PENDIENTE** |
| Idioma | Idioma del informe y de la comunicación (el proyecto escribe en español; el informe público debería estar en inglés) | **PENDIENTE** |
| Equipo y metodología | Personas concretas, horas por componente, uso de *fuzzing* y de revisión de código fuente | **PENDIENTE** |
| Conflictos de interés | Relación con proveedores de la cadena (Google, Mozilla, etc.) o con otros gestores | **PENDIENTE** |

Una tabla comparativa con puntuaciones se añade aquí **solo cuando haya ofertas**; no se puntúa
sobre datos no verificados.

## 3. Vías de financiación

Ninguna tiene presupuesto asignado todavía. Los datos proceden de las webs oficiales (consulta
2026-10-30).

### 3.1 OSTIF (Open Source Technology Improvement Fund)

- Fuente: <https://ostif.org/get-an-audit/>.
- Es una organización sin ánimo de lucro que **coordina** la auditoría: define el alcance contigo,
  selecciona el equipo («según tus necesidades de experiencia, calidad y coste»), supervisa la
  auditoría y **publica el informe** al terminar tras aplicar las correcciones.
- Su página indica que las auditorías iniciales «pueden oscilar entre 30 000 y 200 000 dólares»
  y que ayudan a los proyectos a recaudar fondos y patrocinadores para cubrir el coste total o
  repartirlo. No dice que OSTIF lo pague.
- Requisitos publicados: ninguna convocatoria con fecha. El primer paso es **escribir a OSTIF**; piden
  haber hecho antes comprobaciones propias (su guía de buenas prácticas de seguridad en GitHub; este
  paquete lo cubre en parte con [`internal-review.md`](internal-review.md)).
- Encaje con OpenPassword: sin verificar. Su home habla de proyectos de los que depende «infraestructura
  de Internet»; no se ha comprobado que acepten un gestor de contraseñas personal.
- Plazo y fecha de convocatoria: **no hay convocatoria; contacto abierto**.

### 3.2 OTF Security Lab (antes llamado «Red Team Lab»)

- Fuente: <https://www.opentech.fund/labs/security-lab/>. La URL `…/labs/red-team-lab/` carga la portada
  de OTF; la página con el servicio es **Security Lab**. Si el nombre «Red Team Lab» debe seguir
  usándose en candidaturas, hay que confirmarlo con OTF.
- Qué ofrece: financia «auditorías de seguridad de software, ayuda experta con problemas conocidos y
  revisiones de arquitectura y diseño» y los empareja con socios de confianza. Se anuncia como
  auditoría gratuita para el proyecto. Los resultados se publican «como código abierto».
- Socios listados (algunos): 0xche, **7ASecurity**, Assured, Atredis Partners, Convocation Research &
  Design (la lista es más larga).
- **Elegibilidad, y es el punto débil para OpenPassword:** «si tu herramienta contribuye a la libertad
  de Internet en cualquier parte del mundo». El objetivo de OTF son las personas en contextos de
  represión y censura. Un gestor de contraseñas sin red **no es obviamente** una herramienta de libertad
  de Internet; hay que justificar el encaje (p. ej. periodistas y activistas con secretos en un
  dispositivo incautable) o descartar la vía. **Sin verificar** que lo acepten.
- Cómo se solicita: formulario en su web. Fecha límite: **sin convocatoria publicada** en la página
  consultada (parece una solicitud continua; sin verificar).

### 3.3 NLnet (NGI Zero): cambio importante

- **NGI Zero Commons Fund ya cerró**: su decimotercera y última convocatoria cerró el **1 de junio de
  2026** y no se aceptan solicitudes nuevas (<https://nlnet.nl/commonsfund/>; NGI Zero Core también
  tiene su última convocatoria cerrada, <https://nlnet.nl/NGI0/>). La vía que se había planteado con ese
  nombre **ya no existe como fondo abierto**.
- Su sucesor en la web de NLnet es **Restack** (<https://nlnet.nl/restack/>; fondo temático, ver
  <https://nlnet.nl/themes/>):

  | Dato | Valor (según NLnet) |
  |---|---|
  | Importe | Subvenciones de I+D de **5 000 a 50 000 €** la primera vez |
  | Primera convocatoria | Abrió el 3 de septiembre de 2026, **cierra el 3 de noviembre de 2026 a las 12:00 CET** |
  | Siguientes | Convocatorias abiertas «cada dos meses», entre el 3.er trimestre de 2026 y 2030 (fechas concretas: sin verificar) |
  | Apoyo adicional | Además del dinero, ofrecen «escáneres de accesibilidad y **auditorías de seguridad**, empaquetado reproducible…» (<https://nlnet.nl/restack/>) |
  | Actividades elegibles | Incluye «pruebas formales de seguridad, **auditorías de seguridad**, configuración de pruebas e integración continua» (<https://nlnet.nl/restack/eligibility/>) |
  | Dimensión europea | El equipo con personas de países elegibles en Horizon Europe que reciban **al menos el 60 %** de los fondos; hay excepciones para propuestas excepcionales de fuera (misma página) |
  | Licencia | Software y contenido bajo licencias abiertas (GPL-3.0-or-later cumple) (<https://nlnet.nl/propose/>) |
  | IA generativa | Exigen declararla; las propuestas deben ser «hechas por humanos» (<https://nlnet.nl/propose/>) |
  | Idioma | Respuestas en inglés, en texto plano |

- Aviso de calendario: la fecha del 3 de noviembre de 2026 está a **4 días** de la fecha de esta
  consulta. Las convocatorias siguientes se pueden usar con calma.
- Encaje: el proyecto es open source y de infraestructura de usuario («aplicaciones de usuario final»)
  y la dimensión europea parece cumplirse si el titular y el gasto están en la UE (**confirmar**
  la residencia fiscal de quien solicita). Que NLnet pague o encargue **este** tipo de auditoría:
  sin verificar; su descripción de ayuda menciona «auditorías de seguridad» como apoyo, no los
  términos concretos.

### 3.4 Resumen

| Vía | Qué cubre | Fecha límite | Estado |
|---|---|---|---|
| OSTIF | Coordinación y búsqueda de fondos/patrocinio; informe público | Sin convocatoria; contacto abierto | **PENDIENTE**: escribir |
| OTF Security Lab | Auditoría gratuita con socios (p. ej. 7ASecurity) | Sin fecha publicada | **PENDIENTE**: decidir si hay encaje |
| NLnet Restack (sucesor de NGI Zero) | Subvención 5 000–50 000 € y posible apoyo de auditoría | **3-nov-2026 12:00 CET**; luego cada ~2 meses | **PENDIENTE**: decidir y redactar |
| Fondos propios | — | — | **PENDIENTE**: importe |

Si una candidatura prospera, el proveedor puede venir condicionado (OSTIF, OTF y NLnet eligen o
proponen socios). Eso afecta a la tabla de la sección 1; cada vía debe aceptar el criterio
irrenunciable de **permiso para publicar el informe** (OSTIF y OTF ya publican por diseño).

## 4. Próximos pasos

1. Decidir qué vías se intentan y en qué orden (decisión del proyecto).
2. Escribir a OSTIF con [`scope.md`](scope.md) y el SHA.
3. Contactar con 3–4 proveedores de la sección 1 con la plantilla de
   [`budget-timeline.md`](budget-timeline.md); pedir disponibilidad, equipo con experiencia en
   Rust/Android/criptografía y la política de publicación.
4. Rellenar esta ficha con las respuestas y sustituir «sin verificar» por la fuente.
