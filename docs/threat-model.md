# Modelo de amenazas · v1

Qué protege OpenPassword, frente a quién y qué queda fuera. Se revisa antes de cada versión mayor y antes de la auditoría externa.

## Activos

| Activo | Ejemplos | Sensibilidad |
|---|---|---|
| Secretos | Contraseñas, CVV, PINs, frases semilla, claves API | Crítica |
| Metadatos | Qué servicios usas, qué bancos, títulos, URLs | Alta |
| Credenciales de acceso | Contraseña maestra, clave secreta | Crítica |
| Respaldos | Ficheros `.opvault` | Igual que los secretos |

## Supuestos

- El sistema operativo y el hardware no están comprometidos (sin root malicioso ni firmware alterado).
- El CSPRNG del sistema funciona.
- El usuario conserva la contraseña maestra o el kit de emergencia.

## Atacantes y defensas

Todas las defensas de la tabla están implementadas. «Parcial» significa que la defensa funciona pero tiene un límite conocido, que se indica como riesgo residual en la propia fila.

| # | Atacante | Capacidad | Defensa | Estado |
|---|---|---|---|---|
| A1 | Ladrón con el móvil bloqueado | Acceso físico, extracción del almacenamiento | Cifrado de Android; baúl cifrado con claves que no están en disco en claro | Protegido |
| A2 | Ladrón con el móvil desbloqueado | Abre la app | Contraseña maestra o biometría ligada a hardware; espera exponencial entre intentos | Protegido |
| A3 | Quien obtiene un `.opvault` | Fuerza bruta offline ilimitada | Argon2id + SK de 128 bits: sin la SK, probar contraseñas no sirve | Protegido |
| A4 | Proveedor de nube | Ve el fichero y su historial | Solo ve un blob autenticado; la cabecera no tiene datos del usuario | Protegido |
| A5 | Manipulación del respaldo o de la base de datos | Modifica, trunca, reordena o intercambia bloques | AEAD con AAD de contexto; STREAM con marca de final; cabecera autenticada | Protegido |
| A6 | Reversión (rollback) | Sustituye un elemento por una versión antigua completa | Detectable solo con sincronización; aceptado en v1 | Aceptado |
| A7 | App maliciosa sin privilegios | Superposiciones, portapapeles, capturas | `FLAG_SECURE` y portapapeles marcado como sensible (API 33+) con un borrado a los 30 s **que solo actúa con la app en primer plano**; contra superposiciones (*tapjacking*): `filterTouchesWhenObscured` (descarta los toques tapados del todo) y `setHideOverlayWindows` (oculta las superposiciones de otras apps), en las tres actividades y en sus diálogos, y un aviso (una vez por proceso) cuando llega un toque tapado. Riesgo residual **aceptado** por decisión del responsable (30-oct-2026, [ID-INT-14](audit/internal-review.md#id-int-14)): **el borrado del portapapeles NO ocurre si la app ya no tiene el foco, que es el uso normal (copiar y pegar en otra app)**. Es una limitación de Android: `clearPrimaryClip()` no surte efecto desde segundo plano. Confirmado en dispositivo el 30-oct-2026 (SM-S948B, Android 17 / API 37; [DT-04](audit/device-tests.md#dt-04)): el texto sigue en el portapapeles a los 45 s con la app en segundo plano, mientras que con la app enfocada se borra a los 35 s. Mitigaciones: marca de «sensible» (API 33+), borrado a los 30 s con la app en primer plano, borrado al volver a la app y al apagar la pantalla (estos dos últimos, **sin verificar en dispositivo**), y un mensaje honesto en la interfaz; no se ha quitado el botón de copiar. No se probó en API 29, 33 y 36. El mensaje de la app dice «Se borrará en 30 s, o al volver a la app si sales.». `setHideOverlayWindows` exige Android 12 (API 31); en API 28-30 solo queda el filtro, y un toque **parcialmente** tapado se entrega (con aviso). La ocultación de superposiciones está verificada en dispositivo solo en API 37 y `MainActivity` (DT-01); el aviso y API 28-30 (DT-02, DT-03) siguen sin verificar | Parcial |
| A8 | Mirón | Ve la pantalla | Campos ocultos y revelado por campo | Mitigado |
| A9 | Cadena de suministro | Dependencia o build manipulada | Pocas dependencias, `Cargo.lock` versionado, `cargo deny` (avisos, licencias y orígenes), suma SHA-256 de las dependencias de Gradle, Actions fijadas por SHA, SBOM y atestación de procedencia en la release, builds reproducibles | Mitigado |
| A10 | Malware con root, keylogger | Lee memoria y pulsaciones | Solo un aviso: heurísticas locales, sin red (binarios `su`, gestores de root conocidos, `test-keys`, compilación `userdebug`/`eng`). Informa y **nunca bloquea**. Riesgo residual: un root oculto (p. ej. Magisk con ocultación) no se detecta, una ROM personalizada puede dar un falso positivo, y aunque se detecte la app no protege de ese malware | Fuera de alcance |
| A11 | Coacción | Obliga a desbloquear | Ninguna en v1 | Fuera de alcance |
| A12 | Web o app de *phishing* | Pide al autorrelleno las credenciales de otro sitio | Coincidencia estricta: host guardado o subdominio en webs; nombre de paquete exacto (verificado por Android) en apps; aviso al elegir a mano | Mitigado |
| A13 | Baúl olvidado abierto | El autorrelleno ofrece logins mientras la app está en segundo plano | Bloqueo a los 30 s de salir de la app (3 min, una vez, si se sale a un selector del sistema que pidió el usuario) y al apagar la pantalla, para todo el proceso | Protegido |
| A14 | Otro servicio de autorrelleno (p. ej. el de Google) | Lee los campos de la app u ofrece guardarlos en su nube | Ventanas excluidas de todo autorrelleno (`IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS`) | Protegido |
| A15 | Quien encuentra la exportación de otro gestor | Lee las contraseñas en claro del CSV o JSON importado | Tras importar, la app ofrece borrar el fichero; los bytes leídos se borran de memoria al analizarlos | Mitigado |
| A16 | QR malicioso o fotogramas de la cámara | Un QR que no es de TOTP, o que la app guarde imágenes del entorno | Solo se aceptan enlaces `otpauth://totp/` y el secreto se valida en el núcleo; los fotogramas se analizan en memoria, no se guardan y la app no tiene red; la cámara se pide solo al escanear | Mitigado |
| A17 | App que declara el dominio de una web | `ViewStructure.setWebDomain` lo rellena la app de origen y no lo verifica Android: una app puede declarar el dominio de un banco | El `webDomain` solo se acepta si el paquete es un navegador: uno de la lista fija `KnownBrowsers.PACKAGES` (`BrowserCheck.kt:26-39`) o el navegador **por defecto** del usuario (`resolveActivity` de `ACTION_VIEW` `https`, `MATCH_DEFAULT_ONLY`) **y** que atienda `https` y `http` (`:68-73,83-87`). Declarar un `intent-filter` no basta (no exige permiso). Si no, se trata como una app y solo coincide por nombre de paquete. El host se valida como nombre ASCII (`[a-z0-9.-]+`: sin esquema, puerto, ruta ni Unicode; `LoginMatcher.kt:67-76`); los subdominios solo casan con un dominio registrable según la lista de sufijos públicos y, si la lista no carga (incluido un `IOException`), coincidencia exacta de host (`PublicSuffix.kt:21-25`). Riesgo residual: un navegador que el propio usuario elija como predeterminado y sea malicioso es creído; la lista de navegadores y la de sufijos son datos versionados sin proceso de actualización (un navegador nuevo y no predeterminado no se reconoce: se trata como app); un `iframe` de otro origen dentro de un navegador no se verifica (el `webDomain` se toma del primer nodo que lo declara). **Verificado en dispositivo** (30-oct-2026, SM-S948B, API 37, build de depuración): una app que declara `webDomain` sin ser navegador es tratada como app («Para: test.fakebrowser», sin coincidencias web; DT-07), y la lista de sufijos se carga y se aplica (`evil.github.io` no recibe el login de `github.io`; DT-05). **Sin verificar en dispositivo**: Chrome real (DT-06), el navegador predeterminado malicioso como prueba formal (DT-08; solo se observó de pasada que su `webDomain` se creyó), la lista de sufijos con R8 y el `iframe` | Mitigado |
| A18 | App rellenada que dispara el `PendingIntent` de autenticación | El `IntentSender` de `Dataset.setAuthentication` se entrega a la app que se rellena, y el `PendingIntent` es **mutable** (el sistema le añade la estructura): esa app puede añadirle extras con `Intent.fillIn` y, si el destino viajara en ellos, pedir las credenciales de cualquier dominio | El `Intent` lleva solo un token aleatorio de 16 bytes (hex), de un solo uso y con TTL de 5 min, guardado en un `ConcurrentHashMap` del proceso (`AutofillRequestTokens.kt:14-47`); el dominio o paquete y los campos se recuperan del almacén, no del `Intent` (`AutofillAuthActivity.kt:89-98`). La actividad borra los extras antiguos (`Datasets.LEGACY_EXTRAS`) antes de leer nada y **falla cerrada** (token desconocido, usado o caducado: `finish()` sin resultado). Corregido en el mismo bloque que A17 (ID-INT-26). Riesgo residual: quien ya ejecute código en el proceso de OpenPassword (A10, fuera de alcance) lee el almacén; el token, mientras no se use ni caduque, solo vale para la solicitud a la que se ató; el `PendingIntent` sigue siendo mutable (el sistema lo exige) | Mitigado |

## Riesgos residuales

- **Pérdida total**: sin contraseña maestra ni kit de emergencia no hay recuperación posible.
- **Memoria de la JVM**: los `String` mostrados en pantalla no se pueden borrar a voluntad (aceptado).
- **Residuos de secretos en la frontera FFI** (aceptado): `SecretString` (`ffi/src/secret.rs`) y `Zeroizing` borran en Rust los secretos que entran, pero Rust no alcanza los `String` inmutables de la JVM y de Compose, ni el `RustBuffer` de salida de UniFFI, que se libera sin borrar (ni el `String` que Rust entrega para construirlo).
- **Importadores**: los búferes con secretos de los importadores (copia del `.1pux`, campos del CSV, árbol JSON, valores y archivo de clave de KDBX, claves derivadas, parámetros de `otpauth://`) son `Zeroizing` o se borran al salir del ámbito, también por las rutas de error (`core/src/import/mod.rs`, cabecera del módulo). Quedan, y no se pueden borrar desde Rust: lo que dejan las reasignaciones al crecer un `String`/`Vec` y los búferes internos de `serde_json`, las claves de los objetos JSON (nombres de campo), los temporales de pila de `sha2` y lo que ocurre tras cruzar la FFI (ver arriba). Todo ello exige leer la memoria del proceso (A10, fuera de alcance).
- **Metadatos de tamaño**: el tamaño del respaldo revela aproximadamente cuántos datos hay.
- **Respaldos con credenciales antiguas**: tras cambiar la contraseña, los respaldos viejos se abren con la anterior.
