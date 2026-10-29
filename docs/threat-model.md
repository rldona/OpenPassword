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

| # | Atacante | Capacidad | Defensa | Estado |
|---|---|---|---|---|
| A1 | Ladrón con el móvil bloqueado | Acceso físico, extracción del almacenamiento | Cifrado de Android; baúl cifrado con claves que no están en disco en claro | Protegido |
| A2 | Ladrón con el móvil desbloqueado | Abre la app | Contraseña maestra o biometría ligada a hardware; espera exponencial entre intentos | Protegido |
| A3 | Quien obtiene un `.opvault` | Fuerza bruta offline ilimitada | Argon2id + SK de 128 bits: sin la SK, probar contraseñas no sirve | Protegido |
| A4 | Proveedor de nube | Ve el fichero y su historial | Solo ve un blob autenticado; la cabecera no tiene datos del usuario | Protegido |
| A5 | Manipulación del respaldo o de la base de datos | Modifica, trunca, reordena o intercambia bloques | AEAD con AAD de contexto; STREAM con marca de final; cabecera autenticada | Protegido |
| A6 | Reversión (rollback) | Sustituye un elemento por una versión antigua completa | Detectable solo con sincronización; aceptado en v1 | Aceptado |
| A7 | App maliciosa sin privilegios | Superposiciones, portapapeles, capturas | `FLAG_SECURE`, `filterTouchesWhenObscured`, portapapeles sensible con borrado | Mitigado |
| A8 | Mirón | Ve la pantalla | Campos ocultos y revelado por campo | Mitigado |
| A9 | Cadena de suministro | Dependencia o build manipulada | Pocas dependencias, `Cargo.lock` versionado, `cargo audit`, builds reproducibles | Mitigado |
| A12 | Web o app de *phishing* | Pide al autorrelleno las credenciales de otro sitio | Coincidencia estricta: host guardado o subdominio en webs; nombre de paquete exacto (verificado por Android) en apps; aviso al elegir a mano | Mitigado |
| A13 | Baúl olvidado abierto | El autorrelleno ofrece logins mientras la app está en segundo plano | Bloqueo a los 30 s de salir de la app y al apagar la pantalla, para todo el proceso | Protegido |
| A14 | Otro servicio de autorrelleno (p. ej. el de Google) | Lee los campos de la app u ofrece guardarlos en su nube | Ventanas excluidas de todo autorrelleno (`IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS`) | Protegido |
| A10 | Malware con root, keylogger | Lee memoria y pulsaciones | Ninguna; aviso si se detecta root | Fuera de alcance |
| A11 | Coacción | Obliga a desbloquear | Ninguna en v1 | Fuera de alcance |

## Riesgos residuales

- **Pérdida total**: sin contraseña maestra ni kit de emergencia no hay recuperación posible.
- **Memoria de la JVM**: los `String` mostrados en pantalla no se pueden borrar a voluntad.
- **Metadatos de tamaño**: el tamaño del respaldo revela aproximadamente cuántos datos hay.
- **Respaldos con credenciales antiguas**: tras cambiar la contraseña, los respaldos viejos se abren con la anterior.
