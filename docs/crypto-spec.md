# Especificación criptográfica de OpenPassword · v1

Estado: borrador para revisión (Fase 0). Este documento es normativo: si el código y la especificación no coinciden, el error está en el código o hay que versionar la especificación.

Las palabras DEBE, NO DEBE y PUEDE se usan en el sentido de RFC 2119.

## 1. Objetivos

1. Conocimiento cero: solo quien conoce la contraseña maestra **y** tiene la clave secreta puede descifrar un baúl o un respaldo.
2. Un fichero de respaldo robado DEBE resistir fuerza bruta aunque la contraseña maestra sea débil.
3. Todo el contenido de un elemento, incluidos los metadatos (tipo, título, URLs, etiquetas, fechas), DEBE ir cifrado.
4. Ningún bloque cifrado DEBE poder moverse a otro contexto (otro elemento, otra revisión, otro baúl, otro campo) sin que falle la autenticación.
5. Solo primitivas estándar con implementaciones auditadas.

## 2. Primitivas

| Uso | Primitiva | Implementación |
|---|---|---|
| Derivación desde contraseña | Argon2id v1.3 (RFC 9106) | crate `argon2` (RustCrypto) |
| Derivación de claves | HKDF-SHA256 (RFC 5869) | crate `hkdf` + `sha2` |
| Cifrado autenticado | XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha) | crate `chacha20poly1305` |
| Cifrado por bloques del respaldo | STREAM, variante BE32 (Hoang, Reyhanitabar, Rogaway, Vizár, 2015) sobre XChaCha20-Poly1305 | `chacha20poly1305::aead::stream` |
| Resumen | SHA-256 | crate `sha2` |
| Aleatoriedad | CSPRNG del sistema operativo | crate `getrandom` |

No se usa compresión antes de cifrar: evita filtraciones por longitud (tipo CRIME) y una dependencia en C.

## 3. Claves

Todas las claves simétricas tienen 256 bits.

| Nombre | Qué es | Dónde vive |
|---|---|---|
| **MP** | Contraseña maestra, normalizada Unicode NFKD | Solo en la cabeza del usuario |
| **SK** | Clave secreta, 128 bits aleatorios | Dispositivo (protegida por Keystore) y kit de emergencia en papel |
| **KEK** | Clave de cifrado de claves, derivada de MP y SK | Solo en memoria, durante el desbloqueo |
| **VK** | Clave del baúl, aleatoria | Envuelta por la KEK (y opcionalmente por una clave del Keystore) |
| **IK** | Clave de elemento, aleatoria, una por elemento | Envuelta por la VK |
| **FK** | Clave de fichero, aleatoria, una por respaldo | Envuelta por la VK dentro del respaldo |

## 4. Clave secreta (SK)

- 16 bytes del CSPRNG.
- Representación para humanos: prefijo de versión `OP1` y 30 caracteres en Base32 de Crockford (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`), en grupos de 6:

  ```
  OP1-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX
  ```

  - Caracteres 1–26: los 128 bits de la SK en big-endian, seguidos de 2 bits a cero.
  - Caracteres 27–30: suma de control de 20 bits = los 20 primeros bits de `SHA-256("op/sk-check/v1" ‖ SK)`.
- Al leerla, la implementación DEBE ignorar guiones y espacios, aceptar minúsculas y mapear `O→0` e `I, L→1`. DEBE rechazar una suma de control incorrecta o bits de relleno distintos de cero.
- Identificador público: `sk_id = HKDF-SHA256(ikm = SK, salt = vacío, info = "op/sk-id/v1")[0..4]`. Permite avisar de «clave secreta equivocada» antes de ejecutar Argon2id. No revela bits de la SK.

## 5. Derivación de la KEK

Entradas: MP, SK, `salt` (32 bytes aleatorios por baúl) y parámetros de Argon2id.

```
mp_bytes = UTF-8(NFKD(MP))
pw_key   = Argon2id(password = mp_bytes, salt = salt, m, t, p, len = 32)
sk_key   = HKDF-SHA256(ikm = SK, salt = salt, info = "op/sk/v1", len = 32)
KEK      = HKDF-SHA256(ikm = pw_key ‖ sk_key, salt = salt, info = "op/kek/v1", len = 32)
```

La contraseña no se recorta ni se modifica salvo la normalización NFKD, para que la misma contraseña escrita en teclados distintos produzca los mismos bytes.

### Parámetros de Argon2id

| Perfil | m (KiB) | t | p | Uso |
|---|---|---|---|---|
| Recomendado | 262 144 (256 MiB) | 3 | 4 | Por defecto al crear un baúl |
| Mínimo | 65 536 (64 MiB) | 2 | 1 | Gama baja; no se PUEDE crear por debajo |
| Máximo aceptado al leer | 2 097 152 (2 GiB) | 16 | 16 | Rechazar cabeceras más costosas (evita denegación de servicio) |

Al leer un baúl o respaldo ya existente se aceptan parámetros por debajo del mínimo (pueden venir de un dispositivo antiguo), pero la app DEBE proponer recifrar con parámetros actuales.

## 6. Cifrado autenticado

### 6.1 Formato de un bloque sellado

```
sealed = nonce (24 bytes, aleatorio) ‖ ciphertext ‖ tag (16 bytes)
```

Cada operación de sellado DEBE usar un nonce nuevo del CSPRNG. Con 192 bits el riesgo de colisión es despreciable.

### 6.2 Datos asociados (AAD)

Todo sellado lleva AAD que fija su contexto. Codificación:

```
aad(dominio, partes...) = UTF-8(dominio) ‖ 0x00 ‖ para cada parte: u32_le(len(parte)) ‖ parte
```

| Qué se sella | Clave | Dominio | Partes |
|---|---|---|---|
| VK | KEK | `op/wrap/v1` | `"vault_key"`, `vault_id` |
| IK | VK | `op/wrap/v1` | `"item_key"`, `vault_id`, `item_id` |
| Resumen del elemento | IK | `op/item/v1` | `"overview"`, `vault_id`, `item_id`, `u64_le(revision)` |
| Detalles del elemento | IK | `op/item/v1` | `"details"`, `vault_id`, `item_id`, `u64_le(revision)` |
| FK del respaldo | VK | `op/wrap/v1` | `"file_key"`, `vault_id`, `stream_nonce` |

Consecuencias: no se puede intercambiar el resumen de un elemento con el de otro, ni mezclar el resumen de la revisión 3 con los detalles de la 2, ni reutilizar una IK envuelta en otro elemento o baúl.

### 6.3 Relleno

Antes de sellar, el JSON de un resumen o de unos detalles se rellena para ocultar su longitud exacta:

```
padded = u32_le(len(json)) ‖ json ‖ 0x00…  (hasta un múltiplo de 64 bytes)
```

Al abrir, el relleno DEBE ser todo ceros y la longitud total múltiplo de 64.

## 7. Elementos

Cada elemento se guarda como:

| Campo | Contenido |
|---|---|
| `id` | 16 bytes aleatorios |
| `revision` | u64, empieza en 1 y sube en cada edición |
| `wrapped_item_key` | IK sellada con la VK |
| `overview` | Sellado con la IK: tipo, título, subtítulo, URLs, etiquetas, favorito, fechas. Se descifra al desbloquear para la lista y la búsqueda |
| `details` | Sellado con la IK: campos y notas. Se descifra solo al abrir el elemento |

Una edición mantiene la IK, incrementa `revision` y vuelve a sellar `overview` y `details` con nonces nuevos.

## 8. Cambio de contraseña o de clave secreta

Se genera un `salt` nuevo, se deriva la nueva KEK y se vuelve a envolver la VK. Los elementos no se tocan. Los respaldos antiguos siguen abriéndose con las credenciales antiguas: la app DEBE avisarlo.

## 9. Desbloqueo biométrico (Android)

1. Se crea en Android Keystore una clave AES-256-GCM con `setUserAuthenticationRequired(true)`, autenticación `BIOMETRIC_STRONG`, `setInvalidatedByBiometricEnrollment(true)`, `setUnlockedDeviceRequired(true)` y StrongBox cuando exista.
2. La VK se cifra con esa clave tras un desbloqueo con contraseña y se guarda junto al baúl.
3. Al desbloquear con huella, el Keystore descifra la VK.
4. La app DEBE pedir la contraseña maestra cada 14 días y tras reiniciar el dispositivo. Para detectar el reinicio, guarda `Settings.Global.BOOT_COUNT` en cada desbloqueo con contraseña.
5. Fichero `vault-key.biometric`: `versión (1) ‖ iv (12) ‖ VK cifrada (32) ‖ tag (16)`. Si Android invalida la clave (`KeyPermanentlyInvalidatedException`), la app borra el fichero y la clave y vuelve a la contraseña.

Esta parte vive en la capa Android, no en `op-core`.

## 10. Higiene de memoria

- Los tipos de clave de `op-core` borran su contenido al liberarse (`zeroize`) y no imprimen su valor en `Debug`.
- Los textos en claro descifrados se devuelven en tipos que se borran al liberarse.
- Límite conocido: la JVM y Compose manejan `String` inmutables que no se pueden borrar. La capa Android DEBE minimizar su vida útil.

## 11. Versionado

- Los dominios llevan sufijo de versión (`/v1`). Un cambio incompatible crea `/v2` y una nueva versión de formato.
- Los vectores de prueba de `core/tests/vectors/op-v1.json` fijan esta versión. Si un cambio de código los rompe, el cambio es incompatible.

## 12. Fuera de alcance de v1

Compartir elementos entre usuarios, sincronización, passkeys y adjuntos. El diseño de IK por elemento deja preparado compartir.
