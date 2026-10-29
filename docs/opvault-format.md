# Formato de respaldo `.opvault` · v1

Formato abierto para que cualquiera pueda descifrar sus datos sin la app, por ejemplo con `opvault decrypt`. La criptografía está en [crypto-spec.md](crypto-spec.md).

## Estructura

```
┌──────────────────────────────┐
│ magic         8 bytes        │  "OPVAULT" 0x01
│ header_len    u32 LE         │  ≤ 65 536
│ header        header_len     │  JSON UTF-8, en claro pero autenticado
├──────────────────────────────┤
│ body          resto          │  STREAM-BE32 sobre XChaCha20-Poly1305
└──────────────────────────────┘
```

El último byte de `magic` es la versión mayor del formato.

## Cabecera

```json
{
  "format_version": 1,
  "created_at": 1793257200,
  "vault": {
    "vault_id": "9f2c…(16 bytes hex)",
    "kdf": { "alg": "argon2id", "m_kib": 262144, "t": 3, "p": 4 },
    "salt": "…(32 bytes hex)",
    "secret_key_id": "…(4 bytes hex)",
    "wrapped_vault_key": "…(72 bytes hex)"
  },
  "stream_nonce": "…(19 bytes hex)",
  "wrapped_file_key": "…(72 bytes hex)"
}
```

La cabecera no contiene datos del usuario: ni número de elementos, ni títulos, ni nombre del baúl. Solo lo necesario para derivar claves. `created_at` es un instante Unix en segundos.

## Cuerpo

1. `FK` se obtiene abriendo `wrapped_file_key` con la VK y AAD `aad("op/wrap/v1", "file_key", vault_id, stream_nonce)`.
2. El texto en claro se parte en bloques de 65 536 bytes; el último puede ser más corto o vacío.
3. Cada bloque se cifra con STREAM-BE32: nonce = `stream_nonce (19) ‖ contador u32 BE ‖ marca_final (1 byte)`.
4. AAD de cada bloque: `SHA-256(magic ‖ header_len ‖ header)`. Modificar un solo byte de la cabecera invalida el cuerpo.
5. Cada bloque cifrado ocupa 65 552 bytes salvo el último. La marca de final detecta truncamientos, incluso en el límite exacto de un bloque.

El texto en claro del cuerpo es JSON:

```json
{ "items": [ { "id": "…", "revision": 3, "wrapped_item_key": "…", "overview": "…", "details": "…" } ] }
```

Los elementos siguen cifrados individualmente dentro del cuerpo (sección 7 de la especificación). Así el cuerpo oculta el número de elementos y sus revisiones, y un elemento se puede importar sin recifrarlo.

## Procedimiento de apertura

1. Comprobar `magic`, que `header_len ≤ 65 536` y que `format_version = 1`.
2. Rechazar parámetros de KDF por encima del máximo aceptado.
3. Comparar `secret_key_id` con el de la SK introducida y avisar si no coincide.
4. Derivar la KEK y abrir la VK. Si falla: contraseña o clave secreta incorrectas.
5. Abrir la FK y descifrar el cuerpo.

## Compatibilidad

- Un lector v1 DEBE rechazar `magic` con otra versión mayor.
- Se PUEDEN añadir campos nuevos a la cabecera; un lector v1 los ignora, pero siguen autenticados.
