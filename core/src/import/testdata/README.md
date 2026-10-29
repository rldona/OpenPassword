# Ficheros de prueba de los importadores

Todos los datos son inventados. Las contraseñas de este directorio no protegen nada real.

## `keepassxc-3.1.kdbx`

Base de datos real creada por **KeePassXC 2.8.0** a partir de `fixture.xml`:

```sh
keepassxc-cli import -p -t 100 fixture.xml keepassxc-3.1.kdbx   # contraseña: prueba-kdbx
```

KDBX 3.1, AES-256, AES-KDF (~5,8 millones de rondas) y valores protegidos con Salsa20. Incluye una
entrada con historial (solo debe importarse la contraseña actual), otra en la papelera (no debe
importarse), un campo protegido personalizado, un TOTP de KeePassXC, una nota, entidades XML en
valores sin proteger y una contraseña con espacios al principio y al final.

Si cambia `fixture.xml`, regenera el `.kdbx` con el comando de arriba y revisa los tests de `kdbx.rs`.

## Pendiente

`keepassxc-cli` solo crea KDBX 3.1. Falta un KDBX 4 real (ChaCha20 + Argon2id) creado desde la
interfaz de KeePassXC (*Base de datos → Configuración → Seguridad*) para cubrir esa ruta con un
fichero de referencia. Hasta entonces, el código de KDBX 4 está escrito según la especificación
pero no se ha probado contra un fichero real.
