# Seguridad

OpenPassword guarda mis contraseñas, así que un fallo de seguridad se trata antes que cualquier otra cosa.

> **Proyecto personal, sin auditoría externa.** No hay usuarios a los que dar soporte, ni programa de
> recompensas, ni plazos de divulgación pactados. Los riesgos que conozco y he decidido aceptar están
> en el [modelo de amenazas](docs/threat-model.md).

## Si encuentras un fallo

Abre un issue en el repositorio con:

- qué componente falla (`op-core`, `op-ffi`, la app Android, la CLI o el formato `.opvault`) y en qué
  commit o versión;
- los pasos o el fichero para reproducirlo;
- qué puede conseguir un atacante y bajo qué supuestos (ver el [modelo de amenazas](docs/threat-model.md)).

No hay nada que proteger con divulgación privada: el repositorio no tiene usuarios externos.

## Dentro del alcance

- La criptografía y su implementación: [especificación](docs/crypto-spec.md), derivación de claves,
  cifrado por elemento y formato de copia.
- Lectura de datos no confiables: copias `.opvault`, importadores (KeePass, 1Password, Bitwarden, CSV),
  enlaces `otpauth://` y códigos QR.
- La app Android: autorrelleno (dominios, sufijos públicos y paquetes), bloqueo automático, biometría,
  portapapeles, permisos y copias.

## Fuera del alcance

Lo que el [modelo de amenazas](docs/threat-model.md) deja fuera: un teléfono con root o malware con
privilegios, un *keylogger*, o alguien que conoce la contraseña maestra y tiene la clave secreta.

## Fallos conocidos y aceptados

Están en el [modelo de amenazas](docs/threat-model.md) y en la revisión interna archivada
([`docs/archive/audit/internal-review.md`](docs/archive/audit/internal-review.md)). El más relevante
para el uso diario: en Android, la contraseña copiada al portapapeles no se borra a los 30 s si la app
está en segundo plano; se borra al volver a la app o al apagar la pantalla.
