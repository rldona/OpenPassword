# Seguridad

OpenPassword guarda contraseñas, así que cualquier fallo de seguridad se trata antes que cualquier otra cosa.

> El proyecto aún no ha pasado una auditoría externa (Fase 3 de la [propuesta](docs/propuesta.html)). No guardes datos reales todavía.

## Cómo avisar de una vulnerabilidad

**No abras un issue público.** Usa el aviso privado de GitHub: pestaña *Security* → *Report a vulnerability* en [rldona/OpenPassword](https://github.com/rldona/OpenPassword/security/advisories/new).

Incluye, si puedes:

- qué componente falla (`op-core`, `op-ffi`, la app Android, la CLI o el formato `.opvault`) y en qué versión o commit;
- los pasos o el fichero para reproducirlo;
- qué puede conseguir un atacante y bajo qué supuestos (ver el [modelo de amenazas](docs/threat-model.md)).

## Qué esperar

| Paso | Plazo orientativo |
|---|---|
| Acuse de recibo | 3 días |
| Primera valoración | 10 días |
| Corrección publicada | 90 días como máximo desde el aviso; antes si es grave |

Publicaremos el aviso (GitHub Security Advisory, con CVE si procede) cuando haya versión corregida, y te citaremos salvo que prefieras no aparecer. No hay programa de recompensas por ahora.

## Dentro del alcance

- La criptografía y su implementación: [especificación](docs/crypto-spec.md), derivación de claves, cifrado por elemento, formato de respaldo.
- Lectura de datos no confiables: copias `.opvault`, importadores (KeePass, 1Password, Bitwarden, CSV), enlaces `otpauth://` y códigos QR.
- La app Android: autorrelleno (coincidencia de dominios y paquetes), bloqueo automático, desbloqueo biométrico, portapapeles, permisos.
- Builds reproducibles y firma del APK.

## Fuera del alcance

Lo que el [modelo de amenazas](docs/threat-model.md) deja fuera: un teléfono con root o malware con privilegios, un *keylogger*, o alguien que conoce tu contraseña maestra y tiene tu clave secreta.

## Versiones con soporte

Solo la última versión publicada y la rama `main`.
