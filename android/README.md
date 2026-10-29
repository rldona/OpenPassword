# App Android

Se crea en la Fase 1: Kotlin, Jetpack Compose y Material 3, llamando a `op-core` mediante UniFFI.

Requisitos fijados en la especificación que deben verificarse en CI:

- El manifiesto **no** declara `android.permission.INTERNET`.
- `android:allowBackup="false"` y reglas de extracción de datos vacías.
- `FLAG_SECURE` en todas las actividades.
