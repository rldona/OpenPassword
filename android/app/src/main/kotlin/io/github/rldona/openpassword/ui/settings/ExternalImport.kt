package io.github.rldona.openpassword.ui.settings

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import io.github.rldona.openpassword.core.ImportResult
import io.github.rldona.openpassword.core.OpException
import io.github.rldona.openpassword.core.importNeedsPassword
import io.github.rldona.openpassword.core.parseImport
import io.github.rldona.openpassword.session.VaultSession
import io.github.rldona.openpassword.ui.PasswordField
import io.github.rldona.openpassword.ui.displayNameOf
import io.github.rldona.openpassword.ui.readBackupFile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** A picked export file, parsed and waiting for the user to confirm. */
class PendingImport(val uri: Uri, val result: ImportResult)

/** An encrypted file (KeePass) waiting for its password. Wipe [bytes] when done. */
class LockedExport(val uri: Uri, val bytes: ByteArray)

private fun now() = (System.currentTimeMillis() / 1000).toULong()

/**
 * Reads a picked file. Plaintext exports are parsed right away and their bytes wiped;
 * encrypted ones (KeePass) are returned as [LockedExport] so the app can ask for the password.
 */
suspend fun readExternalExport(context: Context, uri: Uri): Result<Any> = runCatching {
    val bytes = readBackupFile(context, uri)
    if (importNeedsPassword(bytes)) return@runCatching LockedExport(uri, bytes)
    try {
        withContext(Dispatchers.Default) { PendingImport(uri, parseImport(bytes, null, null, now())) }
    } finally {
        bytes.fill(0)
    }
}

/** Decrypts a KeePass database. On a wrong password the bytes are kept so the user can retry. */
suspend fun unlockExternalExport(locked: LockedExport, password: String, keyFile: ByteArray?): Result<PendingImport> = runCatching {
    withContext(Dispatchers.Default) { PendingImport(locked.uri, parseImport(locked.bytes, password, keyFile, now())) }
}.onSuccess { locked.bytes.fill(0) }

fun importErrorMessage(e: Throwable): String = when {
    e is OpException.WrongCredentials ->
        "Contraseña o archivo de clave incorrectos. Si tu base de KeePass usa un archivo de clave, añádelo."
    e is OpException.InvalidInput && "KeePass version" in e.reason ->
        "Esta versión de KeePass no está admitida. Guarda la base como KDBX 4 en KeePass o KeePassXC."
    e is OpException.InvalidInput && "KeePass cipher" in e.reason ->
        "Esta base de KeePass usa Twofish. Cámbiala a AES-256 o ChaCha20 en la configuración de la base."
    e is OpException.InvalidInput && "too costly" in e.reason ->
        "La protección de esta base de KeePass es demasiado costosa para un teléfono. Bájala en la configuración de la base."
    e is OpException.InvalidInput && "key file is damaged" in e.reason -> "El archivo de clave está dañado o no es de KeePass."
    e is OpException.InvalidInput && "KeePass" in e.reason -> "Esta base de KeePass usa una opción que OpenPassword aún no admite."
    e is OpException.Corrupted -> "El fichero está dañado o incompleto."
    e is OpException.InvalidInput && "encrypted Bitwarden" in e.reason ->
        "Es una exportación cifrada de Bitwarden. Vuelve a exportar eligiendo el formato «.json» sin cifrar."
    e is OpException.InvalidInput && ("no password column" in e.reason || "no items" in e.reason) ->
        "No reconozco este fichero. Usa el CSV de Chrome, Google, Firefox, Bitwarden o 1Password, el JSON sin cifrar de Bitwarden o el .1pux de 1Password."
    e is OpException.InvalidInput && "unclosed quote" in e.reason -> "El CSV está incompleto o dañado."
    e is OpException.InvalidInput && ("ZIP" in e.reason || "export.data" in e.reason || "no accounts" in e.reason) ->
        "Este ZIP no es una exportación .1pux de 1Password o está dañado."
    e is OpException.InvalidInput && "too large" in e.reason -> "El fichero es demasiado grande para importarlo."
    e is OpException.InvalidInput && "UTF-8" in e.reason -> "El fichero no es de texto. Elige la exportación en CSV o JSON."
    else -> "No se pudo leer ese fichero."
}

private fun formatName(format: String) = when (format) {
    "bitwarden-json" -> "Bitwarden (JSON)"
    "1password-1pux" -> "1Password (.1pux)"
    "keepass-kdbx" -> "KeePass (.kdbx)"
    else -> "CSV"
}

/** Confirms, imports, and then offers to delete the plaintext export. */
@Composable
fun ExternalImportDialogs(
    pending: PendingImport,
    session: VaultSession,
    context: Context,
    onDone: (message: String) -> Unit,
) {
    var busy by remember { mutableStateOf(false) }
    var imported by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    val result = pending.result

    val summary = imported
    if (summary == null) {
        AlertDialog(
            onDismissRequest = { if (!busy) onDone("") },
            title = { Text("Importar ${result.items.size} elementos") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Formato: ${formatName(result.format)}.")
                    if (result.skipped > 0u) {
                        Text(
                            (if (result.skipped == 1u) "1 entrada no se importará: está vacía o es" else "${result.skipped} entradas no se importarán: están vacías o son") +
                                " de un tipo que OpenPassword aún no admite (identidades, claves SSH…).",
                        )
                    }
                    Text("Se cifrarán con las claves de tu baúl. Lo que ya tengas no se duplica.", style = MaterialTheme.typography.bodySmall)
                }
            },
            confirmButton = {
                TextButton(enabled = !busy && result.items.isNotEmpty(), onClick = {
                    busy = true
                    scope.launch {
                        val message = try {
                            val s = session.importExternal(result.items)
                            when {
                                s.added == 0 && s.duplicates == 1 -> "No había nada nuevo: ese elemento ya estaba en tu baúl."
                                s.added == 0 -> "No había nada nuevo: los ${s.duplicates} ya estaban en tu baúl."
                                else -> buildString {
                                    append(if (s.added == 1) "Importado 1 elemento." else "Importados ${s.added} elementos.")
                                    if (s.duplicates > 0) append(if (s.duplicates == 1) " 1 ya estaba en tu baúl." else " ${s.duplicates} ya estaban en tu baúl.")
                                }
                            }
                        } catch (e: OpException) {
                            "No se pudo importar: el baúl está bloqueado."
                        }
                        // A .kdbx is the user's own encrypted database, not a plaintext export: keep it.
                        if (result.format == "keepass-kdbx") onDone(message) else imported = message
                        busy = false
                    }
                }) { Text(if (busy) "Importando…" else "Importar") }
            },
            dismissButton = { TextButton(enabled = !busy, onClick = { onDone("") }) { Text("Cancelar") } },
        )
    } else {
        AlertDialog(
            onDismissRequest = { onDone(summary) },
            title = { Text("Borra el fichero exportado") },
            text = {
                Text("$summary\n\nEse fichero tiene tus contraseñas sin cifrar: cualquiera que lo encuentre puede leerlas. Bórralo ahora.")
            },
            confirmButton = {
                TextButton(onClick = {
                    val deleted = runCatching { DocumentsContract.deleteDocument(context.contentResolver, pending.uri) }.getOrDefault(false)
                    onDone(if (deleted) "$summary Fichero borrado." else "$summary No se pudo borrar el fichero: bórralo tú desde la app Archivos.")
                }) { Text("Borrar el fichero") }
            },
            dismissButton = { TextButton(onClick = { onDone("$summary Recuerda borrar el fichero exportado.") }) { Text("Ahora no") } },
        )
    }
}

/** Asks for the KeePass database password and, if it uses one, its key file. */
@Composable
fun KeePassPasswordDialog(
    locked: LockedExport,
    onUnlocked: (PendingImport) -> Unit,
    onCancel: () -> Unit,
    /** Called before opening the key file picker, so the vault does not lock meanwhile. */
    beforePicker: () -> Unit,
) {
    val context = LocalContext.current
    var password by remember { mutableStateOf("") }
    var keyFile by remember { mutableStateOf<ByteArray?>(null) }
    var keyFileName by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    val keyFileLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            runCatching { readBackupFile(context, uri) }
                .onSuccess { bytes ->
                    keyFile?.fill(0)
                    keyFile = bytes
                    keyFileName = displayNameOf(context, uri) ?: "archivo de clave"
                    error = null
                }
                .onFailure { error = "No se pudo leer ese archivo de clave." }
        }
    }

    fun close(then: () -> Unit) {
        keyFile?.fill(0)
        then()
    }

    fun submit() {
        if (busy || (password.isEmpty() && keyFile == null)) return
        busy = true
        error = null
        scope.launch {
            unlockExternalExport(locked, password, keyFile)
                .onSuccess { close { onUnlocked(it) } }
                .onFailure { error = importErrorMessage(it); password = "" }
            busy = false
        }
    }

    AlertDialog(
        onDismissRequest = { if (!busy) close(onCancel) },
        title = { Text("Base de datos de KeePass") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Escribe la contraseña maestra de esa base de KeePass. Solo se usa para descifrarla aquí; no se guarda.")
                PasswordField(
                    value = password,
                    onValueChange = { password = it; error = null },
                    label = "Contraseña de KeePass",
                    enabled = !busy,
                    isError = error != null,
                    supportingText = error,
                    onDone = ::submit,
                    modifier = Modifier.fillMaxWidth(),
                )
                TextButton(onClick = { beforePicker(); keyFileLauncher.launch(arrayOf("*/*")) }, enabled = !busy) {
                    Text(keyFileName?.let { "Archivo de clave: $it" } ?: "Añadir archivo de clave")
                }
                if (keyFile != null) {
                    Text("Si la base solo usa archivo de clave, deja la contraseña vacía.", style = MaterialTheme.typography.bodySmall)
                }
            }
        },
        confirmButton = {
            TextButton(onClick = ::submit, enabled = !busy && (password.isNotEmpty() || keyFile != null)) {
                Text(if (busy) "Descifrando…" else "Abrir")
            }
        },
        dismissButton = { TextButton(onClick = { close(onCancel) }, enabled = !busy) { Text("Cancelar") } },
    )
}
