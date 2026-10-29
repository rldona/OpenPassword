package io.github.rldona.openpassword.ui.settings

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
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
import androidx.compose.ui.unit.dp
import io.github.rldona.openpassword.core.ImportResult
import io.github.rldona.openpassword.core.OpException
import io.github.rldona.openpassword.core.parseImport
import io.github.rldona.openpassword.session.VaultSession
import io.github.rldona.openpassword.ui.readBackupFile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** A picked export file, parsed and waiting for the user to confirm. */
class PendingImport(val uri: Uri, val result: ImportResult)

/** Reads and parses an export. The plaintext bytes are wiped as soon as they are parsed. */
suspend fun readExternalExport(context: Context, uri: Uri): Result<PendingImport> = runCatching {
    val bytes = readBackupFile(context, uri)
    try {
        withContext(Dispatchers.Default) { PendingImport(uri, parseImport(bytes, (System.currentTimeMillis() / 1000).toULong())) }
    } finally {
        bytes.fill(0)
    }
}

fun importErrorMessage(e: Throwable): String = when {
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
                        imported = try {
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
