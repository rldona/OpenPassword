package io.github.rldona.openpassword.ui.settings

import android.content.Context
import android.content.res.Resources
import android.net.Uri
import android.provider.DocumentsContract
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
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
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.github.rldona.openpassword.R
import io.github.rldona.openpassword.core.ImportResult
import io.github.rldona.openpassword.core.InternalException
import io.github.rldona.openpassword.core.OpException
import io.github.rldona.openpassword.core.importNeedsPassword
import io.github.rldona.openpassword.core.parseImport
import io.github.rldona.openpassword.session.internalMessage
import io.github.rldona.openpassword.session.VaultSession
import io.github.rldona.openpassword.session.checkImportKdfFits
import io.github.rldona.openpassword.session.deviceTotalMemory
import io.github.rldona.openpassword.ui.PasswordField
import io.github.rldona.openpassword.ui.displayNameOf
import io.github.rldona.openpassword.ui.readBackupFile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import io.github.rldona.openpassword.ui.ProtectedAlertDialog

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
    if (importNeedsPassword(bytes)) {
        // Before asking for the password: a KeePass database can ask for more RAM than the device
        // has, and deriving would be killed by the system instead of showing a clear error.
        checkImportKdfFits(bytes, deviceTotalMemory(context))
        return@runCatching LockedExport(uri, bytes)
    }
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

fun importErrorMessage(e: Throwable, res: Resources): String = when {
    e is OpException.WrongCredentials -> res.getString(R.string.import_error_wrong_credentials)
    e is OpException.InvalidInput && "KeePass version" in e.reason -> res.getString(R.string.import_error_keepass_version)
    e is OpException.InvalidInput && "KeePass cipher" in e.reason -> res.getString(R.string.import_error_keepass_cipher)
    e is OpException.InvalidInput && "too costly" in e.reason -> res.getString(R.string.import_error_too_costly)
    e is OpException.InvalidInput && "key file is damaged" in e.reason -> res.getString(R.string.import_error_key_file)
    e is OpException.InvalidInput && "KeePass" in e.reason -> res.getString(R.string.import_error_keepass_option)
    e is OpException.Corrupted -> res.getString(R.string.import_error_corrupted)
    e is OpException.InvalidInput && "encrypted Bitwarden" in e.reason -> res.getString(R.string.import_error_bitwarden_encrypted)
    e is OpException.InvalidInput && ("no password column" in e.reason || "no items" in e.reason) ->
        res.getString(R.string.import_error_unrecognized)
    e is OpException.InvalidInput && "unclosed quote" in e.reason -> res.getString(R.string.import_error_csv)
    e is OpException.InvalidInput && ("ZIP" in e.reason || "export.data" in e.reason || "no accounts" in e.reason) ->
        res.getString(R.string.import_error_zip)
    e is OpException.InvalidInput && "too large" in e.reason -> res.getString(R.string.import_error_too_large)
    e is OpException.InvalidInput && "UTF-8" in e.reason -> res.getString(R.string.import_error_not_text)
    e is OpException.KdfTooExpensive -> res.getString(R.string.import_error_kdf, (e.mKib / 1024u).toLong())
    else -> res.getString(R.string.import_error_generic)
}

private fun formatName(format: String, res: Resources) = when (format) {
    "bitwarden-json" -> res.getString(R.string.import_format_bitwarden_json)
    "1password-1pux" -> res.getString(R.string.import_format_1password_1pux)
    "keepass-kdbx" -> res.getString(R.string.import_format_keepass_kdbx)
    else -> res.getString(R.string.import_format_csv)
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
    val res = LocalContext.current.resources
    val result = pending.result

    val summary = imported
    if (summary == null) {
        ProtectedAlertDialog(
            onDismissRequest = { if (!busy) onDone("") },
            title = { Text(pluralStringResource(R.plurals.import_title, result.items.size, result.items.size)) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(stringResource(R.string.import_format, formatName(result.format, res)))
                    if (result.skipped > 0u) {
                        Text(pluralStringResource(R.plurals.import_skipped, result.skipped.toInt(), result.skipped.toInt()))
                    }
                    Text(stringResource(R.string.import_will_encrypt), style = MaterialTheme.typography.bodySmall)
                }
            },
            confirmButton = {
                TextButton(enabled = !busy && result.items.isNotEmpty(), onClick = {
                    busy = true
                    scope.launch {
                        val message = try {
                            val s = session.importExternal(result.items)
                            when {
                                s.added == 0 && s.duplicates == 1 -> res.getString(R.string.import_nothing_new_one)
                                s.added == 0 -> res.getQuantityString(R.plurals.import_nothing_new_many, s.duplicates, s.duplicates)
                                else -> buildString {
                                    append(res.getQuantityString(R.plurals.import_added, s.added, s.added))
                                    if (s.duplicates > 0) {
                                        append(" ")
                                        append(res.getQuantityString(R.plurals.import_already_there, s.duplicates, s.duplicates))
                                    }
                                }
                            }
                        } catch (e: OpException) {
                            res.getString(R.string.import_failed_locked)
                        } catch (_: InternalException) {
                            internalMessage(context.resources)
                        }
                        // A .kdbx is the user's own encrypted database, not a plaintext export: keep it.
                        if (result.format == "keepass-kdbx") onDone(message) else imported = message
                        busy = false
                    }
                }) { Text(if (busy) stringResource(R.string.import_importing) else stringResource(R.string.import_action)) }
            },
            dismissButton = { TextButton(enabled = !busy, onClick = { onDone("") }) { Text(stringResource(R.string.action_cancel)) } },
        )
    } else {
        ProtectedAlertDialog(
            onDismissRequest = { onDone(summary) },
            title = { Text(stringResource(R.string.import_delete_title)) },
            text = {
                Text(stringResource(R.string.import_delete_body, summary))
            },
            confirmButton = {
                TextButton(onClick = {
                    val deleted = runCatching { DocumentsContract.deleteDocument(context.contentResolver, pending.uri) }.getOrDefault(false)
                    onDone(if (deleted) res.getString(R.string.import_deleted, summary) else res.getString(R.string.import_delete_failed, summary))
                }) { Text(stringResource(R.string.import_delete_action)) }
            },
            dismissButton = { TextButton(onClick = { onDone(res.getString(R.string.import_delete_reminder, summary)) }) { Text(stringResource(R.string.import_not_now)) } },
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
    val res = context.resources
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
                    keyFileName = displayNameOf(context, uri) ?: res.getString(R.string.import_key_file_default)
                    error = null
                }
                .onFailure { error = res.getString(R.string.import_key_file_read_failed) }
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
                .onFailure { error = importErrorMessage(it, res); password = "" }
            busy = false
        }
    }

    ProtectedAlertDialog(
        onDismissRequest = { if (!busy) close(onCancel) },
        title = { Text(stringResource(R.string.import_keepass_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.import_keepass_intro))
                PasswordField(
                    value = password,
                    onValueChange = { password = it; error = null },
                    label = stringResource(R.string.import_keepass_password),
                    enabled = !busy,
                    isError = error != null,
                    supportingText = error,
                    onDone = ::submit,
                    modifier = Modifier.fillMaxWidth(),
                )
                TextButton(onClick = { beforePicker(); keyFileLauncher.launch(arrayOf("*/*")) }, enabled = !busy) {
                    Text(keyFileName?.let { stringResource(R.string.import_key_file_chosen, it) } ?: stringResource(R.string.import_key_file_add))
                }
                if (keyFile != null) {
                    Text(stringResource(R.string.import_key_file_only), style = MaterialTheme.typography.bodySmall)
                }
            }
        },
        confirmButton = {
            TextButton(onClick = ::submit, enabled = !busy && (password.isNotEmpty() || keyFile != null)) {
                Text(if (busy) stringResource(R.string.import_decrypting) else stringResource(R.string.import_open))
            }
        },
        dismissButton = { TextButton(onClick = { close(onCancel) }, enabled = !busy) { Text(stringResource(R.string.action_cancel)) } },
    )
}
