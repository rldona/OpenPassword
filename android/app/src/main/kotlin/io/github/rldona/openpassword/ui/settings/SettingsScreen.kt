package io.github.rldona.openpassword.ui.settings

import android.content.Intent
import android.net.Uri
import android.provider.DocumentsContract
import android.view.autofill.AutofillManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.rldona.openpassword.BuildConfigInfo
import io.github.rldona.openpassword.backup.AutoBackup
import io.github.rldona.openpassword.core.InternalException
import io.github.rldona.openpassword.core.OpException
import io.github.rldona.openpassword.security.EmergencyKit
import io.github.rldona.openpassword.security.strongBiometricsAvailable
import io.github.rldona.openpassword.session.internalMessage
import io.github.rldona.openpassword.session.UnlockResult
import io.github.rldona.openpassword.session.VaultSession
import io.github.rldona.openpassword.session.toUserMessage
import io.github.rldona.openpassword.ui.PasswordField
import io.github.rldona.openpassword.ui.SecretKeyField
import io.github.rldona.openpassword.ui.EMERGENCY_KIT_FILE_NAME
import io.github.rldona.openpassword.ui.readBackupFile
import io.github.rldona.openpassword.ui.writeDocument
import io.github.rldona.openpassword.ui.SectionLabel
import io.github.rldona.openpassword.ui.theme.SecretFont
import io.github.rldona.openpassword.ui.unlock.enableBiometricUnlock
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.DateFormat
import java.time.LocalDate
import java.util.Date
import io.github.rldona.openpassword.ui.ProtectedAlertDialog
import io.github.rldona.openpassword.ui.RootWarning
import io.github.rldona.openpassword.session.message
import io.github.rldona.openpassword.ui.text.backupErrorText
import io.github.rldona.openpassword.ui.text.message
import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import androidx.annotation.StringRes
import androidx.compose.ui.res.stringResource
import io.github.rldona.openpassword.R
import io.github.rldona.openpassword.locale.AppLanguage
import io.github.rldona.openpassword.locale.AppLocales
import androidx.compose.material3.AlertDialog

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(session: VaultSession, autoBackup: AutoBackup, onBack: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }
    var askingPassword by remember { mutableStateOf(false) }
    var shownSecretKey by remember { mutableStateOf<String?>(null) }
    val biometricsAvailable = remember { strongBiometricsAvailable(context) }
    var biometricOn by remember { mutableStateOf(session.isBiometricEnabled()) }
    var biometricBusy by remember { mutableStateOf(false) }
    var importBytes by remember { mutableStateOf<ByteArray?>(null) }
    var pendingExternal by remember { mutableStateOf<PendingImport?>(null) }
    var lockedExternal by remember { mutableStateOf<LockedExport?>(null) }
    val externalLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            readExternalExport(context, uri)
                .onSuccess { read ->
                    when (read) {
                        is LockedExport -> lockedExternal = read
                        is PendingImport -> pendingExternal = read
                    }
                }
                .onFailure { snackbar.showSnackbar(importErrorMessage(it, context.resources)) }
        }
    }
    val backup by autoBackup.status.collectAsStateWithLifecycle()
    var backingUp by remember { mutableStateOf(false) }
    val folderLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { tree ->
        if (tree == null) return@rememberLauncherForActivityResult
        runCatching { autoBackup.setFolder(tree, folderLabel(tree)) }
            .onFailure { scope.launch { snackbar.showSnackbar(context.getString(R.string.settings_folder_error)) } }
    }
    val autofillManager = remember { context.getSystemService(AutofillManager::class.java) }
    var autofillOn by remember { mutableStateOf(autofillManager?.hasEnabledAutofillServices() == true) }
    val activity = remember(context) { context.findActivity() }
    var language by remember { mutableStateOf(AppLocales.current(context)) }
    var showLanguage by remember { mutableStateOf(false) }
    val autofillLauncher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        autofillOn = autofillManager?.hasEnabledAutofillServices() == true
    }

    // Only reachable from the secret key dialog, i.e. after confirming the master password.
    val kitLauncher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/pdf")) { uri ->
        val key = shownSecretKey
        if (uri == null || key == null) return@rememberLauncherForActivityResult
        scope.launch {
            val message = try {
                writeDocument(context, uri, EmergencyKit.pdf(EmergencyKit.Text.from(context.resources), key))
                context.getString(R.string.settings_kit_saved)
            } catch (_: Exception) {
                context.getString(R.string.settings_kit_save_failed)
            }
            shownSecretKey = null
            snackbar.showSnackbar(message)
        }
    }

    val importLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            try {
                importBytes = readBackupFile(context, uri)
            } catch (_: Exception) {
                snackbar.showSnackbar(context.getString(R.string.settings_file_read_failed))
            }
        }
    }

    val exportLauncher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            val message = try {
                val bytes = session.exportBackup()
                withContext(Dispatchers.IO) {
                    context.contentResolver.openOutputStream(uri, "wt")?.use { it.write(bytes) } ?: error("no output")
                }
                context.getString(R.string.settings_export_saved)
            } catch (_: InternalException) {
                internalMessage(context.resources)
            } catch (e: OpException) {
                e.toUserMessage(context.resources)
            } catch (_: Exception) {
                context.getString(R.string.settings_export_failed)
            }
            snackbar.showSnackbar(message)
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.settings_title)) },
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.settings_back)) } },
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        Column(Modifier.padding(padding).fillMaxSize().verticalScroll(rememberScrollState())) {
            SectionLabel(stringResource(R.string.settings_section_backup), Modifier.padding(start = 16.dp, top = 8.dp))
            ListItem(
                headlineContent = { Text(stringResource(R.string.settings_auto_backup)) },
                supportingContent = {
                    when {
                        !backup.enabled -> Text(stringResource(R.string.settings_auto_backup_disabled))
                        backup.lastError != null -> Text(backupErrorText(backup.lastError!!), color = MaterialTheme.colorScheme.error)
                        else -> {
                            val folder = backup.folderName ?: stringResource(R.string.settings_folder_chosen)
                            val lastBackupAt = backup.lastBackupAt
                            val lastCopy = if (lastBackupAt == null) {
                                stringResource(R.string.settings_backup_none)
                            } else {
                                stringResource(R.string.settings_backup_last, dateTime.format(Date(lastBackupAt)))
                            }
                            Text(stringResource(R.string.settings_backup_status, folder, lastCopy))
                        }
                    }
                },
                trailingContent = { Switch(checked = backup.enabled, onCheckedChange = null) },
                modifier = Modifier.toggleable(value = backup.enabled, role = Role.Switch) { on ->
                    if (on) {
                        session.beforeSystemPicker()
                        folderLauncher.launch(null)
                    } else {
                        autoBackup.disable()
                    }
                },
            )
            if (backup.enabled) {
                ListItem(
                    headlineContent = { Text(if (backingUp) stringResource(R.string.settings_backup_busy) else stringResource(R.string.settings_backup_now)) },
                    modifier = Modifier.clickable(enabled = !backingUp) {
                        backingUp = true
                        scope.launch {
                            val error = autoBackup.backupNow()
                            backingUp = false
                            snackbar.showSnackbar(
                                error?.message(context.resources)
                                    ?: context.getString(
                                        R.string.settings_backup_now_done,
                                        backup.folderName ?: context.getString(R.string.settings_folder_unnamed),
                                    ),
                            )
                        }
                    },
                )
                ListItem(
                    headlineContent = { Text(stringResource(R.string.settings_change_folder)) },
                    modifier = Modifier.clickable { session.beforeSystemPicker(); folderLauncher.launch(null) },
                )
            }
            ListItem(
                headlineContent = { Text(stringResource(R.string.settings_export_backup)) },
                supportingContent = { Text(stringResource(R.string.settings_export_backup_hint)) },
                modifier = Modifier.clickable { session.beforeSystemPicker(); exportLauncher.launch("openpassword-${LocalDate.now()}.opvault") },
            )
            ListItem(
                headlineContent = { Text(stringResource(R.string.settings_import_backup)) },
                supportingContent = { Text(stringResource(R.string.settings_import_backup_hint)) },
                modifier = Modifier.clickable { session.beforeSystemPicker(); importLauncher.launch(arrayOf("*/*")) },
            )
            ListItem(
                headlineContent = { Text(stringResource(R.string.settings_import_external)) },
                supportingContent = { Text(stringResource(R.string.settings_import_external_hint)) },
                modifier = Modifier.clickable { session.beforeSystemPicker(); externalLauncher.launch(arrayOf("*/*")) },
            )
            ListItem(
                headlineContent = { Text(stringResource(R.string.settings_show_secret_key)) },
                supportingContent = { Text(stringResource(R.string.settings_show_secret_key_hint)) },
                modifier = Modifier.clickable { askingPassword = true },
            )
            HorizontalDivider()
            SectionLabel(stringResource(R.string.settings_section_security), Modifier.padding(start = 16.dp, top = 16.dp))
            RootWarning(dismissable = false, modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp))
            ListItem(
                headlineContent = { Text(stringResource(R.string.settings_autofill)) },
                supportingContent = {
                    Text(
                        if (autofillOn) {
                            stringResource(R.string.settings_autofill_on)
                        } else {
                            stringResource(R.string.settings_autofill_off)
                        },
                    )
                },
                modifier = Modifier.clickable {
                    // Android shows its own dialog: the user makes the choice, not the app.
                    val intent = Intent(android.provider.Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE)
                        .setData(Uri.parse("package:${context.packageName}"))
                    runCatching { autofillLauncher.launch(intent) }
                },
            )
            if (biometricsAvailable) {
                ListItem(
                    headlineContent = { Text(stringResource(R.string.settings_biometric)) },
                    supportingContent = { Text(stringResource(R.string.settings_biometric_hint)) },
                    trailingContent = { Switch(checked = biometricOn, onCheckedChange = null, enabled = !biometricBusy) },
                    modifier = Modifier.toggleable(value = biometricOn, enabled = !biometricBusy, role = Role.Switch) { on ->
                        if (on) {
                            biometricBusy = true
                            scope.launch {
                                enableBiometricUnlock(context, session)?.let { snackbar.showSnackbar(it) }
                                biometricOn = session.isBiometricEnabled()
                                biometricBusy = false
                            }
                        } else {
                            session.disableBiometric()
                            biometricOn = false
                        }
                    },
                )
            }
            ListItem(
                headlineContent = { Text(stringResource(R.string.settings_lock_now)) },
                modifier = Modifier.clickable { session.lock() },
            )
            ListItem(
                headlineContent = { Text(stringResource(R.string.settings_auto_lock)) },
                supportingContent = { Text(stringResource(R.string.settings_auto_lock_hint)) },
            )
            ListItem(
                headlineContent = { Text(stringResource(R.string.settings_no_internet)) },
                supportingContent = { Text(stringResource(R.string.settings_no_internet_hint)) },
            )
            SectionLabel(stringResource(R.string.settings_language), Modifier.padding(start = 16.dp, top = 16.dp))
            ListItem(
                headlineContent = { Text(stringResource(language.labelRes)) },
                supportingContent = { Text(stringResource(R.string.settings_language_hint)) },
                modifier = Modifier.clickable { showLanguage = true },
            )
            HorizontalDivider()
            ListItem(
                headlineContent = { Text(stringResource(R.string.settings_about_version, BuildConfigInfo.versionName(context))) },
                supportingContent = { Text(stringResource(R.string.settings_about_legal)) },
            )
        }
    }

    if (showLanguage) {
        AlertDialog(
            onDismissRequest = { showLanguage = false },
            title = { Text(stringResource(R.string.settings_language)) },
            text = {
                Column {
                    AppLanguage.entries.forEach { option ->
                        ListItem(
                            headlineContent = { Text(stringResource(option.labelRes)) },
                            modifier = Modifier.clickable {
                                showLanguage = false
                                language = option
                                activity?.let { AppLocales.set(it, option) }
                            },
                        )
                    }
                }
            },
            confirmButton = {},
            dismissButton = { TextButton(onClick = { showLanguage = false }) { Text(stringResource(R.string.action_cancel)) } },
        )
    }

    lockedExternal?.let { locked ->
        KeePassPasswordDialog(
            locked = locked,
            onUnlocked = { pendingExternal = it; lockedExternal = null },
            onCancel = { locked.bytes.fill(0); lockedExternal = null },
            beforePicker = session::beforeSystemPicker,
        )
    }

    pendingExternal?.let { pending ->
        ExternalImportDialogs(pending, session, context) { message ->
            pendingExternal = null
            if (message.isNotEmpty()) scope.launch { snackbar.showSnackbar(message) }
        }
    }

    importBytes?.let { bytes ->
        ImportDialog(
            onDismiss = { importBytes = null },
            onImport = { password, secretKey ->
                val summary = session.importBackup(bytes, password, secretKey.ifBlank { null })
                // The screen's scope, not the dialog's: closing the dialog cancels its scope.
                scope.launch {
                    snackbar.showSnackbar(
                        when {
                            summary.added == 0 && summary.updated == 0 -> context.getString(R.string.settings_import_nothing_new)
                            else -> context.getString(R.string.settings_import_result, summary.added, summary.updated)
                        },
                    )
                }
                importBytes = null
            },
        )
    }

    if (askingPassword) {
        ConfirmPasswordDialog(
            onDismiss = { askingPassword = false },
            onConfirm = { password ->
                val result = try {
                    session.verifyPassword(password)
                } catch (_: OpException) {
                    UnlockResult.Failed(io.github.rldona.openpassword.session.Failure.PasswordCheckFailed)
                } catch (_: InternalException) {
                    UnlockResult.Failed(io.github.rldona.openpassword.session.Failure.Internal)
                }
                if (result is UnlockResult.Success) {
                    askingPassword = false
                    shownSecretKey = session.secretKey()
                }
                result
            },
        )
    }

    shownSecretKey?.let { key ->
        ProtectedAlertDialog(
            onDismissRequest = { shownSecretKey = null },
            title = { Text(stringResource(R.string.settings_secret_key_title)) },
            text = {
                @OptIn(ExperimentalLayoutApi::class)
                FlowRow(horizontalArrangement = Arrangement.spacedBy(10.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    key.split('-').forEach { Text(it, fontFamily = SecretFont, fontSize = 19.sp, fontWeight = FontWeight.Medium) }
                }
            },
            confirmButton = { TextButton(onClick = { shownSecretKey = null }) { Text(stringResource(R.string.settings_secret_key_done)) } },
            dismissButton = { TextButton(onClick = { session.beforeSystemPicker(); kitLauncher.launch(EMERGENCY_KIT_FILE_NAME) }) { Text(stringResource(R.string.settings_secret_key_save_kit)) } },
        )
    }
}

@Composable
private fun ConfirmPasswordDialog(onDismiss: () -> Unit, onConfirm: suspend (String) -> UnlockResult) {
    val res = LocalContext.current.resources
    var password by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    fun submit() {
        if (busy || password.isEmpty()) return
        busy = true
        scope.launch {
            error = when (val result = onConfirm(password)) {
                UnlockResult.Success -> null
                is UnlockResult.WrongPassword ->
                    res.getString(R.string.settings_confirm_wrong_password) +
                        if (result.waitSeconds > 0) " " + res.getString(R.string.settings_confirm_wait, result.waitSeconds) else ""
                is UnlockResult.MustWait -> res.getString(R.string.settings_confirm_too_many_attempts, result.waitSeconds)
                is UnlockResult.Failed -> result.failure.message(res)
            }
            password = ""
            busy = false
        }
    }

    ProtectedAlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.settings_confirm_title)) },
        text = {
            PasswordField(
                value = password,
                onValueChange = { password = it; error = null },
                label = stringResource(R.string.settings_master_password),
                isError = error != null,
                supportingText = error,
                enabled = !busy,
                onDone = ::submit,
                modifier = Modifier.fillMaxWidth(),
            )
        },
        confirmButton = { TextButton(onClick = ::submit, enabled = !busy && password.isNotEmpty()) { Text(if (busy) stringResource(R.string.settings_checking) else stringResource(R.string.settings_continue)) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.action_cancel)) } },
    )
}

@Composable
private fun ImportDialog(onDismiss: () -> Unit, onImport: suspend (password: String, secretKey: String) -> Unit) {
    val res = LocalContext.current.resources
    var password by remember { mutableStateOf("") }
    var secretKey by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    fun submit() {
        if (busy || password.isEmpty()) return
        busy = true
        error = null
        scope.launch {
            try {
                onImport(password, secretKey)
            } catch (e: OpException) {
                error = when (e) {
                    is OpException.WrongCredentials -> res.getString(R.string.settings_import_wrong_password)
                    is OpException.WrongSecretKey -> res.getString(R.string.settings_import_wrong_secret_key)
                    is OpException.Corrupted -> res.getString(R.string.settings_import_corrupted)
                    else -> e.toUserMessage(res)
                }
                password = ""
                busy = false
            } catch (_: InternalException) {
                error = res.getString(R.string.settings_import_read_failed)
                password = ""
                busy = false
            }
        }
    }

    ProtectedAlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        title = { Text(stringResource(R.string.settings_import_backup)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.settings_import_dialog_intro), style = MaterialTheme.typography.bodyMedium)
                PasswordField(
                    value = password,
                    onValueChange = { password = it; error = null },
                    label = stringResource(R.string.settings_import_password),
                    enabled = !busy,
                    imeAction = ImeAction.Next,
                    modifier = Modifier.fillMaxWidth(),
                )
                SecretKeyField(
                    value = secretKey,
                    onValueChange = { secretKey = it; error = null },
                    enabled = !busy,
                    imeAction = ImeAction.Done,
                    supportingText = stringResource(R.string.settings_import_secret_key_hint),
                    modifier = Modifier.fillMaxWidth(),
                )
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            }
        },
        confirmButton = {
            TextButton(onClick = ::submit, enabled = !busy && password.isNotEmpty()) { Text(if (busy) stringResource(R.string.import_decrypting) else stringResource(R.string.import_action)) }
        },
        dismissButton = { TextButton(onClick = onDismiss, enabled = !busy) { Text(stringResource(R.string.action_cancel)) } },
    )
}

/** "primary:Download/OpenPassword" → "OpenPassword". */
private fun folderLabel(tree: Uri): String? =
    runCatching { DocumentsContract.getTreeDocumentId(tree) }.getOrNull()
        ?.substringAfter(':')?.trimEnd('/')?.substringAfterLast('/')?.ifBlank { null }

private val dateTime: DateFormat = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT)

@get:StringRes
private val AppLanguage.labelRes: Int
    get() = when (this) {
        AppLanguage.SYSTEM -> R.string.language_system
        AppLanguage.ENGLISH -> R.string.language_english
        AppLanguage.SPANISH -> R.string.language_spanish
    }

private fun Context.findActivity(): Activity? {
    var current: Context? = this
    while (current is ContextWrapper) {
        if (current is Activity) return current
        current = current.baseContext
    }
    return null
}
