package io.github.rldona.openpassword.ui.settings

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
import androidx.compose.material3.AlertDialog
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
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.rldona.openpassword.BuildConfigInfo
import io.github.rldona.openpassword.core.OpException
import io.github.rldona.openpassword.security.strongBiometricsAvailable
import io.github.rldona.openpassword.session.VaultSession
import io.github.rldona.openpassword.session.toUserMessage
import io.github.rldona.openpassword.ui.PasswordField
import io.github.rldona.openpassword.ui.SectionLabel
import io.github.rldona.openpassword.ui.theme.SecretFont
import io.github.rldona.openpassword.ui.unlock.enableBiometricUnlock
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.time.LocalDate

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(session: VaultSession, onBack: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }
    var askingPassword by remember { mutableStateOf(false) }
    var shownSecretKey by remember { mutableStateOf<String?>(null) }
    val biometricsAvailable = remember { strongBiometricsAvailable(context) }
    var biometricOn by remember { mutableStateOf(session.isBiometricEnabled()) }
    var biometricBusy by remember { mutableStateOf(false) }

    val exportLauncher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            val message = try {
                val bytes = session.exportBackup()
                withContext(Dispatchers.IO) {
                    context.contentResolver.openOutputStream(uri, "wt")?.use { it.write(bytes) } ?: error("no output")
                }
                "Copia cifrada guardada. Para abrirla necesitarás tu contraseña maestra y tu clave secreta."
            } catch (e: OpException) {
                e.toUserMessage()
            } catch (_: Exception) {
                "No se pudo guardar la copia en esa ubicación."
            }
            snackbar.showSnackbar(message)
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Ajustes") },
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Volver") } },
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        Column(Modifier.padding(padding).fillMaxSize().verticalScroll(rememberScrollState())) {
            SectionLabel("Copia de seguridad", Modifier.padding(start = 16.dp, top = 8.dp))
            ListItem(
                headlineContent = { Text("Exportar copia cifrada") },
                supportingContent = { Text("Guarda un fichero .opvault donde elijas: tu ordenador, una tarjeta SD o una carpeta de la nube.") },
                modifier = Modifier.clickable { exportLauncher.launch("openpassword-${LocalDate.now()}.opvault") },
            )
            ListItem(
                headlineContent = { Text("Ver clave secreta") },
                supportingContent = { Text("Para anotarla de nuevo. Te pediremos la contraseña maestra.") },
                modifier = Modifier.clickable { askingPassword = true },
            )
            HorizontalDivider()
            SectionLabel("Seguridad", Modifier.padding(start = 16.dp, top = 16.dp))
            if (biometricsAvailable) {
                ListItem(
                    headlineContent = { Text("Desbloquear con huella") },
                    supportingContent = { Text("Te pediremos la contraseña maestra cada 14 días y tras reiniciar el teléfono.") },
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
                headlineContent = { Text("Bloquear ahora") },
                modifier = Modifier.clickable { session.lock() },
            )
            ListItem(
                headlineContent = { Text("Bloqueo automático") },
                supportingContent = { Text("Tras 5 minutos sin uso, 30 segundos en segundo plano o al apagar la pantalla.") },
            )
            ListItem(
                headlineContent = { Text("Sin acceso a Internet") },
                supportingContent = { Text("Esta app no tiene permiso de red. Tus datos solo salen del teléfono en las copias que exportes tú.") },
            )
            HorizontalDivider()
            ListItem(
                headlineContent = { Text("OpenPassword ${BuildConfigInfo.versionName(context)}") },
                supportingContent = { Text("Software libre bajo GPL-3.0-or-later. github.com/rldona/OpenPassword") },
            )
        }
    }

    if (askingPassword) {
        ConfirmPasswordDialog(
            onDismiss = { askingPassword = false },
            onConfirm = { password ->
                if (session.verifyPassword(password)) {
                    askingPassword = false
                    shownSecretKey = session.secretKey()
                    true
                } else {
                    false
                }
            },
        )
    }

    shownSecretKey?.let { key ->
        AlertDialog(
            onDismissRequest = { shownSecretKey = null },
            title = { Text("Tu clave secreta") },
            text = {
                @OptIn(ExperimentalLayoutApi::class)
                FlowRow(horizontalArrangement = Arrangement.spacedBy(10.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    key.split('-').forEach { Text(it, fontFamily = SecretFont, fontSize = 19.sp, fontWeight = FontWeight.Medium) }
                }
            },
            confirmButton = { TextButton(onClick = { shownSecretKey = null }) { Text("Hecho") } },
        )
    }
}

@Composable
private fun ConfirmPasswordDialog(onDismiss: () -> Unit, onConfirm: suspend (String) -> Boolean) {
    var password by remember { mutableStateOf("") }
    var wrong by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    fun submit() {
        if (busy || password.isEmpty()) return
        busy = true
        scope.launch {
            wrong = !onConfirm(password)
            password = ""
            busy = false
        }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Confirma que eres tú") },
        text = {
            PasswordField(
                value = password,
                onValueChange = { password = it; wrong = false },
                label = "Contraseña maestra",
                isError = wrong,
                supportingText = if (wrong) "Contraseña incorrecta." else null,
                enabled = !busy,
                onDone = ::submit,
                modifier = Modifier.fillMaxWidth(),
            )
        },
        confirmButton = { TextButton(onClick = ::submit, enabled = !busy && password.isNotEmpty()) { Text(if (busy) "Comprobando…" else "Continuar") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancelar") } },
    )
}
