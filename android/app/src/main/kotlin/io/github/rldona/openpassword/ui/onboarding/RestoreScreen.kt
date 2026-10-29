package io.github.rldona.openpassword.ui.onboarding

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import io.github.rldona.openpassword.core.OpException
import io.github.rldona.openpassword.session.toUserMessage
import io.github.rldona.openpassword.ui.PasswordField
import io.github.rldona.openpassword.ui.SecretKeyField
import io.github.rldona.openpassword.ui.displayNameOf
import io.github.rldona.openpassword.ui.readBackupFile
import kotlinx.coroutines.launch

@Composable
fun RestoreStep(
    onRestore: suspend (backup: ByteArray, password: String, secretKey: String) -> Unit,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var file by remember { mutableStateOf<ByteArray?>(null) }
    var fileName by remember { mutableStateOf<String?>(null) }
    var secretKey by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            error = null
            file = try {
                readBackupFile(context, uri).also { fileName = displayNameOf(context, uri) }
            } catch (_: Exception) {
                error = "No se pudo leer ese fichero."
                null
            }
        }
    }

    fun restore() {
        val bytes = file ?: return
        if (busy || password.isEmpty() || secretKey.isBlank()) return
        busy = true
        error = null
        scope.launch {
            try {
                onRestore(bytes, password, secretKey)
            } catch (e: OpException) {
                error = when (e) {
                    is OpException.WrongCredentials -> "La contraseña maestra no es la de esta copia."
                    is OpException.WrongSecretKey -> "La clave secreta no corresponde a esta copia."
                    is OpException.Corrupted -> "Este fichero no es una copia de OpenPassword o está dañado."
                    else -> e.toUserMessage()
                }
                password = ""
                busy = false
            } catch (_: Exception) {
                error = "No se pudo restaurar la copia."
                busy = false
            }
        }
    }

    Text("Restaurar una copia", style = MaterialTheme.typography.headlineMedium)
    Text(
        "Elige el fichero .opvault que exportaste y escribe la clave secreta de tu kit y tu contraseña maestra.",
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        OutlinedButton(onClick = { picker.launch(arrayOf("*/*")) }, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
            Text(if (file == null) "Elegir fichero" else "Fichero: ${fileName ?: "elegido"}")
        }
        SecretKeyField(value = secretKey, onValueChange = { secretKey = it }, enabled = !busy, modifier = Modifier.fillMaxWidth())
        PasswordField(
            value = password,
            onValueChange = { password = it },
            label = "Contraseña maestra",
            enabled = !busy,
            onDone = ::restore,
            modifier = Modifier.fillMaxWidth(),
        )
        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        Button(
            onClick = ::restore,
            enabled = file != null && secretKey.isNotBlank() && password.isNotEmpty() && !busy,
            modifier = Modifier.fillMaxWidth(),
        ) {
            if (busy) {
                CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                Spacer(Modifier.size(10.dp))
                Text("Descifrando la copia…")
            } else {
                Text("Restaurar")
            }
        }
        TextButton(onClick = onBack, enabled = !busy) { Text("Volver") }
    }
}
