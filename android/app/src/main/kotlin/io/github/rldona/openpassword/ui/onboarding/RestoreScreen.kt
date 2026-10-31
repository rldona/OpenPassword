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
import io.github.rldona.openpassword.R
import io.github.rldona.openpassword.core.OpException
import io.github.rldona.openpassword.session.toUserMessage
import io.github.rldona.openpassword.ui.PasswordField
import io.github.rldona.openpassword.ui.SecretKeyField
import io.github.rldona.openpassword.ui.displayNameOf
import io.github.rldona.openpassword.ui.readBackupFile
import androidx.compose.ui.res.stringResource
import kotlinx.coroutines.launch
import androidx.compose.ui.platform.LocalResources

@Composable
fun RestoreStep(
    onRestore: suspend (backup: ByteArray, password: String, secretKey: String) -> Unit,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    val resources = LocalResources.current
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
                error = resources.getString(R.string.settings_file_read_failed)
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
                    is OpException.WrongCredentials -> resources.getString(R.string.restore_wrong_password)
                    is OpException.WrongSecretKey -> resources.getString(R.string.restore_wrong_secret_key)
                    is OpException.Corrupted -> resources.getString(R.string.restore_corrupted)
                    else -> e.toUserMessage(resources)
                }
                password = ""
                busy = false
            } catch (_: Exception) {
                error = resources.getString(R.string.restore_failed)
                busy = false
            }
        }
    }

    Text(stringResource(R.string.restore_title), style = MaterialTheme.typography.headlineMedium)
    Text(
        stringResource(R.string.restore_body),
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        OutlinedButton(onClick = { picker.launch(arrayOf("*/*")) }, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
            Text(
                if (file == null) stringResource(R.string.restore_choose_file)
                else stringResource(
                    R.string.restore_file_chosen,
                    fileName ?: stringResource(R.string.restore_file_chosen_default),
                ),
            )
        }
        SecretKeyField(value = secretKey, onValueChange = { secretKey = it }, enabled = !busy, modifier = Modifier.fillMaxWidth())
        PasswordField(
            value = password,
            onValueChange = { password = it },
            label = stringResource(R.string.settings_master_password),
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
                Text(stringResource(R.string.restore_decrypting))
            } else {
                Text(stringResource(R.string.restore_action))
            }
        }
        TextButton(onClick = onBack, enabled = !busy) { Text(stringResource(R.string.restore_back)) }
    }
}
