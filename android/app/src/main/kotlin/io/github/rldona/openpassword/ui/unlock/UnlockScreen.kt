package io.github.rldona.openpassword.ui.unlock

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import io.github.rldona.openpassword.session.UnlockResult
import io.github.rldona.openpassword.ui.PasswordField
import io.github.rldona.openpassword.ui.RootWarning
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import io.github.rldona.openpassword.session.message

/**
 * @param onBiometric biometric unlock, or null if it is off or the password is required now.
 *   Returns null when the user dismissed the prompt.
 * @param notice why the password is required although biometric unlock is on.
 */
@Composable
fun UnlockScreen(
    onUnlock: suspend (String) -> UnlockResult,
    onBiometric: (suspend () -> UnlockResult?)? = null,
    notice: String? = null,
) {
    var password by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<String?>(null) }
    var waitSeconds by remember { mutableLongStateOf(0L) }
    val res = androidx.compose.ui.platform.LocalContext.current.resources
    val scope = rememberCoroutineScope()
    val focus = remember { FocusRequester() }

    fun biometric() {
        val run = onBiometric ?: return
        if (busy) return
        busy = true
        message = null
        scope.launch {
            when (val result = run()) {
                is UnlockResult.Failed -> message = result.failure.message(res)
                else -> Unit
            }
            busy = false
        }
    }

    // Offer the fingerprint straight away; the password field stays as the fallback.
    LaunchedEffect(Unit) { if (onBiometric != null) biometric() else focus.requestFocus() }
    LaunchedEffect(waitSeconds) {
        if (waitSeconds > 0) {
            delay(1_000)
            waitSeconds--
        }
    }

    fun submit() {
        if (busy || password.isEmpty() || waitSeconds > 0) return
        busy = true
        message = null
        scope.launch {
            when (val result = onUnlock(password)) {
                UnlockResult.Success -> Unit
                is UnlockResult.WrongPassword -> {
                    message = "Contraseña maestra incorrecta."
                    waitSeconds = result.waitSeconds
                }
                is UnlockResult.MustWait -> waitSeconds = result.waitSeconds
                is UnlockResult.Failed -> message = result.failure.message(res)
            }
            password = ""
            busy = false
        }
    }

    Surface(Modifier.fillMaxSize()) {
        Column(
            Modifier.safeDrawingPadding().imePadding().padding(24.dp).fillMaxSize(),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
        ) {
            Box(
                Modifier.size(72.dp).clip(RoundedCornerShape(22.dp)).background(MaterialTheme.colorScheme.primaryContainer),
                contentAlignment = Alignment.Center,
            ) {
                Icon(Icons.Filled.Lock, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(34.dp))
            }
            Text("Caja fuerte bloqueada", style = MaterialTheme.typography.headlineMedium)
            notice?.let {
                Text(it, color = MaterialTheme.colorScheme.onSurfaceVariant, textAlign = TextAlign.Center)
            }
            PasswordField(
                value = password,
                onValueChange = { password = it },
                label = "Contraseña maestra",
                modifier = Modifier.fillMaxWidth().focusRequester(focus),
                enabled = !busy,
                isError = message != null,
                supportingText = message,
                onDone = ::submit,
            )
            Button(onClick = ::submit, enabled = !busy && password.isNotEmpty() && waitSeconds == 0L, modifier = Modifier.fillMaxWidth()) {
                if (busy) {
                    CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                    Spacer(Modifier.size(10.dp))
                    Text("Descifrando…")
                } else {
                    Text("Desbloquear")
                }
            }
            if (onBiometric != null) {
                OutlinedButton(onClick = ::biometric, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
                    Text("Usar huella")
                }
            }
            RootWarning(dismissable = true)
            if (waitSeconds > 0) {
                Text(
                    "Demasiados intentos. Espera $waitSeconds s para volver a probar.",
                    color = MaterialTheme.colorScheme.tertiary,
                    textAlign = TextAlign.Center,
                )
            }
        }
    }
}
