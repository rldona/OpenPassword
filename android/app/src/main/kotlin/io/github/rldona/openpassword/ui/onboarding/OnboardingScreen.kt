package io.github.rldona.openpassword.ui.onboarding

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.activity.compose.BackHandler
import io.github.rldona.openpassword.core.OpException
import io.github.rldona.openpassword.core.generateSecretKey
import io.github.rldona.openpassword.session.toUserMessage
import io.github.rldona.openpassword.ui.PasswordField
import io.github.rldona.openpassword.ui.SectionLabel
import io.github.rldona.openpassword.ui.theme.SecretFont
import kotlinx.coroutines.launch

private const val MIN_PASSWORD = 10
private const val RESTORE = -1

@Composable
fun OnboardingScreen(
    onCreate: suspend (password: String, secretKey: String) -> Unit,
    onRestore: suspend (backup: ByteArray, password: String, secretKey: String) -> Unit,
) {
    var step by remember { mutableIntStateOf(0) }
    // Deliberately `remember`, not `rememberSaveable`: secrets never go to saved state.
    var password by remember { mutableStateOf("") }
    val secretKey = remember { generateSecretKey() }

    BackHandler(enabled = step != 0) { step = if (step == RESTORE) 0 else step - 1 }

    Surface(Modifier.fillMaxSize()) {
        Column(
            Modifier.safeDrawingPadding().imePadding().verticalScroll(rememberScrollState()).padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(20.dp),
        ) {
            if (step in 1..2) SectionLabel("Paso $step de 2")
            when (step) {
                0 -> Welcome(onNext = { step = 1 }, onRestore = { step = RESTORE })
                RESTORE -> RestoreStep(onRestore = onRestore, onBack = { step = 0 })
                1 -> ChoosePassword(password, { password = it }, onNext = { step = 2 })
                else -> SecretKeyStep(secretKey, onCreate = { onCreate(password, secretKey) })
            }
        }
    }
}

@Composable
private fun Welcome(onNext: () -> Unit, onRestore: () -> Unit) {
    Spacer(Modifier.height(32.dp))
    Text("OpenPassword", style = MaterialTheme.typography.headlineMedium)
    Text(
        "Tus contraseñas, tarjetas, PINs y secretos, cifrados en este teléfono.",
        style = MaterialTheme.typography.bodyLarge,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
        Point("Sin cuenta y sin servidor", "Nada sale del teléfono. La app no tiene permiso de Internet.")
        Point("Cifrado antes de guardarse", "Todo se cifra con tu contraseña maestra y una clave secreta, títulos incluidos.")
        Point("Código abierto", "Cualquiera puede revisar cómo funciona.")
    }
    Spacer(Modifier.height(8.dp))
    Button(onClick = onNext, modifier = Modifier.fillMaxWidth()) { Text("Crear mi baúl") }
    OutlinedButton(onClick = onRestore, modifier = Modifier.fillMaxWidth()) { Text("Restaurar una copia de seguridad") }
}

@Composable
private fun Point(title: String, body: String) {
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Text(title, style = MaterialTheme.typography.titleSmall)
        Text(body, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun ChoosePassword(password: String, onChange: (String) -> Unit, onNext: () -> Unit) {
    var confirm by remember { mutableStateOf("") }
    var triedNext by remember { mutableStateOf(false) }
    val tooShort = password.length < MIN_PASSWORD
    val mismatch = confirm != password
    val strength = strengthOf(password)

    Text("Elige tu contraseña maestra", style = MaterialTheme.typography.headlineMedium)
    Text(
        "Es la única que tendrás que recordar. Una frase de varias palabras es más fácil de recordar y más difícil de adivinar.",
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    PasswordField(
        value = password,
        onValueChange = onChange,
        label = "Contraseña maestra",
        imeAction = ImeAction.Next,
        modifier = Modifier.fillMaxWidth(),
        isError = triedNext && tooShort,
        supportingText = if (triedNext && tooShort) "Usa al menos $MIN_PASSWORD caracteres." else null,
    )
    if (password.isNotEmpty()) {
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            LinearProgressIndicator(progress = { strength.fraction }, modifier = Modifier.fillMaxWidth(), color = strength.color())
            Text(strength.label, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
    PasswordField(
        value = confirm,
        onValueChange = { confirm = it },
        label = "Repite la contraseña",
        modifier = Modifier.fillMaxWidth(),
        isError = triedNext && mismatch,
        supportingText = if (triedNext && mismatch) "Las contraseñas no coinciden." else null,
        onDone = { triedNext = true; if (!tooShort && !mismatch) onNext() },
    )
    WarningCard("Si la olvidas, nadie podrá recuperar tus datos. Tampoco nosotros.")
    Button(
        onClick = { triedNext = true; if (!tooShort && !mismatch) onNext() },
        modifier = Modifier.fillMaxWidth(),
    ) { Text("Continuar") }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun SecretKeyStep(secretKey: String, onCreate: suspend () -> Unit) {
    var saved by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    Text("Tu clave secreta", style = MaterialTheme.typography.headlineMedium)
    Text(
        "Se combina con tu contraseña maestra. Se queda guardada en este teléfono, pero la necesitarás para abrir una copia de seguridad en otro.",
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    Card(
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLowest),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
        modifier = Modifier.fillMaxWidth(),
    ) {
        FlowRow(
            Modifier.padding(18.dp),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            secretKey.split('-').forEach { group ->
                Text(group, fontFamily = SecretFont, fontSize = 20.sp, fontWeight = FontWeight.Medium, letterSpacing = 1.sp)
            }
        }
    }
    Text(
        "Anótala en papel y guárdala con tus documentos importantes. No le hagas foto ni la guardes en la nube: la app bloquea las capturas de pantalla.",
        style = MaterialTheme.typography.bodyMedium,
    )
    Row(
        Modifier.fillMaxWidth().toggleable(value = saved, enabled = !busy, role = Role.Checkbox, onValueChange = { saved = it }),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Checkbox(checked = saved, onCheckedChange = null, enabled = !busy)
        Spacer(Modifier.size(12.dp))
        Text("He anotado mi clave secreta en un lugar seguro")
    }
    error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
    Button(
        onClick = {
            busy = true
            error = null
            scope.launch {
                try {
                    onCreate()
                } catch (e: OpException) {
                    error = e.toUserMessage()
                    busy = false
                }
            }
        },
        enabled = saved && !busy,
        modifier = Modifier.fillMaxWidth(),
    ) {
        if (busy) {
            CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
            Spacer(Modifier.size(10.dp))
            Text("Cifrando el baúl…")
        } else {
            Text("Crear baúl")
        }
    }
}

@Composable
fun WarningCard(text: String) {
    Surface(
        color = MaterialTheme.colorScheme.tertiaryContainer,
        shape = MaterialTheme.shapes.medium,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Text(text, Modifier.padding(14.dp), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurface)
    }
}
