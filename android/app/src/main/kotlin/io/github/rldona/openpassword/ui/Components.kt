package io.github.rldona.openpassword.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.FocusDirection
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.rldona.openpassword.ui.theme.SecretText

/**
 * Password input. Uses [KeyboardType.Password] so keyboards do not learn or suggest
 * what is typed. Holds its text in plain `remember`, never in saved instance state.
 */
@Composable
fun PasswordField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    modifier: Modifier = Modifier,
    imeAction: ImeAction = ImeAction.Done,
    onDone: () -> Unit = {},
    isError: Boolean = false,
    supportingText: String? = null,
    enabled: Boolean = true,
    keyboardType: KeyboardType = KeyboardType.Password,
) {
    var visible by remember { mutableStateOf(false) }
    val focusManager = LocalFocusManager.current
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label) },
        modifier = modifier,
        singleLine = true,
        enabled = enabled,
        isError = isError,
        textStyle = SecretText,
        supportingText = supportingText?.let { { Text(it) } },
        visualTransformation = if (visible) VisualTransformation.None else PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = keyboardType, imeAction = imeAction, autoCorrectEnabled = false),
        keyboardActions = KeyboardActions(
            onDone = { onDone() },
            onGo = { onDone() },
            onNext = { focusManager.moveFocus(FocusDirection.Down) },
        ),
        trailingIcon = {
            TextButton(onClick = { visible = !visible }) { Text(if (visible) "Ocultar" else "Ver") }
        },
    )
}

@Composable
fun Avatar(letter: String, color: Color, size: Dp = 40.dp) {
    Box(
        modifier = Modifier.size(size).clip(RoundedCornerShape(size / 3.5f)).background(color),
        contentAlignment = Alignment.Center,
    ) {
        Text(letter, color = Color.White, fontWeight = FontWeight.Bold, fontSize = (size.value * 0.42f).sp)
    }
}

@Composable
fun SectionLabel(text: String, modifier: Modifier = Modifier) {
    Text(
        text.uppercase(),
        style = MaterialTheme.typography.labelSmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = modifier,
    )
}

fun initialOf(title: String): String = title.trim().firstOrNull()?.uppercase() ?: "#"

/**
 * Secret key input: shown in clear so it can be checked against the paper copy, but with
 * a password keyboard so the IME neither learns nor suggests it.
 */
@Composable
fun SecretKeyField(
    value: String,
    onValueChange: (String) -> Unit,
    modifier: Modifier = Modifier,
    isError: Boolean = false,
    supportingText: String? = null,
    enabled: Boolean = true,
    imeAction: ImeAction = ImeAction.Next,
) {
    OutlinedTextField(
        value = value,
        // Never rewrite the text here (e.g. uppercase()): it fights the IME's composing text
        // and drops characters on some keyboards. op-core already ignores case and dashes.
        onValueChange = onValueChange,
        label = { Text("Clave secreta") },
        placeholder = { Text("OP1-XXXXXX-…") },
        modifier = modifier,
        singleLine = true,
        enabled = enabled,
        isError = isError,
        textStyle = SecretText,
        supportingText = supportingText?.let { { Text(it) } },
        keyboardOptions = KeyboardOptions(
            capitalization = KeyboardCapitalization.Characters,
            keyboardType = KeyboardType.Password,
            imeAction = imeAction,
            autoCorrectEnabled = false,
        ),
    )
}

/** The name the user sees for a picked document, e.g. "openpassword-2026-10-29.opvault". */
fun displayNameOf(context: android.content.Context, uri: android.net.Uri): String? =
    context.contentResolver.query(uri, arrayOf(android.provider.OpenableColumns.DISPLAY_NAME), null, null, null)
        ?.use { c -> if (c.moveToFirst()) c.getString(0) else null }

/** Reads a document chosen with the system picker, refusing anything implausibly large for a backup. */
suspend fun readBackupFile(context: android.content.Context, uri: android.net.Uri): ByteArray =
    kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        context.contentResolver.openInputStream(uri)?.use { input ->
            val out = java.io.ByteArrayOutputStream()
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val n = input.read(buffer)
                if (n < 0) break
                out.write(buffer, 0, n)
                require(out.size() <= MAX_BACKUP_BYTES) { "too large" }
            }
            out.toByteArray()
        } ?: error("cannot open")
    }

private const val MAX_BACKUP_BYTES = 64 * 1024 * 1024

/** Writes [bytes] to a document the user picked with the system "save as" dialog. */
suspend fun writeDocument(context: android.content.Context, uri: android.net.Uri, bytes: ByteArray) =
    kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        context.contentResolver.openOutputStream(uri, "wt")?.use { it.write(bytes) } ?: error("cannot open")
    }

/** File name for the emergency kit, so it is easy to find and delete after printing. */
const val EMERGENCY_KIT_FILE_NAME = "openpassword-kit-de-emergencia.pdf"
