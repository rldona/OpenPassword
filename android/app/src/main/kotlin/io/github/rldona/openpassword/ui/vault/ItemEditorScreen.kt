package io.github.rldona.openpassword.ui.vault

import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import android.content.Context
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import io.github.rldona.openpassword.autofill.LoginMatcher
import io.github.rldona.openpassword.core.FieldKindRecord
import io.github.rldona.openpassword.core.FieldRecord
import io.github.rldona.openpassword.core.ItemDetailsRecord
import io.github.rldona.openpassword.core.ItemKindRecord
import io.github.rldona.openpassword.core.ItemOverviewRecord
import io.github.rldona.openpassword.core.OpException
import io.github.rldona.openpassword.core.totpCode
import io.github.rldona.openpassword.health.VaultHealth
import io.github.rldona.openpassword.qr.QrScanScreen
import io.github.rldona.openpassword.qr.TotpScan
import io.github.rldona.openpassword.qr.decodeQrImage
import io.github.rldona.openpassword.security.PasswordGenerator
import io.github.rldona.openpassword.security.Wordlist
import io.github.rldona.openpassword.session.VaultEntry
import io.github.rldona.openpassword.session.VaultSession
import io.github.rldona.openpassword.session.toUserMessage
import io.github.rldona.openpassword.ui.PasswordField
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ItemEditorScreen(
    existing: VaultEntry?,
    kind: ItemKindRecord,
    session: VaultSession,
    onSaved: (VaultEntry) -> Unit,
    onCancel: () -> Unit,
) {
    // Plain `remember`: field values are secrets and must not reach saved instance state.
    var title by remember { mutableStateOf(existing?.overview?.title ?: "") }
    var url by remember { mutableStateOf(existing?.overview?.urls?.firstOrNull { !it.startsWith(LoginMatcher.APP_SCHEME) } ?: "") }
    val appLinks = remember { existing?.overview?.urls?.filter { it.startsWith(LoginMatcher.APP_SCHEME) }.orEmpty() }
    var favorite by remember { mutableStateOf(existing?.overview?.favorite ?: false) }
    var notes by remember { mutableStateOf("") }
    val fields = remember { mutableStateListOf<FieldRecord>() }
    var loaded by remember { mutableStateOf(existing == null) }
    var saving by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current

    LaunchedEffect(existing?.id) {
        if (existing == null) {
            fields.addAll(kind.template())
        } else {
            val d = session.details(existing)
            // Keep stored fields; add template fields that are missing so they can be filled in.
            fields.addAll(d.fields)
            kind.template().filter { t -> d.fields.none { it.label == t.label } }.forEach(fields::add)
            notes = d.notes
            loaded = true
        }
    }

    fun save() {
        if (saving) return
        saving = true
        error = null
        scope.launch {
            try {
                val now = (System.currentTimeMillis() / 1000).toULong()
                val kept = fields.filter { it.value.isNotBlank() }.map { normalized(kind, it) }
                val invalid = when {
                    kept.any { it.kind == FieldKindRecord.TOTP && !isValidTotp(it.value) } ->
                        "El código TOTP no es válido. Pega el enlace otpauth:// o el secreto que te dio el servicio."
                    kept.any { it.kind == FieldKindRecord.CARD_NUMBER && !CardNumber.isValid(it.value) } ->
                        "El número de tarjeta no es válido: revisa que no falte ni sobre ningún dígito."
                    kind == ItemKindRecord.BANK_ACCOUNT && kept.any { it.label == IBAN_LABEL && !Iban.isValid(it.value) } ->
                        "El IBAN no es válido: revisa el país, la longitud y los dígitos."
                    else -> null
                }
                if (invalid != null) {
                    error = invalid
                    saving = false
                    return@launch
                }
                val overview = ItemOverviewRecord(
                    kind = kind,
                    title = title.trim().ifEmpty { kind.label() },
                    subtitle = kind.subtitleFor(kept),
                    urls = listOf(url.trim()).filter(String::isNotEmpty) + appLinks,
                    tags = existing?.overview?.tags ?: emptyList(),
                    favorite = favorite,
                    createdAt = existing?.overview?.createdAt ?: now,
                    updatedAt = now,
                )
                onSaved(session.save(existing, overview, ItemDetailsRecord(kept, notes.trim())))
            } catch (e: OpException) {
                error = e.toUserMessage()
                saving = false
            }
        }
    }

    // TOTP QR: which field the scanner or the picked image fills.
    var scanningField by remember { mutableStateOf<Int?>(null) }
    var imageField by remember { mutableStateOf<Int?>(null) }
    var qrMessage by remember { mutableStateOf<String?>(null) }
    val imagePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        val index = imageField ?: return@rememberLauncherForActivityResult
        imageField = null
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            qrMessage = when (val scan = decodeQrImage(context, uri)) {
                is TotpScan.Valid -> { fields[index] = fields[index].copy(value = scan.value); scanningField = null; "Código QR leído." }
                TotpScan.NotTotp -> "Ese QR no es de verificación en dos pasos."
                null -> "No se encontró ningún código QR en esa imagen."
            }
        }
    }
    fun pickQrImage(index: Int) {
        imageField = index
        session.beforeSystemPicker()
        imagePicker.launch(arrayOf("image/*"))
    }

    scanningField?.let { index ->
        BackHandler { scanningField = null }
        QrScanScreen(
            onResult = { value ->
                fields[index] = fields[index].copy(value = value)
                scanningField = null
                qrMessage = "Código QR leído."
            },
            onCancel = { scanningField = null },
            onPickImage = { pickQrImage(index) },
        )
        return
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(if (existing == null) "Nuevo: ${kind.label()}" else "Editar") },
                navigationIcon = { IconButton(onClick = onCancel) { Icon(Icons.Filled.Close, contentDescription = "Cancelar") } },
                actions = {
                    Button(onClick = ::save, enabled = loaded && !saving, modifier = Modifier.padding(end = 8.dp)) {
                        if (saving) CircularProgressIndicator(Modifier.padding(2.dp), strokeWidth = 2.dp) else Text("Guardar")
                    }
                },
            )
        },
    ) { padding ->
        if (!loaded) return@Scaffold
        Column(
            Modifier.padding(padding).imePadding().fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            OutlinedTextField(
                value = title,
                onValueChange = { title = it },
                label = { Text("Nombre") },
                placeholder = { Text(placeholderTitle(kind)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            if (kind == ItemKindRecord.LOGIN) {
                OutlinedTextField(
                    value = url,
                    onValueChange = { url = it },
                    label = { Text("Sitio web") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, autoCorrectEnabled = false),
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            fields.forEachIndexed { i, field ->
                FieldEditor(
                    field,
                    onChange = { fields[i] = field.copy(value = it) },
                    generators = generatorsFor(kind, field, context),
                    onScanQr = if (field.kind == FieldKindRecord.TOTP) ({ qrMessage = null; scanningField = i }) else null,
                    onQrImage = if (field.kind == FieldKindRecord.TOTP) ({ pickQrImage(i) }) else null,
                    qrMessage = if (field.kind == FieldKindRecord.TOTP) qrMessage else null,
                )
            }
            OutlinedTextField(
                value = notes,
                onValueChange = { notes = it },
                label = { Text("Notas") },
                minLines = if (kind == ItemKindRecord.SECURE_NOTE) 8 else 3,
                modifier = Modifier.fillMaxWidth(),
            )
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
                Text("Favorito", modifier = Modifier.weight(1f))
                Switch(checked = favorite, onCheckedChange = { favorite = it })
            }
            error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        }
    }
}

@Composable
private fun FieldEditor(
    field: FieldRecord,
    onChange: (String) -> Unit,
    generators: List<Pair<String, () -> String>>,
    onScanQr: (() -> Unit)? = null,
    onQrImage: (() -> Unit)? = null,
    qrMessage: String? = null,
) {
    if (field.kind.isSecret) {
        Column {
            PasswordField(
                value = field.value,
                onValueChange = onChange,
                label = field.label,
                imeAction = ImeAction.Next,
                modifier = Modifier.fillMaxWidth(),
                keyboardType = when (field.kind) {
                    FieldKindRecord.PIN, FieldKindRecord.CARD_NUMBER -> KeyboardType.NumberPassword
                    else -> KeyboardType.Password
                },
            )
            if (generators.isNotEmpty()) {
                Row {
                    generators.forEach { (label, generate) ->
                        TextButton(onClick = { onChange(generate()) }) { Text(label) }
                    }
                }
            }
            if (onScanQr != null && onQrImage != null) {
                Row {
                    TextButton(onClick = onScanQr) { Text("Escanear QR") }
                    TextButton(onClick = onQrImage) { Text("Desde una imagen") }
                }
                qrMessage?.let { Text(it, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(start = 12.dp)) }
            }
        }
    } else {
        OutlinedTextField(
            value = field.value,
            onValueChange = onChange,
            label = { Text(field.label) },
            singleLine = true,
            keyboardOptions = KeyboardOptions(
                keyboardType = when (field.kind) {
                    FieldKindRecord.EMAIL -> KeyboardType.Email
                    FieldKindRecord.URL -> KeyboardType.Uri
                    FieldKindRecord.DATE -> KeyboardType.Number
                    else -> KeyboardType.Text
                },
                imeAction = ImeAction.Next,
                autoCorrectEnabled = false,
            ),
            modifier = Modifier.fillMaxWidth(),
        )
    }
}

private fun generatorsFor(kind: ItemKindRecord, field: FieldRecord, context: Context): List<Pair<String, () -> String>> = when {
    field.kind == FieldKindRecord.CONCEALED && (kind == ItemKindRecord.LOGIN || kind == ItemKindRecord.WIFI) -> listOf(
        "Contraseña al azar" to { PasswordGenerator.password() },
        // Websites often reject spaces; this one is stored, not memorised.
        "Frase de paso" to { PasswordGenerator.passphrase(Wordlist.eff(context), words = 5, separator = "-") },
    )
    field.kind == FieldKindRecord.PIN && kind == ItemKindRecord.PIN -> listOf("Generar al azar" to { PasswordGenerator.pin() })
    else -> emptyList()
}

private fun placeholderTitle(kind: ItemKindRecord) = when (kind) {
    ItemKindRecord.LOGIN -> "Google, Netflix, banco…"
    ItemKindRecord.CARD -> "Visa del banco"
    ItemKindRecord.PIN -> "Alarma de casa, SIM, caja fuerte…"
    ItemKindRecord.SECRET -> "Clave API de producción"
    ItemKindRecord.SECURE_NOTE -> "Códigos de recuperación"
    ItemKindRecord.BANK_ACCOUNT -> "Cuenta nómina"
    ItemKindRecord.IDENTITY -> "DNI, pasaporte, carné de conducir…"
    ItemKindRecord.WIFI -> "Wi-Fi de casa"
}

/** Stores IBANs grouped by four and document dates as DD/MM/AAAA, whatever was typed. */
private fun normalized(kind: ItemKindRecord, field: FieldRecord): FieldRecord = when {
    kind == ItemKindRecord.BANK_ACCOUNT && field.label == IBAN_LABEL && Iban.isValid(field.value) -> field.copy(value = Iban.format(field.value))
    kind == ItemKindRecord.IDENTITY && field.kind == FieldKindRecord.DATE ->
        VaultHealth.parseDocumentDate(field.value)?.let { field.copy(value = it.format(VaultHealth.DOCUMENT_DATE)) } ?: field
    else -> field
}

private fun isValidTotp(value: String): Boolean = runCatching { totpCode(value, 0uL) }.isSuccess
