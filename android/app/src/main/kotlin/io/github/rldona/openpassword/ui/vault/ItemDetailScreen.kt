package io.github.rldona.openpassword.ui.vault

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.rldona.openpassword.autofill.LoginMatcher
import io.github.rldona.openpassword.core.FieldKindRecord
import io.github.rldona.openpassword.core.FieldRecord
import io.github.rldona.openpassword.core.InternalException
import io.github.rldona.openpassword.core.OpException
import io.github.rldona.openpassword.core.totpCode
import io.github.rldona.openpassword.core.ItemDetailsRecord
import io.github.rldona.openpassword.core.ItemKindRecord
import io.github.rldona.openpassword.qr.WifiQr
import io.github.rldona.openpassword.security.SensitiveClipboard
import io.github.rldona.openpassword.session.INTERNAL_ERROR_MESSAGE
import io.github.rldona.openpassword.session.VaultEntry
import io.github.rldona.openpassword.session.VaultSession
import io.github.rldona.openpassword.session.toUserMessage
import io.github.rldona.openpassword.ui.Avatar
import io.github.rldona.openpassword.ui.SectionLabel
import io.github.rldona.openpassword.ui.initialOf
import io.github.rldona.openpassword.ui.theme.SecretText
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.text.DateFormat
import java.util.Date
import io.github.rldona.openpassword.ui.ProtectedAlertDialog
import androidx.compose.ui.platform.LocalContext
import io.github.rldona.openpassword.data.StoredLabels

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ItemDetailScreen(
    entry: VaultEntry,
    session: VaultSession,
    clipboard: SensitiveClipboard,
    onBack: () -> Unit,
    onEdit: () -> Unit,
    onDeleted: () -> Unit,
) {
    val snackbar = remember { SnackbarHostState() }
    val details by produceState<ItemDetailsRecord?>(null, entry.record.revision) {
        try {
            value = session.details(entry)
        } catch (e: OpException) {
            snackbar.showSnackbar(e.toUserMessage())
        } catch (_: InternalException) {
            snackbar.showSnackbar(INTERNAL_ERROR_MESSAGE)
        }
    }
    val revealed = remember { mutableStateMapOf<Int, Boolean>() }
    var confirmDelete by remember { mutableStateOf(false) }
    var wifiQr by remember { mutableStateOf<String?>(null) }
    var viewing by remember { mutableStateOf<Pair<ByteArray, String>?>(null) }
    val scope = rememberCoroutineScope()
    val res = LocalContext.current.resources
    val o = entry.overview

    fun copy(field: FieldRecord) {
        clipboard.copy(field.value)
        scope.launch { snackbar.showSnackbar("${FieldLabels.display(field.label, res)} copiado. Se borrará en 30 s, o al volver a la app si sales.") }
    }

    fun viewImage(field: FieldRecord) {
        scope.launch {
            try {
                val bytes = session.image(entry, field.value)
                if (bytes == null) snackbar.showSnackbar("Imagen no disponible.") else viewing = bytes to FieldLabels.display(field.label, res)
            } catch (e: OpException) {
                snackbar.showSnackbar(e.toUserMessage())
            } catch (_: InternalException) {
                snackbar.showSnackbar(INTERNAL_ERROR_MESSAGE)
            }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {},
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Volver") } },
                actions = {
                    IconButton(onClick = onEdit) { Icon(Icons.Filled.Edit, contentDescription = "Editar") }
                    IconButton(onClick = { confirmDelete = true }) { Icon(Icons.Filled.Delete, contentDescription = "Borrar") }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        Column(
            Modifier.padding(padding).fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(14.dp)) {
                Avatar(initialOf(o.title), o.kind.avatarColor(), size = 52.dp)
                Column {
                    Text(o.title, style = MaterialTheme.typography.titleLarge)
                    Text(o.kind.labelText(), color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }

            val d = details
            if (d == null) {
                CircularProgressIndicator(Modifier.align(Alignment.CenterHorizontally))
            } else {
                val fields = d.fields.withIndex().filter { it.value.value.isNotEmpty() }
                if (fields.isNotEmpty()) {
                    Card(
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLowest),
                        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
                    ) {
                        fields.forEachIndexed { pos, (index, field) ->
                            if (pos > 0) HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                            if (field.kind == FieldKindRecord.TOTP) {
                                TotpRow(field, onCopy = { code ->
                                    clipboard.copy(code)
                                    scope.launch { snackbar.showSnackbar("Código copiado. Se borrará en 30 s, o al volver a la app si sales.") }
                                })
                            } else if (field.kind == FieldKindRecord.IMAGE) {
                                ImageRow(field, onView = { viewImage(field) })
                            } else {
                                FieldRow(
                                    field = field,
                                    revealed = revealed[index] == true,
                                    onToggle = { revealed[index] = revealed[index] != true },
                                    onCopy = { copy(field) },
                                )
                            }
                        }
                    }
                }
                if (o.kind == ItemKindRecord.WIFI) {
                    val ssid = d.fields.firstOrNull { it.label == StoredLabels.WIFI_SSID }?.value.orEmpty()
                    val password = d.fields.firstOrNull { it.kind == FieldKindRecord.CONCEALED }?.value.orEmpty()
                    if (ssid.isNotEmpty()) {
                        OutlinedButton(onClick = { wifiQr = WifiQr.payload(ssid, password) }) { Text("Mostrar QR para conectarse") }
                    }
                }
                val (apps, sites) = o.urls.partition { it.startsWith(LoginMatcher.APP_SCHEME) }
                if (sites.isNotEmpty()) {
                    SectionLabel("Sitio web")
                    sites.forEach { Text(it, style = MaterialTheme.typography.bodyLarge) }
                }
                if (apps.isNotEmpty()) {
                    SectionLabel("Apps donde se rellena")
                    apps.forEach { Text(it.removePrefix(LoginMatcher.APP_SCHEME), style = MaterialTheme.typography.bodyLarge) }
                }
                if (d.history.isNotEmpty()) {
                    SectionLabel("Contraseñas anteriores")
                    val dateFmt = remember { DateFormat.getDateInstance(DateFormat.MEDIUM) }
                    Card(
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLowest),
                        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
                    ) {
                        d.history.forEachIndexed { i, change ->
                            if (i > 0) HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                            val old = FieldRecord("${storedLabelText(change.label)} · hasta el ${dateFmt.format(Date(change.changedAt.toLong() * 1000))}", FieldKindRecord.CONCEALED, change.value)
                            // Negative keys so they never clash with the field indexes above.
                            FieldRow(old, revealed = revealed[-1 - i] == true, onToggle = { revealed[-1 - i] = revealed[-1 - i] != true }, onCopy = {
                                clipboard.copy(change.value)
                                scope.launch { snackbar.showSnackbar("Contraseña anterior copiada. Se borrará en 30 s, o al volver a la app si sales.") }
                            })
                        }
                    }
                }
                if (d.notes.isNotBlank()) {
                    SectionLabel("Notas")
                    Text(d.notes, style = MaterialTheme.typography.bodyLarge)
                }
            }

            val fmt = remember { DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT) }
            Text(
                "Creado ${fmt.format(Date(o.createdAt.toLong() * 1000))} · Modificado ${fmt.format(Date(o.updatedAt.toLong() * 1000))}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(bottom = 24.dp),
            )
        }
    }

    wifiQr?.let { payload ->
        val qr = remember(payload) { WifiQr.bitmap(payload, 720).asImageBitmap() }
        ProtectedAlertDialog(
            onDismissRequest = { wifiQr = null },
            title = { Text(o.title) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                    Image(qr, contentDescription = "Código QR de la red", modifier = Modifier.fillMaxWidth().aspectRatio(1f))
                    Text("Escanéalo con la cámara del otro teléfono. Quien vea este código puede conectarse a la red.")
                }
            },
            confirmButton = { TextButton(onClick = { wifiQr = null }) { Text("Cerrar") } },
        )
    }

    if (confirmDelete) {
        ProtectedAlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text("¿Borrar «${o.title}»?") },
            text = { Text("Se borrará de este teléfono. Las copias de seguridad que ya hayas exportado lo conservan.") },
            confirmButton = {
                TextButton(onClick = {
                    confirmDelete = false
                    scope.launch {
                        try {
                            session.delete(entry)
                            onDeleted()
                        } catch (e: OpException) {
                            snackbar.showSnackbar(e.toUserMessage())
                        } catch (_: InternalException) {
                            snackbar.showSnackbar(INTERNAL_ERROR_MESSAGE)
                        }
                    }
                }) { Text("Borrar", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text("Cancelar") } },
        )
    }

    viewing?.let { (bytes, label) ->
        ImageViewerDialog(bytes = bytes, label = label) { viewing = null }
    }
}

/** An attached image: only the label and a way to see it. Never copied, shared or thumbnailed. */
@Composable
private fun ImageRow(field: FieldRecord, onView: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().padding(start = 16.dp, end = 4.dp, top = 10.dp, bottom = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(field.displayLabel(), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text("Imagen cifrada", style = MaterialTheme.typography.bodyLarge)
        }
        TextButton(onClick = onView) { Text("Ver") }
    }
}

/** Shows the current one-time code, never the secret behind it. */
@Composable
private fun TotpRow(field: FieldRecord, onCopy: (String) -> Unit) {
    val now by produceState(System.currentTimeMillis() / 1000) {
        while (true) {
            value = System.currentTimeMillis() / 1000
            delay(1_000 - System.currentTimeMillis() % 1_000)
        }
    }
    val code = remember(field.value, now) { runCatching { totpCode(field.value, now.toULong()) }.getOrNull() }
    Row(Modifier.fillMaxWidth().padding(start = 16.dp, end = 4.dp, top = 10.dp, bottom = 10.dp), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(field.displayLabel(), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            if (code == null) {
                Text("El secreto guardado no es válido. Edita el elemento.", color = MaterialTheme.colorScheme.error)
            } else {
                Text(code.code.chunked(3).joinToString(" "), style = SecretText.copy(fontSize = 24.sp))
                val left = code.secondsRemaining.toFloat() / code.period.toFloat()
                LinearProgressIndicator(
                    progress = { left },
                    color = if (code.secondsRemaining <= 5uL) MaterialTheme.colorScheme.tertiary else MaterialTheme.colorScheme.primary,
                    modifier = Modifier.fillMaxWidth(0.6f),
                )
                Text("Cambia en ${code.secondsRemaining} s", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        if (code != null) TextButton(onClick = { onCopy(code.code) }) { Text("Copiar") }
    }
}

@Composable
private fun FieldRow(field: FieldRecord, revealed: Boolean, onToggle: () -> Unit, onCopy: () -> Unit) {
    val secret = field.kind.isSecret
    Row(Modifier.fillMaxWidth().padding(start = 16.dp, end = 4.dp, top = 10.dp, bottom = 10.dp), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            val network = if (field.kind == FieldKindRecord.CARD_NUMBER) CardNumber.network(field.value) else null
            Text(listOfNotNull(field.displayLabel(), network).joinToString(" · "), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(
                if (secret && !revealed) field.masked() else field.formatted(),
                style = if (secret) SecretText else MaterialTheme.typography.bodyLarge,
            )
        }
        if (secret) TextButton(onClick = onToggle) { Text(if (revealed) "Ocultar" else "Ver") }
        TextButton(onClick = onCopy) { Text("Copiar") }
    }
}
