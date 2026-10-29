package io.github.rldona.openpassword.ui.vault

import androidx.compose.foundation.BorderStroke
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
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
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
import androidx.compose.ui.unit.dp
import io.github.rldona.openpassword.autofill.LoginMatcher
import io.github.rldona.openpassword.core.FieldRecord
import io.github.rldona.openpassword.core.ItemDetailsRecord
import io.github.rldona.openpassword.security.SensitiveClipboard
import io.github.rldona.openpassword.session.VaultEntry
import io.github.rldona.openpassword.session.VaultSession
import io.github.rldona.openpassword.ui.Avatar
import io.github.rldona.openpassword.ui.SectionLabel
import io.github.rldona.openpassword.ui.initialOf
import io.github.rldona.openpassword.ui.theme.SecretText
import kotlinx.coroutines.launch
import java.text.DateFormat
import java.util.Date

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
    val details by produceState<ItemDetailsRecord?>(null, entry.record.revision) { value = session.details(entry) }
    val revealed = remember { mutableStateMapOf<Int, Boolean>() }
    var confirmDelete by remember { mutableStateOf(false) }
    val snackbar = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    val o = entry.overview

    fun copy(field: FieldRecord) {
        clipboard.copy(field.value)
        scope.launch { snackbar.showSnackbar("${field.label} copiado. Se borrará del portapapeles en 30 s.") }
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
                    Text(o.kind.label(), color = MaterialTheme.colorScheme.onSurfaceVariant)
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
                            FieldRow(
                                field = field,
                                revealed = revealed[index] == true,
                                onToggle = { revealed[index] = revealed[index] != true },
                                onCopy = { copy(field) },
                            )
                        }
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

    if (confirmDelete) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text("¿Borrar «${o.title}»?") },
            text = { Text("Se borrará de este teléfono. Las copias de seguridad que ya hayas exportado lo conservan.") },
            confirmButton = {
                TextButton(onClick = {
                    confirmDelete = false
                    scope.launch {
                        session.delete(entry)
                        onDeleted()
                    }
                }) { Text("Borrar", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text("Cancelar") } },
        )
    }
}

@Composable
private fun FieldRow(field: FieldRecord, revealed: Boolean, onToggle: () -> Unit, onCopy: () -> Unit) {
    val secret = field.kind.isSecret
    Row(Modifier.fillMaxWidth().padding(start = 16.dp, end = 4.dp, top = 10.dp, bottom = 10.dp), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(field.label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(
                if (secret && !revealed) field.masked() else field.formatted(),
                style = if (secret) SecretText else MaterialTheme.typography.bodyLarge,
            )
        }
        if (secret) TextButton(onClick = onToggle) { Text(if (revealed) "Ocultar" else "Ver") }
        TextButton(onClick = onCopy) { Text("Copiar") }
    }
}
