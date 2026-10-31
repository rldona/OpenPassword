package io.github.rldona.openpassword.ui.vault

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import io.github.rldona.openpassword.R
import io.github.rldona.openpassword.core.ItemKindRecord
import io.github.rldona.openpassword.health.HealthBanner
import io.github.rldona.openpassword.health.HealthReport
import io.github.rldona.openpassword.session.VaultEntry
import io.github.rldona.openpassword.ui.Avatar
import io.github.rldona.openpassword.ui.initialOf
import java.text.Collator
import java.util.Locale
import io.github.rldona.openpassword.ui.ProtectedAlertDialog

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VaultListScreen(
    entries: List<VaultEntry>,
    onOpen: (VaultEntry) -> Unit,
    onAdd: (ItemKindRecord) -> Unit,
    onLock: () -> Unit,
    onSettings: () -> Unit,
    health: HealthReport = HealthReport.EMPTY,
    onHealth: () -> Unit = {},
    unreadable: Int = 0,
) {
    // The query is not a secret, but it can reveal what you look for: keep it out of saved state too.
    var query by remember { mutableStateOf("") }
    var filter by rememberSaveable { mutableStateOf<ItemKindRecord?>(null) }
    var choosingKind by remember { mutableStateOf(false) }

    val collator = remember { Collator.getInstance(Locale.forLanguageTag("es")) }
    val kindsPresent = remember(entries) { entries.map { it.overview.kind }.distinct().sortedBy { it.ordinal } }
    val visible = remember(entries, query, filter) {
        val key = query.searchKey().trim()
        entries
            .filter { filter == null || it.overview.kind == filter }
            .filter { e ->
                key.isEmpty() || listOfNotNull(e.overview.title, e.overview.subtitle, *e.overview.urls.toTypedArray(), *e.overview.tags.toTypedArray())
                    .any { it.searchKey().contains(key) }
            }
            .sortedWith(compareByDescending<VaultEntry> { it.overview.favorite }.thenBy(collator) { it.overview.title })
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.vault_list_title)) },
                actions = {
                    IconButton(onClick = onLock) { Icon(Icons.Filled.Lock, contentDescription = stringResource(R.string.vault_list_lock)) }
                    IconButton(onClick = onSettings) { Icon(Icons.Filled.Settings, contentDescription = stringResource(R.string.vault_list_settings)) }
                },
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = { choosingKind = true }) { Icon(Icons.Filled.Add, contentDescription = stringResource(R.string.vault_list_add_item)) }
        },
    ) { padding ->
        Column(Modifier.padding(padding).fillMaxSize()) {
            UnreadableBanner(unreadable, Modifier.padding(horizontal = 16.dp, vertical = 4.dp))
            if (query.isEmpty()) HealthBanner(health, onHealth, Modifier.padding(horizontal = 16.dp, vertical = 4.dp))
            if (entries.isNotEmpty()) {
                OutlinedTextField(
                    value = query,
                    onValueChange = { query = it },
                    placeholder = { Text(pluralStringResource(R.plurals.vault_list_search_placeholder, entries.size, entries.size)) },
                    leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp),
                )
                if (kindsPresent.size > 1) {
                    LazyRow(
                        contentPadding = PaddingValues(horizontal = 16.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        item { FilterChip(selected = filter == null, onClick = { filter = null }, label = { Text(stringResource(R.string.vault_list_filter_all)) }) }
                        items(kindsPresent) { kind ->
                            FilterChip(selected = filter == kind, onClick = { filter = if (filter == kind) null else kind }, label = { Text(kind.shortLabelText()) })
                        }
                    }
                }
            }
            when {
                entries.isEmpty() -> EmptyState(
                    stringResource(R.string.vault_list_empty_title),
                    stringResource(R.string.vault_list_empty_body),
                )
                visible.isEmpty() -> EmptyState(
                    stringResource(R.string.vault_list_no_results_title),
                    stringResource(R.string.vault_list_no_results_body, query),
                )
                else -> LazyColumn(contentPadding = PaddingValues(bottom = 96.dp)) {
                    items(visible, key = { it.id }) { entry ->
                        EntryRow(entry, onClick = { onOpen(entry) })
                        HorizontalDivider(Modifier.padding(start = 72.dp), color = MaterialTheme.colorScheme.outlineVariant)
                    }
                }
            }
        }
    }

    if (choosingKind) {
        ProtectedAlertDialog(
            onDismissRequest = { choosingKind = false },
            title = { Text(stringResource(R.string.vault_list_choose_kind_title)) },
            text = {
                Column {
                    CreatableKinds.forEach { kind ->
                        ListItem(
                            headlineContent = { Text(kind.labelText()) },
                            leadingContent = { Avatar(kind.labelText().take(1), kind.avatarColor(), size = 32.dp) },
                            modifier = Modifier.clickable { choosingKind = false; onAdd(kind) },
                        )
                    }
                }
            },
            confirmButton = {},
            dismissButton = { TextButton(onClick = { choosingKind = false }) { Text(stringResource(R.string.action_cancel)) } },
        )
    }
}

@Composable
private fun EntryRow(entry: VaultEntry, onClick: () -> Unit) {
    val o = entry.overview
    ListItem(
        headlineContent = { Text(o.title, maxLines = 1) },
        supportingContent = { Text(o.subtitle?.let { storedLabelText(it) } ?: o.kind.labelText(), maxLines = 1) },
        leadingContent = { Avatar(initialOf(o.title), o.kind.avatarColor()) },
        trailingContent = if (o.favorite) {
            { Icon(Icons.Filled.Star, contentDescription = stringResource(R.string.vault_list_favorite), tint = MaterialTheme.colorScheme.tertiary) }
        } else {
            null
        },
        modifier = Modifier.clickable(onClick = onClick),
    )
}

@Composable
private fun EmptyState(title: String, body: String) {
    Box(Modifier.fillMaxSize().padding(32.dp), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium)
            Text(body, textAlign = TextAlign.Center, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

/**
 * Rows that could not be decrypted (ID-INT-06). They are not deleted or modified: they stay in
 * storage and in every backup, so a good copy of this vault can still repair them.
 */
@Composable
private fun UnreadableBanner(count: Int, modifier: Modifier = Modifier) {
    if (count == 0) return
    Card(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
    ) {
        ListItem(
            headlineContent = {
                Text(pluralStringResource(R.plurals.vault_list_unreadable_title, count, count))
            },
            supportingContent = {
                Text(stringResource(R.string.vault_list_unreadable_body))
            },
            leadingContent = { Icon(Icons.Filled.Warning, contentDescription = null, tint = MaterialTheme.colorScheme.error) },
            colors = ListItemDefaults.colors(containerColor = MaterialTheme.colorScheme.errorContainer),
        )
    }
}
