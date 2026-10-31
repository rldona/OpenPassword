package io.github.rldona.openpassword.health

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.github.rldona.openpassword.R
import io.github.rldona.openpassword.session.VaultEntry
import io.github.rldona.openpassword.ui.Avatar
import io.github.rldona.openpassword.ui.SectionLabel
import io.github.rldona.openpassword.ui.initialOf
import io.github.rldona.openpassword.ui.vault.avatarColor

/** Notice at the top of the vault list. Only shown when something needs attention. */
@Composable
fun HealthBanner(report: HealthReport, onClick: () -> Unit, modifier: Modifier = Modifier) {
    if (report.isClean) return
    val res = LocalContext.current.resources
    Card(
        onClick = onClick,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.tertiaryContainer),
        modifier = modifier.fillMaxWidth(),
    ) {
        ListItem(
            headlineContent = {
                Text(pluralStringResource(R.plurals.health_banner_attention, report.affected, report.affected))
            },
            supportingContent = { Text(summary(report, res)) },
            leadingContent = { Icon(Icons.Filled.Warning, contentDescription = null, tint = MaterialTheme.colorScheme.tertiary) },
            colors = androidx.compose.material3.ListItemDefaults.colors(containerColor = MaterialTheme.colorScheme.tertiaryContainer),
        )
    }
}

private fun summary(r: HealthReport, res: android.content.res.Resources): String = listOfNotNull(
    r.reusedIds.size.takeIf { it > 0 }?.let { res.getString(R.string.health_summary_reused, it) },
    r.weak.size.takeIf { it > 0 }?.let { res.getQuantityString(R.plurals.health_summary_weak, it, it) },
    (r.expiredCards.size + r.expiringCards.size).takeIf { it > 0 }?.let {
        res.getQuantityString(R.plurals.health_summary_cards, it, it)
    },
    (r.expiredDocuments.size + r.expiringDocuments.size).takeIf { it > 0 }?.let {
        res.getQuantityString(R.plurals.health_summary_documents, it, it)
    },
    r.old.size.takeIf { it > 0 }?.let { res.getString(R.string.health_summary_old, it) },
).joinToString(" · ")

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HealthScreen(report: HealthReport, entries: List<VaultEntry>, onOpen: (VaultEntry) -> Unit, onBack: () -> Unit) {
    val byId = entries.associateBy { it.id }
    val res = LocalContext.current.resources
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.health_title)) },
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.item_detail_back)) } },
            )
        },
    ) { padding ->
        LazyColumn(Modifier.padding(padding).fillMaxSize(), contentPadding = PaddingValues(bottom = 32.dp)) {
            item {
                Text(
                    stringResource(R.string.health_intro),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 16.dp),
                )
            }
            if (report.isClean) {
                item {
                    Column(Modifier.fillMaxWidth().padding(32.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(stringResource(R.string.health_all_clear_title), style = MaterialTheme.typography.titleMedium)
                        Text(stringResource(R.string.health_all_clear_body), color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
            if (report.reused.isNotEmpty()) {
                section(res.getString(R.string.health_reused_title), res.getString(R.string.health_reused_body))
                report.reused.forEachIndexed { i, group ->
                    item { SectionLabel(pluralStringResource(R.plurals.health_reused_group, group.size, group.size), Modifier.padding(start = 16.dp, top = 8.dp)) }
                    items(group.mapNotNull(byId::get), key = { "r$i-" + it.id }) { EntryRow(it, onOpen) }
                }
            }
            if (report.weak.isNotEmpty()) {
                section(res.getString(R.string.health_weak_title), res.getString(R.string.health_weak_body))
                items(report.weak.mapNotNull(byId::get), key = { "w" + it.id }) { EntryRow(it, onOpen) }
            }
            if (report.expiredCards.isNotEmpty()) {
                section(res.getString(R.string.health_expired_cards_title), res.getString(R.string.health_expired_cards_body))
                items(report.expiredCards.mapNotNull(byId::get), key = { "x" + it.id }) { EntryRow(it, onOpen) }
            }
            if (report.expiringCards.isNotEmpty()) {
                section(res.getString(R.string.health_expiring_cards_title), res.getString(R.string.health_expiring_cards_body, VaultHealth.EXPIRING_MONTHS))
                items(report.expiringCards.mapNotNull(byId::get), key = { "s" + it.id }) { EntryRow(it, onOpen) }
            }
            if (report.expiredDocuments.isNotEmpty()) {
                section(res.getString(R.string.health_expired_documents_title), res.getString(R.string.health_expired_documents_body))
                items(report.expiredDocuments.mapNotNull(byId::get), key = { "dx" + it.id }) { EntryRow(it, onOpen) }
            }
            if (report.expiringDocuments.isNotEmpty()) {
                section(res.getString(R.string.health_expiring_documents_title), res.getString(R.string.health_expiring_documents_body, VaultHealth.DOCUMENT_EXPIRING_MONTHS))
                items(report.expiringDocuments.mapNotNull(byId::get), key = { "ds" + it.id }) { EntryRow(it, onOpen) }
            }
            if (report.old.isNotEmpty()) {
                section(res.getString(R.string.health_old_title), res.getString(R.string.health_old_body, VaultHealth.OLD_AFTER_DAYS))
                items(report.old.mapNotNull(byId::get), key = { "o" + it.id }) { EntryRow(it, onOpen) }
            }
        }
    }
}

private fun androidx.compose.foundation.lazy.LazyListScope.section(title: String, body: String) {
    item {
        Column(Modifier.padding(start = 16.dp, end = 16.dp, top = 24.dp, bottom = 4.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium)
            Text(body, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun EntryRow(entry: VaultEntry, onOpen: (VaultEntry) -> Unit) {
    ListItem(
        headlineContent = { Text(entry.overview.title, maxLines = 1) },
        supportingContent = { entry.overview.subtitle?.let { Text(it, maxLines = 1) } },
        leadingContent = { Avatar(initialOf(entry.overview.title), entry.overview.kind.avatarColor(), size = 36.dp) },
        modifier = Modifier.clickable { onOpen(entry) },
    )
}
