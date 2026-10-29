package io.github.rldona.openpassword.autofill

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.selection.toggleable
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.rldona.openpassword.OpenPasswordApp
import io.github.rldona.openpassword.core.ItemKindRecord
import io.github.rldona.openpassword.security.excludeFromAutofill
import io.github.rldona.openpassword.security.strongBiometricsAvailable
import io.github.rldona.openpassword.session.SessionState
import io.github.rldona.openpassword.session.VaultEntry
import io.github.rldona.openpassword.session.VaultSession
import io.github.rldona.openpassword.ui.Avatar
import io.github.rldona.openpassword.ui.SectionLabel
import io.github.rldona.openpassword.ui.initialOf
import io.github.rldona.openpassword.ui.theme.OpenPasswordTheme
import io.github.rldona.openpassword.ui.unlock.UnlockScreen
import io.github.rldona.openpassword.ui.unlock.biometricUnlock
import io.github.rldona.openpassword.ui.vault.avatarColor
import io.github.rldona.openpassword.ui.vault.searchKey
import kotlinx.coroutines.launch

/**
 * Opened from an autofill suggestion: unlocks the vault if needed and lets the user pick
 * the login to fill. Returns a Dataset to the autofill framework.
 */
class AutofillAuthActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) setRecentsScreenshotEnabled(false)
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        setResult(Activity.RESULT_CANCELED)

        val usernameId = extra<AutofillId>(Datasets.EXTRA_USERNAME_ID)
        val passwordId = extra<AutofillId>(Datasets.EXTRA_PASSWORD_ID)
        val target = intent.getStringExtra(Datasets.EXTRA_WEB_DOMAIN)?.let { FillTarget.Web(it) }
            ?: intent.getStringExtra(Datasets.EXTRA_PACKAGE)?.let { FillTarget.App(it) }
        if (target == null || (usernameId == null && passwordId == null)) {
            finish()
            return
        }
        val session = (application as OpenPasswordApp).session

        setContent {
            OpenPasswordTheme {
                val state by session.state.collectAsStateWithLifecycle()
                when (val s = state) {
                    SessionState.NoVault -> {
                        finish()
                    }
                    SessionState.Locked -> {
                        val context = LocalContext.current
                        val biometric = remember { session.canUseBiometricNow() && strongBiometricsAvailable(context) }
                        UnlockScreen(
                            onUnlock = session::unlock,
                            onBiometric = if (biometric) ({ biometricUnlock(context, session) }) else null,
                            notice = remember { session.passwordRequiredReason() },
                        )
                    }
                    is SessionState.Unlocked -> PickLogin(
                        entries = s.entries.filter { it.overview.kind == ItemKindRecord.LOGIN },
                        target = target,
                        session = session,
                        onPicked = { entry, credentials -> finishWith(usernameId, passwordId, entry, credentials) },
                        onCancel = ::finish,
                    )
                }
            }
        }
        excludeFromAutofill(this)
    }

    private fun finishWith(usernameId: AutofillId?, passwordId: AutofillId?, entry: VaultEntry, credentials: Credentials) {
        val dataset = Datasets.filled(this, usernameId, passwordId, Datasets.label(entry), credentials)
        setResult(Activity.RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, dataset))
        finish()
    }

    private inline fun <reified T : android.os.Parcelable> extra(name: String): T? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableExtra(name, T::class.java)
        } else {
            @Suppress("DEPRECATION")
            intent.getParcelableExtra(name)
        }

    companion object {
        fun intent(context: Context, request: LoginRequest): Intent =
            Datasets.toIntentExtras(Intent(context, AutofillAuthActivity::class.java), request)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun PickLogin(
    entries: List<VaultEntry>,
    target: FillTarget,
    session: VaultSession,
    onPicked: (VaultEntry, Credentials) -> Unit,
    onCancel: () -> Unit,
) {
    var query by remember { mutableStateOf("") }
    var remember by remember { mutableStateOf(true) }
    val scope = rememberCoroutineScope()
    val matching = remember(entries) { entries.filter { LoginMatcher.matches(it.overview.urls, target) } }
    val others = remember(entries, query) {
        val key = query.searchKey().trim()
        entries.filter { it !in matching }
            .filter { e -> key.isEmpty() || listOfNotNull(e.overview.title, e.overview.subtitle, *e.overview.urls.toTypedArray()).any { it.searchKey().contains(key) } }
            .sortedBy { it.overview.title.lowercase() }
    }
    val where = when (target) {
        is FillTarget.Web -> target.domain
        is FillTarget.App -> target.packageName
    }

    fun pick(entry: VaultEntry, isMatch: Boolean) {
        scope.launch {
            val details = session.details(entry)
            // Linking a login to an app: only for apps (package names are verified by Android).
            if (!isMatch && remember && target is FillTarget.App) {
                val urls = entry.overview.urls + LoginMatcher.appUrl(target.packageName)
                session.save(entry, entry.overview.copy(urls = urls, updatedAt = (System.currentTimeMillis() / 1000).toULong()), details)
            }
            onPicked(entry, details.credentials())
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Rellenar con OpenPassword") },
                navigationIcon = { IconButton(onClick = onCancel) { Icon(Icons.Filled.Close, contentDescription = "Cancelar") } },
            )
        },
    ) { padding ->
        Column(Modifier.padding(padding).fillMaxSize()) {
            Text(
                "Para: $where",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 16.dp),
            )
            LazyColumn(Modifier.fillMaxSize()) {
                if (matching.isNotEmpty()) {
                    item { SectionLabel("Coinciden", Modifier.padding(start = 16.dp, top = 16.dp, bottom = 4.dp)) }
                    items(matching, key = { "m" + it.id }) { LoginRow(it) { pick(it, isMatch = true) } }
                }
                item {
                    Column(Modifier.padding(horizontal = 16.dp, vertical = 12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        SectionLabel(if (matching.isEmpty()) "Elige un login" else "Otros logins")
                        OutlinedTextField(
                            value = query,
                            onValueChange = { query = it },
                            placeholder = { Text("Buscar") },
                            leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                        )
                        if (target is FillTarget.App) {
                            Row(
                                Modifier.fillMaxWidth().toggleable(value = remember, role = Role.Checkbox, onValueChange = { remember = it }),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Checkbox(checked = remember, onCheckedChange = null)
                                Text("Recordar el login elegido para esta app", Modifier.padding(start = 12.dp))
                            }
                        } else if (matching.isEmpty()) {
                            Text(
                                "Ningún login tiene guardado $where. Comprueba que es el sitio que esperas antes de rellenar.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.tertiary,
                            )
                        }
                    }
                }
                items(others, key = { "o" + it.id }) { LoginRow(it) { pick(it, isMatch = false) } }
            }
        }
    }
}

@Composable
private fun LoginRow(entry: VaultEntry, onClick: () -> Unit) {
    ListItem(
        headlineContent = { Text(entry.overview.title, maxLines = 1) },
        supportingContent = { Text(entry.overview.subtitle ?: entry.overview.urls.firstOrNull().orEmpty(), maxLines = 1) },
        leadingContent = { Avatar(initialOf(entry.overview.title), entry.overview.kind.avatarColor()) },
        modifier = Modifier.clickable(onClick = onClick),
    )
}
