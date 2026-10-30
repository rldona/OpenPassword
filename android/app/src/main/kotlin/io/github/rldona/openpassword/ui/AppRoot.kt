package io.github.rldona.openpassword.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.rldona.openpassword.backup.AutoBackup
import io.github.rldona.openpassword.core.ItemKindRecord
import io.github.rldona.openpassword.health.HealthReport
import io.github.rldona.openpassword.health.HealthScreen
import io.github.rldona.openpassword.security.SensitiveClipboard
import io.github.rldona.openpassword.security.strongBiometricsAvailable
import io.github.rldona.openpassword.session.SessionState
import io.github.rldona.openpassword.session.VaultEntry
import io.github.rldona.openpassword.session.VaultSession
import io.github.rldona.openpassword.ui.onboarding.OnboardingScreen
import io.github.rldona.openpassword.ui.settings.SettingsScreen
import io.github.rldona.openpassword.ui.unlock.UnlockScreen
import io.github.rldona.openpassword.ui.unlock.biometricUnlock
import io.github.rldona.openpassword.ui.vault.ItemDetailScreen
import io.github.rldona.openpassword.ui.vault.ItemEditorScreen
import io.github.rldona.openpassword.ui.vault.VaultListScreen

private sealed interface Screen {
    data object List : Screen
    data class Detail(val id: String) : Screen
    data class Edit(val id: String?, val kind: ItemKindRecord) : Screen
    data object Settings : Screen
    data object Health : Screen
}

@Composable
fun AppRoot(session: VaultSession, clipboard: SensitiveClipboard, autoBackup: AutoBackup) {
    val state by session.state.collectAsStateWithLifecycle()
    Box {
        AppContent(state, session, clipboard, autoBackup)
        OverlayWarningBanner(Modifier.align(Alignment.TopCenter).statusBarsPadding())
    }
}

@Composable
private fun AppContent(state: SessionState, session: VaultSession, clipboard: SensitiveClipboard, autoBackup: AutoBackup) {
    when (val s = state) {
        SessionState.NoVault -> OnboardingScreen(onCreate = session::create, onRestore = session::restore)
        SessionState.Locked -> {
            val context = LocalContext.current
            // Re-evaluated every time the vault locks.
            val biometric = remember { session.canUseBiometricNow() && strongBiometricsAvailable(context) }
            UnlockScreen(
                onUnlock = session::unlock,
                onBiometric = if (biometric) ({ biometricUnlock(context, session) }) else null,
                notice = remember { session.passwordRequiredReason() },
            )
        }
        // Leaving this branch on lock discards the whole navigation stack and every decrypted value in it.
        is SessionState.Unlocked -> UnlockedRoot(s.entries, session, clipboard, autoBackup)
    }
}

@Composable
private fun UnlockedRoot(entries: List<VaultEntry>, session: VaultSession, clipboard: SensitiveClipboard, autoBackup: AutoBackup) {
    var stack by remember { mutableStateOf(listOf<Screen>(Screen.List)) }
    fun push(screen: Screen) { stack = stack + screen }
    fun pop() { stack = stack.dropLast(1) }
    fun replaceTop(screen: Screen) { stack = stack.dropLast(1) + screen }
    fun find(id: String) = entries.firstOrNull { it.id == id }

    BackHandler(enabled = stack.size > 1) { pop() }
    // Recomputed whenever items change. Offline, and only while unlocked.
    val health by produceState(HealthReport.EMPTY, entries) { value = runCatching { session.healthReport() }.getOrDefault(HealthReport.EMPTY) }

    when (val top = stack.last()) {
        Screen.List -> VaultListScreen(
            entries = entries,
            onOpen = { push(Screen.Detail(it.id)) },
            onAdd = { push(Screen.Edit(null, it)) },
            onLock = session::lock,
            onSettings = { push(Screen.Settings) },
            health = health,
            onHealth = { push(Screen.Health) },
        )
        is Screen.Detail -> find(top.id)?.let { entry ->
            ItemDetailScreen(
                entry = entry,
                session = session,
                clipboard = clipboard,
                onBack = ::pop,
                onEdit = { push(Screen.Edit(entry.id, entry.overview.kind)) },
                onDeleted = ::pop,
            )
        } ?: LaunchedEffect(top) { pop() }
        is Screen.Edit -> ItemEditorScreen(
            existing = top.id?.let(::find),
            kind = top.kind,
            session = session,
            onSaved = { saved ->
                if (top.id == null) replaceTop(Screen.Detail(saved.id)) else pop()
            },
            onCancel = ::pop,
        )
        Screen.Health -> HealthScreen(health, entries, onOpen = { push(Screen.Detail(it.id)) }, onBack = ::pop)
        Screen.Settings -> SettingsScreen(session = session, autoBackup = autoBackup, onBack = ::pop)
    }
}
