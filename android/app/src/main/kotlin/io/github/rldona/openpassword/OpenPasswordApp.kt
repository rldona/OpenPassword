package io.github.rldona.openpassword

import android.app.ActivityManager
import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.provider.Settings
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import io.github.rldona.openpassword.autofill.PendingSaves
import io.github.rldona.openpassword.backup.AutoBackup
import io.github.rldona.openpassword.core.KdfProfile
import io.github.rldona.openpassword.data.VaultStorage
import io.github.rldona.openpassword.security.AndroidDeviceProbe
import io.github.rldona.openpassword.security.BiometricKeyStore
import io.github.rldona.openpassword.security.RootDetector
import io.github.rldona.openpassword.security.RootSignal
import io.github.rldona.openpassword.security.SensitiveClipboard
import io.github.rldona.openpassword.session.VaultSession
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class OpenPasswordApp : Application() {
    lateinit var session: VaultSession
        private set
    lateinit var clipboard: SensitiveClipboard
        private set
    lateinit var autoBackup: AutoBackup
        private set

    private val _rootSignals = MutableStateFlow<Set<RootSignal>>(emptySet())
    /** Heuristic root / debug-build signals, computed once at startup. Advisory only. */
    val rootSignals: StateFlow<Set<RootSignal>> = _rootSignals.asStateFlow()

    private val _rootWarningDismissed = MutableStateFlow<Set<String>>(emptySet())
    /** The signals the user already dismissed the notice for; a new signal shows it again. */
    val rootWarningDismissed: StateFlow<Set<String>> = _rootWarningDismissed.asStateFlow()

    fun dismissRootWarning() {
        val names = _rootSignals.value.map { it.name }.toSet()
        getSharedPreferences("device_warning", MODE_PRIVATE).edit().putStringSet("dismissed", names).apply()
        _rootWarningDismissed.value = names
    }

    override fun onCreate() {
        super.onCreate()
        _rootWarningDismissed.value = getSharedPreferences("device_warning", MODE_PRIVATE).getStringSet("dismissed", emptySet()).orEmpty().toSet()
        val probe = AndroidDeviceProbe(this)
        MainScope().launch { _rootSignals.value = withContext(Dispatchers.IO) { RootDetector.evaluate(probe) } }
        clipboard = SensitiveClipboard(this, isForeground = {
            ProcessLifecycleOwner.get().lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)
        })
        // A copy may be pending from a process that died; this also re-arms its timer.
        clipboard.onForeground()
        session = VaultSession(
            storage = VaultStorage(this),
            prefs = getSharedPreferences("security", MODE_PRIVATE),
            kdfProfile = kdfProfileFor(this),
            biometricKeys = BiometricKeyStore(),
            bootCount = { Settings.Global.getInt(contentResolver, Settings.Global.BOOT_COUNT, 0) },
            totalMemory = { ActivityManager.MemoryInfo().also(getSystemService(ActivityManager::class.java)::getMemoryInfo).totalMem },
        )
        autoBackup = AutoBackup(this, session, getSharedPreferences("backup", MODE_PRIVATE), MainScope())
        session.onChanged = autoBackup::onVaultChanged
        session.onUnlocked = autoBackup::onUnlocked
        session.onLocked = PendingSaves::clear
        ProcessLifecycleOwner.get().lifecycle.addObserver(object : DefaultLifecycleObserver {
            override fun onStart(owner: LifecycleOwner) {
                session.onAppForegrounded()
                clipboard.onForeground()
            }
            override fun onStop(owner: LifecycleOwner) = session.onAppBackgrounded()
        })
        // For the whole process, not one activity: the vault can also be unlocked from the
        // autofill window, and must lock when the screen turns off whichever screen did it.
        registerReceiver(
            object : BroadcastReceiver() {
                override fun onReceive(context: Context, intent: Intent) {
                    session.lock()
                    clipboard.clearIfOurs()
                }
            },
            IntentFilter(Intent.ACTION_SCREEN_OFF),
        )
    }
}

/** 256 MiB of Argon2id memory, or 64 MiB on devices with less than 3 GB of RAM. */
private fun kdfProfileFor(context: Context): KdfProfile {
    val am = context.getSystemService(ActivityManager::class.java)
    val info = ActivityManager.MemoryInfo().also(am::getMemoryInfo)
    return if (am.isLowRamDevice || info.totalMem < 3L * 1024 * 1024 * 1024) KdfProfile.MINIMUM else KdfProfile.RECOMMENDED
}
