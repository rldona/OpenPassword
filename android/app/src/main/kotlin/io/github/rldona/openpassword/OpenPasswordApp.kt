package io.github.rldona.openpassword

import android.app.ActivityManager
import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.provider.Settings
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import io.github.rldona.openpassword.core.KdfProfile
import io.github.rldona.openpassword.data.VaultStorage
import io.github.rldona.openpassword.security.BiometricKeyStore
import io.github.rldona.openpassword.security.SensitiveClipboard
import io.github.rldona.openpassword.session.VaultSession

class OpenPasswordApp : Application() {
    lateinit var session: VaultSession
        private set
    lateinit var clipboard: SensitiveClipboard
        private set

    override fun onCreate() {
        super.onCreate()
        clipboard = SensitiveClipboard(this)
        session = VaultSession(
            storage = VaultStorage(this),
            prefs = getSharedPreferences("security", MODE_PRIVATE),
            kdfProfile = kdfProfileFor(this),
            biometricKeys = BiometricKeyStore(),
            bootCount = { Settings.Global.getInt(contentResolver, Settings.Global.BOOT_COUNT, 0) },
        )
        ProcessLifecycleOwner.get().lifecycle.addObserver(object : DefaultLifecycleObserver {
            override fun onStart(owner: LifecycleOwner) = session.onAppForegrounded()
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
