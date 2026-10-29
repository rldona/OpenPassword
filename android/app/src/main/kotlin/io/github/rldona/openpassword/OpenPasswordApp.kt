package io.github.rldona.openpassword

import android.app.ActivityManager
import android.app.Application
import android.content.Context
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import io.github.rldona.openpassword.core.KdfProfile
import io.github.rldona.openpassword.data.VaultStorage
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
        )
        ProcessLifecycleOwner.get().lifecycle.addObserver(object : DefaultLifecycleObserver {
            override fun onStart(owner: LifecycleOwner) = session.onAppForegrounded()
            override fun onStop(owner: LifecycleOwner) = session.onAppBackgrounded()
        })
    }
}

/** 256 MiB of Argon2id memory, or 64 MiB on devices with less than 3 GB of RAM. */
private fun kdfProfileFor(context: Context): KdfProfile {
    val am = context.getSystemService(ActivityManager::class.java)
    val info = ActivityManager.MemoryInfo().also(am::getMemoryInfo)
    return if (am.isLowRamDevice || info.totalMem < 3L * 1024 * 1024 * 1024) KdfProfile.MINIMUM else KdfProfile.RECOMMENDED
}
