package io.github.rldona.openpassword.security

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.io.File

/** Reads the device only through public APIs: no processes, no reflection, no network. */
class AndroidDeviceProbe(context: Context) : DeviceProbe {
    private val packages = context.packageManager

    override fun fileExists(path: String): Boolean = File(path).exists()

    // Needs the matching <queries> entries in the manifest (package visibility, API 30+).
    override fun packageInstalled(name: String): Boolean =
        try {
            packages.getPackageInfo(name, 0)
            true
        } catch (_: PackageManager.NameNotFoundException) {
            false
        }

    override val buildTags: String? get() = Build.TAGS
    override val buildType: String get() = Build.TYPE
}
