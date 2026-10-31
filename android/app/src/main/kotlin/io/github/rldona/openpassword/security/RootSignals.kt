package io.github.rldona.openpassword.security

/** What the detector can see of the device. Real implementation: [AndroidDeviceProbe]. */
interface DeviceProbe {
    fun fileExists(path: String): Boolean
    fun packageInstalled(name: String): Boolean
    val buildTags: String?
    val buildType: String
}

enum class RootSignal { SU_BINARY, ROOT_MANAGER_APP, TEST_KEYS, DEBUG_BUILD }

/**
 * Local, offline heuristics. Easy to evade (hidden Magisk) and prone to false positives
 * (custom ROMs, emulators), so the result is only ever shown as a notice, never as a block.
 */
object RootDetector {
    val SU_PATHS = listOf(
        "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
        "/data/local/xbin/su", "/data/local/bin/su", "/system/sd/xbin/su", "/vendor/bin/su",
        "/data/adb/magisk", "/data/adb/ksu",
    )

    /** Also declared in the manifest `<queries>` block: keep both lists in sync. */
    val ROOT_PACKAGES = listOf(
        "com.topjohnwu.magisk", "me.weishu.kernelsu", "eu.chainfire.supersu",
        "com.koushikdutta.superuser", "com.noshufou.android.su", "com.kingroot.kinguser",
    )

    val DEBUG_BUILD_TYPES = setOf("userdebug", "eng")

    fun evaluate(probe: DeviceProbe): Set<RootSignal> = buildSet {
        if (SU_PATHS.any(probe::fileExists)) add(RootSignal.SU_BINARY)
        if (ROOT_PACKAGES.any(probe::packageInstalled)) add(RootSignal.ROOT_MANAGER_APP)
        if (probe.buildTags?.contains("test-keys") == true) add(RootSignal.TEST_KEYS)
        if (probe.buildType in DEBUG_BUILD_TYPES) add(RootSignal.DEBUG_BUILD)
    }

    /** Show the notice unless the user already dismissed it for this exact set of signals. */
    fun shouldWarn(signals: Set<RootSignal>, dismissed: Set<String>): Boolean =
        signals.isNotEmpty() && signals.map { it.name }.toSet() != dismissed
}
