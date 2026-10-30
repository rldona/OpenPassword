package io.github.rldona.openpassword

import io.github.rldona.openpassword.security.DeviceProbe
import io.github.rldona.openpassword.security.RootDetector
import io.github.rldona.openpassword.security.RootSignal
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RootDetectorTest {
    private class FakeProbe(
        val files: Set<String> = emptySet(),
        val packages: Set<String> = emptySet(),
        override val buildTags: String? = "release-keys",
        override val buildType: String = "user",
    ) : DeviceProbe {
        override fun fileExists(path: String) = path in files
        override fun packageInstalled(name: String) = name in packages
    }

    @Test fun cleanDeviceHasNoSignals() = assertEquals(emptySet<RootSignal>(), RootDetector.evaluate(FakeProbe()))

    @Test fun nullTagsAreNotASignal() = assertEquals(emptySet<RootSignal>(), RootDetector.evaluate(FakeProbe(buildTags = null)))

    @Test fun everySuPathIsDetected() {
        RootDetector.SU_PATHS.forEach {
            assertEquals(setOf(RootSignal.SU_BINARY), RootDetector.evaluate(FakeProbe(files = setOf(it))))
        }
    }

    @Test fun everyRootManagerPackageIsDetected() {
        RootDetector.ROOT_PACKAGES.forEach {
            assertEquals(setOf(RootSignal.ROOT_MANAGER_APP), RootDetector.evaluate(FakeProbe(packages = setOf(it))))
        }
    }

    @Test fun unrelatedFilesAndPackagesAreIgnored() {
        assertTrue(RootDetector.evaluate(FakeProbe(files = setOf("/system/bin/sh"), packages = setOf("com.android.chrome"))).isEmpty())
    }

    @Test fun testKeysInsideOtherTags() {
        assertEquals(setOf(RootSignal.TEST_KEYS), RootDetector.evaluate(FakeProbe(buildTags = "dev-keys,test-keys")))
    }

    @Test fun userdebugAndEngAreDebugBuilds() {
        listOf("userdebug", "eng").forEach {
            assertEquals(setOf(RootSignal.DEBUG_BUILD), RootDetector.evaluate(FakeProbe(buildType = it)))
        }
    }

    @Test fun signalsCombine() {
        val s = RootDetector.evaluate(FakeProbe(files = setOf("/sbin/su"), packages = setOf("com.topjohnwu.magisk")))
        assertEquals(setOf(RootSignal.SU_BINARY, RootSignal.ROOT_MANAGER_APP), s)
    }

    /** Known false positive: an unrooted development emulator image looks like a debug build. */
    @Test fun developmentEmulatorIsAKnownFalsePositive() {
        val s = RootDetector.evaluate(FakeProbe(buildTags = "test-keys", buildType = "userdebug"))
        assertEquals(setOf(RootSignal.TEST_KEYS, RootSignal.DEBUG_BUILD), s)
    }

    @Test fun noticeReturnsOnlyWhenTheSignalsChange() {
        val one = setOf(RootSignal.TEST_KEYS)
        assertFalse(RootDetector.shouldWarn(emptySet(), emptySet()))
        assertTrue(RootDetector.shouldWarn(one, emptySet()))
        assertFalse(RootDetector.shouldWarn(one, setOf("TEST_KEYS")))
        assertTrue(RootDetector.shouldWarn(one + RootSignal.SU_BINARY, setOf("TEST_KEYS")))
    }
}
