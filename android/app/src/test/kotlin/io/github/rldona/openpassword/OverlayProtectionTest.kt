package io.github.rldona.openpassword

import io.github.rldona.openpassword.security.Obscured
import io.github.rldona.openpassword.security.obscuredTouch
import org.junit.Assert.assertEquals
import org.junit.Test

class OverlayProtectionTest {
    private val full = 0x1
    private val partial = 0x2

    private fun classify(flags: Int) = obscuredTouch(flags, full, partial)

    @Test fun noFlagsIsNone() = assertEquals(Obscured.NONE, classify(0))
    @Test fun unrelatedFlagsAreNone() = assertEquals(Obscured.NONE, classify(0x8 or 0x10))
    @Test fun fullFlag() = assertEquals(Obscured.FULL, classify(full))
    @Test fun partialFlag() = assertEquals(Obscured.PARTIAL, classify(partial))
    @Test fun fullWinsOverPartial() = assertEquals(Obscured.FULL, classify(full or partial))
    @Test fun unrelatedBitsDoNotHide() = assertEquals(Obscured.PARTIAL, classify(partial or 0x40))
}
