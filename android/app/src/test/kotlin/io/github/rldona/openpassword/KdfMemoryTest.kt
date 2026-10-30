package io.github.rldona.openpassword

import io.github.rldona.openpassword.session.kdfMemoryFits
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class KdfMemoryTest {
    private val gib = 1024L * 1024 * 1024

    @Test
    fun exactlyHalfOfTheRamFits() {
        assertTrue(kdfMemoryFits(524_288u, 1 * gib))
    }

    @Test
    fun oneKibAboveHalfDoesNotFit() {
        assertFalse(kdfMemoryFits(524_289u, 1 * gib))
    }

    @Test
    fun recommendedProfileFitsInAnyDeviceThatCanRunIt() {
        assertTrue(kdfMemoryFits(262_144u, 3 * gib))
        assertFalse(kdfMemoryFits(262_144u, 256L * 1024 * 1024))
    }

    @Test
    fun formatMaximumNeedsMoreThanFourGibOfRam() {
        assertTrue(kdfMemoryFits(2_097_152u, 4 * gib))
        assertFalse(kdfMemoryFits(2_097_152u, 4 * gib - 2))
    }

    @Test
    fun largeValuesDoNotOverflow() {
        assertFalse(kdfMemoryFits(UInt.MAX_VALUE, 8 * gib))
        assertTrue(kdfMemoryFits(UInt.MAX_VALUE, Long.MAX_VALUE))
    }

    @Test
    fun zeroRamFitsNothing() {
        assertFalse(kdfMemoryFits(1u, 0))
    }
}
