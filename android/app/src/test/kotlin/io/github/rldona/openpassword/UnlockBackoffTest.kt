package io.github.rldona.openpassword

import io.github.rldona.openpassword.session.VaultSession.Companion.unlockWaitSeconds
import org.junit.Assert.assertEquals
import org.junit.Test

class UnlockBackoffTest {
    @Test
    fun firstFourFailuresAreFree() {
        for (f in 0 until 4) assertEquals(0, unlockWaitSeconds(f, 0))
    }

    @Test
    fun waitDoublesFrom30Seconds() {
        assertEquals(30, unlockWaitSeconds(4, 0))
        assertEquals(60, unlockWaitSeconds(5, 0))
        assertEquals(120, unlockWaitSeconds(6, 0))
    }

    @Test
    fun waitIsCappedAtOneHour() {
        assertEquals(3600, unlockWaitSeconds(11, 0))
        assertEquals(3600, unlockWaitSeconds(100, 0))
    }

    @Test
    fun elapsedTimeCountsDownAndRoundsUp() {
        assertEquals(20, unlockWaitSeconds(4, 10_000))
        assertEquals(1, unlockWaitSeconds(4, 29_500))
        assertEquals(0, unlockWaitSeconds(4, 30_000))
        assertEquals(0, unlockWaitSeconds(4, 99_000))
    }
}
