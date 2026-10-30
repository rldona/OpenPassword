package io.github.rldona.openpassword

import io.github.rldona.openpassword.session.AttemptLimiter
import io.github.rldona.openpassword.session.AttemptStore
import org.junit.Assert.assertEquals
import org.junit.Test

/** ID-INT-09: unlock and verifyPassword share one counter and one wait. */
class AttemptLimiterTest {
    private class MemoryStore : AttemptStore {
        override var failures = 0
        override var lastFailureAt = 0L
        override fun write(failures: Int, lastFailureAt: Long) {
            this.failures = failures
            this.lastFailureAt = lastFailureAt
        }
    }

    private var clock = 1_000_000L
    private val store = MemoryStore()
    private val limiter = AttemptLimiter(store) { clock }

    @Test
    fun `four failures are free then the wait starts at 30 seconds`() {
        repeat(3) { limiter.recordFailure() }
        assertEquals(0, limiter.remainingWait())
        limiter.recordFailure()
        assertEquals(30, limiter.remainingWait())
    }

    @Test
    fun `the wait counts down with the clock`() {
        repeat(4) { limiter.recordFailure() }
        clock += 10_000
        assertEquals(20, limiter.remainingWait())
        clock += 20_000
        assertEquals(0, limiter.remainingWait())
    }

    @Test
    fun `a second caller on the same store sees the failures of the first`() {
        val unlock = AttemptLimiter(store) { clock }
        val verify = AttemptLimiter(store) { clock }
        repeat(2) { unlock.recordFailure() }
        repeat(2) { verify.recordFailure() }
        assertEquals(4, store.failures)
        assertEquals(30, unlock.remainingWait())
        assertEquals(30, verify.remainingWait())
    }

    @Test
    fun `a success clears the failures`() {
        repeat(5) { limiter.recordFailure() }
        limiter.recordSuccess()
        assertEquals(0, store.failures)
        assertEquals(0, limiter.remainingWait())
    }

    @Test
    fun `the wait doubles with each further failure`() {
        repeat(5) { limiter.recordFailure() }
        assertEquals(60, limiter.remainingWait())
    }
}
