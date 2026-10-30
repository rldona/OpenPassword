package io.github.rldona.openpassword

import io.github.rldona.openpassword.core.OpException
import io.github.rldona.openpassword.session.KeyHolder
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** ID-INT-08: lock() races with an operation in flight. A fake plays the native vault. */
class KeyHolderTest {
    private class FakeVault {
        @Volatile var wiped = false
        var wipes = 0
        /** What the generated binding does after close(): throw IllegalStateException. */
        fun call(): String {
            check(!wiped) { "object has already been destroyed" }
            return "ok"
        }
    }

    private fun holder() = KeyHolder<FakeVault> { it.wipes++; it.wiped = true }

    @Test
    fun `after lock the key cannot be obtained any more`() {
        val h = holder()
        val v = FakeVault()
        h.replace(v)
        assertTrue(h.lock())
        assertNull(h.current())
        assertTrue(v.wiped)
        assertTrue(runCatching { h.use { it.call() } }.exceptionOrNull() is OpException.Locked)
    }

    @Test
    fun `lock is idempotent and wipes once`() {
        val h = holder()
        val v = FakeVault()
        h.replace(v)
        assertTrue(h.lock())
        assertFalse(h.lock())
        assertEquals(1, v.wipes)
    }

    @Test
    fun `replace wipes the previous vault`() {
        val h = holder()
        val old = FakeVault()
        val next = FakeVault()
        h.replace(old)
        h.replace(next)
        assertTrue(old.wiped)
        assertFalse(next.wiped)
        assertEquals("ok", h.use { it.call() })
    }

    @Test
    fun `an operation in flight ends with Locked, not with IllegalStateException`() {
        val h = holder()
        h.replace(FakeVault())
        val error = runCatching {
            h.use { v ->
                v.call()
                h.lock() // the autolock fires between two native calls
                v.call()
            }
        }.exceptionOrNull()
        assertTrue("was $error", error is OpException.Locked)
    }

    @Test
    fun `lock from another thread during an operation`() {
        val h = holder()
        h.replace(FakeVault())
        val inside = CountDownLatch(1)
        val locked = CountDownLatch(1)
        val outcome = AtomicReference<Throwable?>()
        val worker = thread {
            outcome.set(runCatching {
                h.use { v ->
                    v.call()
                    inside.countDown()
                    locked.await(5, TimeUnit.SECONDS)
                    v.call()
                }
            }.exceptionOrNull())
        }
        assertTrue(inside.await(5, TimeUnit.SECONDS))
        h.lock() // returns without waiting for the operation
        assertNull(h.current())
        locked.countDown()
        worker.join(5_000)
        assertTrue("was ${outcome.get()}", outcome.get() is OpException.Locked)
    }

    @Test
    fun `an unrelated IllegalStateException is not hidden while the vault is still live`() {
        val h = holder()
        h.replace(FakeVault())
        try {
            h.use { error("a real bug") }
            fail("expected a throw")
        } catch (e: IllegalStateException) {
            assertEquals("a real bug", e.message)
        }
    }

    @Test
    fun `other exceptions pass through untouched`() {
        val h = holder()
        h.replace(FakeVault())
        val original = OpException.Corrupted()
        assertTrue(runCatching { h.use { throw original } }.exceptionOrNull() === original)
    }
}
