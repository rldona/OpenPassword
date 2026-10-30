package io.github.rldona.openpassword

import io.github.rldona.openpassword.core.InternalException
import io.github.rldona.openpassword.core.OpException
import io.github.rldona.openpassword.session.VaultSession
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class FfiFailureHandlingTest {
    @Test
    fun `an internal exception always degrades the session`() {
        assertTrue(VaultSession.shouldLockAfter(InternalException("panic"), sessionUnlocked = true))
        assertTrue(VaultSession.shouldLockAfter(InternalException("panic"), sessionUnlocked = false))
    }

    @Test
    fun `Locked is unexpected only while the session claims to be unlocked`() {
        assertTrue(VaultSession.shouldLockAfter(OpException.Locked(), sessionUnlocked = true))
        assertFalse(VaultSession.shouldLockAfter(OpException.Locked(), sessionUnlocked = false))
    }

    @Test
    fun `ordinary errors do not lock the session`() {
        assertFalse(VaultSession.shouldLockAfter(OpException.Corrupted(), sessionUnlocked = true))
        assertFalse(VaultSession.shouldLockAfter(IllegalStateException("x"), sessionUnlocked = true))
    }

    /**
     * Every `catch (e: OpException)` in the app must have, in the same try, a catch of
     * InternalException or Exception: a Rust panic arrives as InternalException and would
     * otherwise crash the coroutine. Same check as the grep in docs/audit/decisions.md (ADR-AUD-03).
     */
    @Test
    fun `every OpException catch also handles InternalException`() {
        val root = File("src/main/kotlin")
        assertTrue("run from the app module: ${File(".").absolutePath}", root.isDirectory)
        val broad = Regex("""catch \((\w+): (InternalException|Exception|Throwable)\)""")
        val offenders = root.walkTopDown()
            .filter { it.extension == "kt" }
            .flatMap { file ->
                val lines = file.readLines()
                lines.indices
                    .filter { Regex("""catch \((\w+): OpException\)""").containsMatchIn(lines[it]) }
                    .filter { i -> lines.subList(i, minOf(i + 25, lines.size)).none { broad.containsMatchIn(it) } }
                    .map { "${file.name}:${it + 1}" }
            }.toList()
        assertEquals(emptyList<String>(), offenders)
    }

    @Test
    fun `a failure after opening the vault releases it and rethrows`() {
        var released = 0
        val failures = listOf(OpException.Corrupted(), InternalException("panic"), IllegalStateException("x"))
        for (failure in failures) {
            val thrown = runCatching { VaultSession.discardOnFailure({ released++ }) { throw failure } }.exceptionOrNull()
            assertTrue(thrown === failure)
        }
        assertEquals(failures.size, released)
    }

    @Test
    fun `a failing release does not hide the original error`() {
        val original = OpException.Corrupted()
        val thrown = runCatching {
            VaultSession.discardOnFailure({ throw IllegalStateException("close failed") }) { throw original }
        }.exceptionOrNull()
        assertTrue(thrown === original)
    }

    @Test
    fun `success does not release the vault`() {
        var released = 0
        assertEquals(7, VaultSession.discardOnFailure({ released++ }) { 7 })
        assertEquals(0, released)
    }
}
