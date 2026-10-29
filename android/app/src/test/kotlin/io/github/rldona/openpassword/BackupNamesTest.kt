package io.github.rldona.openpassword

import io.github.rldona.openpassword.backup.BackupNames
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.LocalDateTime

class BackupNamesTest {
    private fun at(day: Int, hour: Int = 12) = BackupNames.nameFor(LocalDateTime.of(2026, 10, day, hour, 0, 0))

    @Test
    fun namesSortByTime() {
        assertEquals("openpassword-auto-20261029-213005.opvault", BackupNames.nameFor(LocalDateTime.of(2026, 10, 29, 21, 30, 5)))
        assertTrue(at(1) < at(2) && at(2, 9) < at(2, 10))
    }

    @Test
    fun keepsTheNewestAndDeletesTheRest() {
        val names = (1..14).map { at(it) }.shuffled()
        val deleted = BackupNames.toDelete(names, keep = 10)
        assertEquals((1..4).map { at(it) }.toSet(), deleted.toSet())
    }

    @Test
    fun neverTouchesOtherFiles() {
        val others = listOf(
            "openpassword-2026-10-29.opvault", // manual export
            "openpassword-kit-de-emergencia.pdf",
            "openpassword-auto-20261001-120000.opvault.bak",
            "copia openpassword-auto-20261001-120000.opvault",
            "openpassword-auto-20261001-120000 (1).opvault",
            "fotos.zip",
        )
        val names = others + (1..12).map { at(it) }
        val deleted = BackupNames.toDelete(names, keep = 10)
        assertEquals(2, deleted.size)
        assertTrue(deleted.none { it in others })
        others.forEach { assertFalse(it, BackupNames.isAutomatic(it)) }
    }

    @Test
    fun alwaysKeepsAtLeastOne() {
        assertEquals(listOf(at(1)), BackupNames.toDelete(listOf(at(1), at(2)), keep = 0))
        assertTrue(BackupNames.toDelete(listOf(at(1)), keep = 10).isEmpty())
    }
}
