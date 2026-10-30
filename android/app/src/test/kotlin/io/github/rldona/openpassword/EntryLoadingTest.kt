package io.github.rldona.openpassword

import io.github.rldona.openpassword.core.EncryptedItemRecord
import io.github.rldona.openpassword.core.InternalException
import io.github.rldona.openpassword.core.ItemKindRecord
import io.github.rldona.openpassword.core.ItemOverviewRecord
import io.github.rldona.openpassword.core.OpException
import io.github.rldona.openpassword.session.loadEntries
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** ID-INT-06: one damaged row must not lock the user out of the others. */
class EntryLoadingTest {
    private fun record(id: String) = EncryptedItemRecord(id, 1uL, ByteArray(0), ByteArray(0), ByteArray(0))
    private fun overview(title: String) = ItemOverviewRecord(ItemKindRecord.LOGIN, title, null, emptyList(), emptyList(), false, 0uL, 0uL)

    @Test
    fun `a corrupted row is skipped and reported, the rest loads`() {
        val loaded = loadEntries(listOf(record("a"), record("bad"), record("c"))) {
            if (it.id == "bad") throw OpException.Corrupted() else overview(it.id)
        }
        assertEquals(listOf("a", "c"), loaded.entries.map { it.id })
        assertEquals(listOf("bad"), loaded.unreadable)
    }

    @Test
    fun `all rows readable gives no unreadable ids`() {
        val loaded = loadEntries(listOf(record("a"), record("b"))) { overview(it.id) }
        assertEquals(2, loaded.entries.size)
        assertTrue(loaded.unreadable.isEmpty())
    }

    @Test
    fun `every row corrupted still opens an empty list`() {
        val loaded = loadEntries(listOf(record("a"), record("b"))) { throw OpException.Corrupted() }
        assertTrue(loaded.entries.isEmpty())
        assertEquals(listOf("a", "b"), loaded.unreadable)
    }

    @Test
    fun `a panic or a locked vault still aborts the load`() {
        assertTrue(runCatching { loadEntries(listOf(record("a"))) { throw InternalException("panic") } }.exceptionOrNull() is InternalException)
        assertTrue(runCatching { loadEntries(listOf(record("a"))) { throw OpException.Locked() } }.exceptionOrNull() is OpException.Locked)
    }
}
