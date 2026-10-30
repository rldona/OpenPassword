package io.github.rldona.openpassword

import io.github.rldona.openpassword.autofill.FillTarget
import io.github.rldona.openpassword.autofill.PendingSave
import io.github.rldona.openpassword.autofill.PendingStore
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

/** ID-INT-17: TTL, active purge and clearing on lock. */
class PendingStoreTest {
    private var clock = 0L
    private val store = PendingStore(ttlMs = 1_000, now = { clock })
    private fun save() = PendingSave(FillTarget.App("com.example"), "u", "p")

    @Test
    fun `an entry is available until the ttl`() {
        val token = store.put(save())
        clock = 1_000
        assertNotNull(store.peek(token))
        clock = 1_001
        assertNull(store.peek(token))
    }

    @Test
    fun `purge drops expired entries without any put or peek`() {
        store.put(save())
        clock = 5_000
        assertEquals(1, store.size())
        store.purge()
        assertEquals(0, store.size())
    }

    @Test
    fun `purge keeps entries that are still fresh`() {
        store.put(save())
        clock = 800
        val fresh = store.put(save())
        clock = 1_200
        store.purge()
        assertEquals(1, store.size())
        assertNotNull(store.peek(fresh))
    }

    @Test
    fun `clear empties everything, as when the vault locks`() {
        val a = store.put(save())
        store.put(save())
        store.clear()
        assertEquals(0, store.size())
        assertNull(store.peek(a))
    }

    @Test
    fun `remove drops one entry`() {
        val a = store.put(save())
        val b = store.put(save())
        store.remove(a)
        assertNull(store.peek(a))
        assertNotNull(store.peek(b))
    }

    @Test
    fun `tokens are unique`() {
        assertEquals(50, (1..50).map { store.put(save()) }.toSet().size)
    }
}
