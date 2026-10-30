package io.github.rldona.openpassword

import io.github.rldona.openpassword.security.ClipboardAction
import io.github.rldona.openpassword.security.clipboardAction
import org.junit.Assert.assertEquals
import org.junit.Test

/** ID-INT-14: decision logic only. Behaviour in the background is NOT verified on a device. */
class ClipboardClearPolicyTest {
    private val own = "OpenPassword"
    private fun act(deadline: Long? = 100, now: Long = 200, label: String? = own, canRead: Boolean = true, force: Boolean = false) =
        clipboardAction(deadline, now, label, canRead, own, force)

    @Test
    fun `nothing pending means nothing to do`() {
        assertEquals(ClipboardAction.NOTHING, act(deadline = null))
    }

    @Test
    fun `before the deadline it waits`() {
        assertEquals(ClipboardAction.WAIT, act(now = 99))
    }

    @Test
    fun `clears our clip once due`() {
        assertEquals(ClipboardAction.CLEAR, act(now = 100))
        assertEquals(ClipboardAction.CLEAR, act(canRead = false))
    }

    @Test
    fun `never clears someone else's content`() {
        assertEquals(ClipboardAction.FORGET, act(label = "otra app"))
        assertEquals(ClipboardAction.FORGET, act(label = "otra app", canRead = false))
    }

    @Test
    fun `unreadable in the background is retried, not cleared blindly`() {
        assertEquals(ClipboardAction.RETRY_LATER, act(label = null, canRead = false))
    }

    @Test
    fun `empty clipboard in the foreground means there is nothing left to clear`() {
        assertEquals(ClipboardAction.FORGET, act(label = null, canRead = true))
    }

    @Test
    fun `force ignores the deadline`() {
        assertEquals(ClipboardAction.WAIT, act(now = 50))
        assertEquals(ClipboardAction.CLEAR, act(now = 50, force = true))
    }
}
