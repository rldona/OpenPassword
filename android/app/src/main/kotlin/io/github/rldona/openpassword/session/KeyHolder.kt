package io.github.rldona.openpassword.session

import io.github.rldona.openpassword.core.OpException
import java.util.concurrent.atomic.AtomicReference

/**
 * Holds the one live native vault and makes [lock] safe to call from any thread while an
 * operation is using it (ID-INT-08).
 *
 * [lock] never waits for the session mutex: it detaches the vault atomically and wipes it
 * right away, so after it returns nobody can obtain the key from here again. An operation
 * already running keeps the reference it took; its next native call fails because the handle
 * was closed (`IllegalStateException`), and [use] turns that into [OpException.Locked]
 * instead of letting a foreign exception reach the UI as a crash.
 *
 * What stays outside this class: whether the Rust side tolerates `lock()` racing with a call
 * that is already inside it. That is the core's contract (not changed here) and is only
 * exercised on a device by `VaultSessionTest`.
 */
class KeyHolder<V : Any>(private val wipe: (V) -> Unit) {
    private val ref = AtomicReference<V?>(null)

    /** The live vault, or null once locked. For checks; operate through [use]. */
    fun current(): V? = ref.get()

    /** Makes [next] the live vault and wipes the previous one, if any. */
    fun replace(next: V) {
        ref.getAndSet(next)?.let(wipe)
    }

    /** Wipes and forgets the vault. Returns false if there was none. Idempotent and thread-safe. */
    fun lock(): Boolean {
        val old = ref.getAndSet(null) ?: return false
        wipe(old)
        return true
    }

    /** Runs [block] on the live vault; [OpException.Locked] if it is locked before or during the call. */
    fun <T> use(block: (V) -> T): T {
        val vault = ref.get() ?: throw OpException.Locked()
        return try {
            block(vault)
        } catch (e: IllegalStateException) {
            // The handle was closed under us by lock(): a clean "locked", not a crash.
            if (ref.get() !== vault) throw OpException.Locked()
            throw e
        }
    }
}
