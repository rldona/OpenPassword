package io.github.rldona.openpassword.autofill

import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import java.security.SecureRandom

/** A login typed into another app, waiting for the user to confirm saving it. */
class PendingSave(val target: FillTarget, val username: String, val password: String)

/**
 * The expiry rules of [PendingSaves], with the clock injected so they can be tested on the JVM.
 * Entries older than [ttlMs] are never returned and are dropped by [purge], [put] and [peek].
 */
class PendingStore(private val ttlMs: Long, private val now: () -> Long, private val random: SecureRandom = SecureRandom()) {
    private val entries = mutableMapOf<String, Pair<Long, PendingSave>>()

    @Synchronized
    fun put(save: PendingSave): String {
        purge()
        val token = ByteArray(16).also(random::nextBytes).joinToString("") { "%02x".format(it) }
        entries[token] = now() to save
        return token
    }

    @Synchronized
    fun peek(token: String): PendingSave? {
        purge()
        return entries[token]?.second
    }

    @Synchronized
    fun remove(token: String) {
        entries.remove(token)
    }

    /** Drops everything, e.g. when the vault locks. */
    @Synchronized
    fun clear() {
        entries.clear()
    }

    /** Drops expired entries. */
    @Synchronized
    fun purge() {
        val t = now()
        entries.entries.removeAll { t - it.value.first > ttlMs }
    }

    @Synchronized
    fun size(): Int = entries.size
}

/**
 * Holds pending saves in this process's memory. The activity that confirms them only
 * gets a random token through its Intent, so the password never travels through the
 * system (Intents and PendingIntents are kept by system_server).
 *
 * Entries expire after [TTL_MS] by a timer, not only when someone happens to call [put] or
 * [peek] (ID-INT-17), and are all dropped when the vault locks ([clear], wired from
 * `VaultSession.onLocked`). The password is still a `String` in the heap until the GC runs.
 */
object PendingSaves {
    const val TTL_MS = 5 * 60_000L
    private val store = PendingStore(TTL_MS, SystemClock::elapsedRealtime)
    private val handler by lazy { Handler(Looper.getMainLooper()) }
    private const val SWEEP_MS = 30_000L
    private val sweep = object : Runnable {
        override fun run() {
            store.purge()
            if (store.size() > 0) handler.postDelayed(this, SWEEP_MS)
        }
    }

    fun put(save: PendingSave): String {
        val token = store.put(save)
        handler.removeCallbacks(sweep)
        handler.postDelayed(sweep, SWEEP_MS)
        return token
    }

    fun peek(token: String): PendingSave? = store.peek(token)

    fun remove(token: String) = store.remove(token)

    /** Drops every pending save now. */
    fun clear() {
        handler.removeCallbacks(sweep)
        store.clear()
    }
}
