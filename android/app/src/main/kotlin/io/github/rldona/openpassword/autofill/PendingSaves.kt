package io.github.rldona.openpassword.autofill

import android.os.SystemClock
import java.security.SecureRandom

/** A login typed into another app, waiting for the user to confirm saving it. */
class PendingSave(val target: FillTarget, val username: String, val password: String)

/**
 * Holds pending saves in this process's memory. The activity that confirms them only
 * gets a random token through its Intent, so the password never travels through the
 * system (Intents and PendingIntents are kept by system_server). Entries expire.
 */
object PendingSaves {
    private const val TTL_MS = 5 * 60_000L
    private val random = SecureRandom()
    private val entries = mutableMapOf<String, Pair<Long, PendingSave>>()

    @Synchronized
    fun put(save: PendingSave): String {
        expire()
        val token = ByteArray(16).also(random::nextBytes).joinToString("") { "%02x".format(it) }
        entries[token] = SystemClock.elapsedRealtime() to save
        return token
    }

    @Synchronized
    fun peek(token: String): PendingSave? {
        expire()
        return entries[token]?.second
    }

    @Synchronized
    fun remove(token: String) {
        entries.remove(token)
    }

    private fun expire() {
        val now = SystemClock.elapsedRealtime()
        entries.entries.removeAll { now - it.value.first > TTL_MS }
    }
}
