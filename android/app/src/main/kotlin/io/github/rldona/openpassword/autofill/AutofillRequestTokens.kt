package io.github.rldona.openpassword.autofill

import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap

/**
 * Holds, in this process's memory, the fill requests waiting for [AutofillAuthActivity].
 *
 * The `IntentSender` of `Dataset.setAuthentication` is handed to the app being filled, which
 * can fire it with any extras it likes (the PendingIntent has to be mutable). So the Intent
 * carries only an opaque random token and the target (domain or package) and field ids are
 * looked up here: nothing the caller can add to the Intent can change who gets the login.
 *
 * Tokens are random (128 bits), expire after [ttlMs] and are single use ([take]).
 */
class AutofillRequestTokens(
    private val now: () -> Long = { System.nanoTime() / 1_000_000 },
    private val ttlMs: Long = TTL_MS,
) {
    private class Entry(val at: Long, val request: LoginRequest)

    private val random = SecureRandom()
    private val entries = ConcurrentHashMap<String, Entry>()

    fun put(request: LoginRequest): String {
        expire()
        val token = ByteArray(16).also(random::nextBytes).joinToString("") { "%02x".format(it) }
        entries[token] = Entry(now(), request)
        return token
    }

    /** The request behind [token], removing it. Null if unknown, already used or expired. */
    fun take(token: String?): LoginRequest? {
        if (token == null) return null
        val entry = entries.remove(token) ?: return null
        return entry.request.takeIf { now() - entry.at < ttlMs }
    }

    /** Drops [token] without using it. */
    fun discard(token: String?) {
        if (token != null) entries.remove(token)
    }

    private fun expire() {
        val t = now()
        entries.entries.removeAll { t - it.value.at >= ttlMs }
    }

    companion object {
        const val TTL_MS = 5 * 60_000L

        /** The process-wide store used by the autofill service and activity. */
        val shared = AutofillRequestTokens()
    }
}
