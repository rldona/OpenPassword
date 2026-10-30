package io.github.rldona.openpassword.session

/** Where the failed-attempt counter lives (SharedPreferences in the app, memory in tests). */
interface AttemptStore {
    val failures: Int
    val lastFailureAt: Long

    /** Stores both values together. */
    fun write(failures: Int, lastFailureAt: Long)
}

/**
 * The one failed-password counter, shared by the unlock screen and by every re-check of the
 * master password (`verifyPassword`): ID-INT-09. Splitting them would let someone with the
 * vault open guess the password without the growing wait.
 */
class AttemptLimiter(
    private val store: AttemptStore,
    private val now: () -> Long = System::currentTimeMillis,
) {
    /** Seconds still to wait before another attempt; 0 if free. */
    fun remainingWait(): Long = VaultSession.unlockWaitSeconds(store.failures, now() - store.lastFailureAt)

    fun recordFailure() {
        store.write(store.failures + 1, now())
    }

    fun recordSuccess() {
        store.write(0, store.lastFailureAt)
    }
}
