package io.github.rldona.openpassword.session

import android.content.SharedPreferences
import android.os.SystemClock
import io.github.rldona.openpassword.core.EncryptedItemRecord
import io.github.rldona.openpassword.core.ItemDetailsRecord
import io.github.rldona.openpassword.core.ItemOverviewRecord
import io.github.rldona.openpassword.core.KdfProfile
import io.github.rldona.openpassword.core.OpException
import io.github.rldona.openpassword.core.Vault
import io.github.rldona.openpassword.data.VaultStorage
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlin.math.min

/** An item with its overview already decrypted, for the list and search. */
data class VaultEntry(val record: EncryptedItemRecord, val overview: ItemOverviewRecord) {
    val id: String get() = record.id
}

sealed interface SessionState {
    data object NoVault : SessionState
    data object Locked : SessionState
    data class Unlocked(val entries: List<VaultEntry>) : SessionState
}

sealed interface UnlockResult {
    data object Success : UnlockResult
    data class WrongPassword(val waitSeconds: Long) : UnlockResult
    data class MustWait(val waitSeconds: Long) : UnlockResult
    data class Failed(val message: String) : UnlockResult
}

/**
 * Owns the unlocked [Vault]. Only this class holds the vault key in memory, and [lock]
 * wipes it. All Argon2id and crypto calls run on [Dispatchers.Default].
 */
class VaultSession(
    private val storage: VaultStorage,
    private val prefs: SharedPreferences,
    private val kdfProfile: KdfProfile,
) {
    private val mutex = Mutex()
    private var vault: Vault? = null
    private val _state = MutableStateFlow<SessionState>(
        if (storage.hasVault()) SessionState.Locked else SessionState.NoVault,
    )
    val state: StateFlow<SessionState> = _state.asStateFlow()

    private var lastInteraction = SystemClock.elapsedRealtime()
    private var backgroundedAt: Long? = null

    suspend fun create(password: String, secretKey: String) = mutex.withLock {
        withContext(Dispatchers.Default) {
            val created = Vault.create(password, secretKey, kdfProfile)
            storage.saveSecretKey(secretKey)
            storage.writeHeader(created.headerJson())
            replaceVault(created, emptyList())
        }
    }

    suspend fun unlock(password: String): UnlockResult = mutex.withLock {
        remainingWait().takeIf { it > 0 }?.let { return UnlockResult.MustWait(it) }
        withContext(Dispatchers.Default) {
            try {
                val unlocked = Vault.unlock(storage.readHeader(), password, storage.loadSecretKey())
                val entries = storage.items().map { VaultEntry(it, unlocked.decryptOverview(it)) }
                prefs.edit().putInt(KEY_FAILURES, 0).apply()
                replaceVault(unlocked, entries)
                UnlockResult.Success
            } catch (_: OpException.WrongCredentials) {
                val failures = prefs.getInt(KEY_FAILURES, 0) + 1
                prefs.edit().putInt(KEY_FAILURES, failures).putLong(KEY_LAST_FAILURE, System.currentTimeMillis()).apply()
                UnlockResult.WrongPassword(remainingWait())
            } catch (e: OpException) {
                UnlockResult.Failed(e.toUserMessage())
            }
        }
    }

    /** Checks the master password again without changing the session (e.g. to reveal the secret key). */
    suspend fun verifyPassword(password: String): Boolean = withContext(Dispatchers.Default) {
        try {
            Vault.unlock(storage.readHeader(), password, storage.loadSecretKey()).use { it.lock() }
            true
        } catch (_: OpException) {
            false
        }
    }

    fun secretKey(): String = storage.loadSecretKey()

    fun lock() {
        vault?.let {
            it.lock()
            it.close()
        }
        vault = null
        if (_state.value is SessionState.Unlocked) _state.value = SessionState.Locked
    }

    suspend fun details(entry: VaultEntry): ItemDetailsRecord = withVault { it.decryptDetails(entry.record) }

    suspend fun save(existing: VaultEntry?, overview: ItemOverviewRecord, details: ItemDetailsRecord): VaultEntry =
        withVault { v ->
            val record = if (existing == null) {
                v.encryptItem(overview, details)
            } else {
                v.updateItem(existing.record, overview, details)
            }
            storage.upsert(record)
            VaultEntry(record, overview).also { saved ->
                updateEntries { entries -> entries.filterNot { it.id == saved.id } + saved }
            }
        }

    suspend fun delete(entry: VaultEntry) = withVault {
        storage.delete(entry.id)
        updateEntries { entries -> entries.filterNot { it.id == entry.id } }
    }

    suspend fun exportBackup(): ByteArray = withVault { v ->
        v.exportBackup(storage.items(), (System.currentTimeMillis() / 1000).toULong())
    }

    // ---- Auto-lock ----

    fun onUserInteraction() {
        lastInteraction = SystemClock.elapsedRealtime()
    }

    fun onAppBackgrounded() {
        backgroundedAt = SystemClock.elapsedRealtime()
    }

    fun onAppForegrounded() {
        val since = backgroundedAt?.let { SystemClock.elapsedRealtime() - it } ?: 0
        backgroundedAt = null
        if (since >= BACKGROUND_TIMEOUT_MS) lock()
    }

    /** Called periodically while the app is visible. */
    fun lockIfIdle() {
        if (SystemClock.elapsedRealtime() - lastInteraction >= IDLE_TIMEOUT_MS) lock()
    }

    // ---- Internals ----

    private suspend fun <T> withVault(block: (Vault) -> T): T = mutex.withLock {
        withContext(Dispatchers.Default) {
            block(vault ?: throw OpException.Locked())
        }
    }

    private fun replaceVault(newVault: Vault, entries: List<VaultEntry>) {
        vault?.let {
            it.lock()
            it.close()
        }
        vault = newVault
        lastInteraction = SystemClock.elapsedRealtime()
        _state.value = SessionState.Unlocked(entries)
    }

    private fun updateEntries(transform: (List<VaultEntry>) -> List<VaultEntry>) {
        val current = _state.value as? SessionState.Unlocked ?: return
        _state.value = current.copy(entries = transform(current.entries))
    }

    /** Seconds to wait before the next attempt: free for 4 failures, then 30 s doubling up to 1 h. */
    private fun remainingWait(): Long {
        val failures = prefs.getInt(KEY_FAILURES, 0)
        if (failures < FREE_ATTEMPTS) return 0
        val delayMs = min(30_000L shl min(failures - FREE_ATTEMPTS, 7), 3_600_000L)
        val elapsed = System.currentTimeMillis() - prefs.getLong(KEY_LAST_FAILURE, 0)
        return ((delayMs - elapsed).coerceAtLeast(0) + 999) / 1000
    }

    companion object {
        const val BACKGROUND_TIMEOUT_MS = 30_000L
        const val IDLE_TIMEOUT_MS = 5 * 60_000L
        private const val FREE_ATTEMPTS = 4
        private const val KEY_FAILURES = "unlock_failures"
        private const val KEY_LAST_FAILURE = "unlock_last_failure"
    }
}

fun OpException.toUserMessage(): String = when (this) {
    is OpException.WrongCredentials -> "Contraseña maestra incorrecta."
    is OpException.WrongSecretKey -> "La clave secreta no corresponde a este baúl."
    is OpException.InvalidSecretKey -> "La clave secreta no es válida. Revisa si hay erratas."
    is OpException.InvalidInput -> "Dato no válido: $reason."
    is OpException.Corrupted -> "Los datos están dañados o han sido modificados."
    is OpException.UnsupportedVersion -> "Este fichero es de una versión más nueva de OpenPassword."
    is OpException.Locked -> "El baúl está bloqueado."
    is OpException.Internal -> "Error interno: $reason."
}
