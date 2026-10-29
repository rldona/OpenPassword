package io.github.rldona.openpassword.session

import android.content.SharedPreferences
import android.os.SystemClock
import android.security.keystore.KeyPermanentlyInvalidatedException
import io.github.rldona.openpassword.core.EncryptedItemRecord
import io.github.rldona.openpassword.core.ItemDetailsRecord
import io.github.rldona.openpassword.core.ItemOverviewRecord
import io.github.rldona.openpassword.core.KdfProfile
import io.github.rldona.openpassword.core.OpException
import io.github.rldona.openpassword.core.Vault
import io.github.rldona.openpassword.core.normalizeSecretKey
import io.github.rldona.openpassword.core.openBackup
import io.github.rldona.openpassword.data.VaultStorage
import io.github.rldona.openpassword.security.BiometricKeyStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.security.GeneralSecurityException
import javax.crypto.Cipher
import kotlin.math.min

/** What an import into the current vault did. */
data class ImportSummary(val added: Int, val updated: Int, val unchanged: Int)

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
    private val biometricKeys: BiometricKeyStore,
    /** Device boot counter, to require the master password after every reboot. */
    private val bootCount: () -> Int,
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
            storage.clearItems()
            storage.saveSecretKey(secretKey)
            storage.writeHeader(created.headerJson())
            recordPasswordUnlock()
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
                recordPasswordUnlock()
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

    /**
     * Makes a `.opvault` backup this device's vault: same vault key, same items.
     * Only allowed while there is no vault on the device.
     */
    suspend fun restore(backup: ByteArray, password: String, secretKey: String) = mutex.withLock {
        check(!storage.hasVault()) { "a vault already exists on this device" }
        withContext(Dispatchers.Default) {
            val normalizedKey = normalizeSecretKey(secretKey)
            val contents = openBackup(backup, password, normalizedKey)
            val entries = contents.items.map { VaultEntry(it, contents.vault.decryptOverview(it)) }
            try {
                storage.clearItems()
                contents.items.forEach(storage::upsert)
                storage.saveSecretKey(normalizedKey)
                // Header last: until it exists the device still counts as having no vault.
                storage.writeHeader(contents.vault.headerJson())
            } catch (e: Exception) {
                storage.clearItems()
                contents.vault.lock()
                throw e
            }
            recordPasswordUnlock()
            replaceVault(contents.vault, entries)
        }
    }

    /**
     * Imports a backup into the unlocked vault. A backup of this same vault is merged by
     * revision; items from another vault are re-encrypted under this vault's keys, so
     * importing the same foreign backup twice adds its items twice.
     */
    suspend fun importBackup(backup: ByteArray, password: String, secretKey: String?): ImportSummary = mutex.withLock {
        withContext(Dispatchers.Default) {
            val current = vault ?: throw OpException.Locked()
            // No key given: a backup made on this device, so use the one stored here.
            val key = secretKey?.let(::normalizeSecretKey) ?: storage.loadSecretKey()
            val contents = openBackup(backup, password, key)
            val source = contents.vault
            try {
                val sameVault = vaultIdOf(source.headerJson()) == vaultIdOf(current.headerJson())
                val existing = storage.items().associateBy { it.id }
                var added = 0
                var updated = 0
                var unchanged = 0
                for (record in contents.items) {
                    val mine = existing[record.id]
                    when {
                        !sameVault -> {
                            storage.upsert(current.encryptItem(source.decryptOverview(record), source.decryptDetails(record)))
                            added++
                        }
                        mine == null -> { storage.upsert(record); added++ }
                        record.revision > mine.revision -> { storage.upsert(record); updated++ }
                        else -> unchanged++
                    }
                }
                val entries = storage.items().map { VaultEntry(it, current.decryptOverview(it)) }
                _state.value = SessionState.Unlocked(entries)
                ImportSummary(added, updated, unchanged)
            } finally {
                source.lock()
                source.close()
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

    // ---- Biometric unlock (crypto-spec section 9) ----

    fun isBiometricEnabled(): Boolean = storage.hasBiometricVaultKey()

    /** Why the master password is required even though biometric unlock is on, or null if it is not. */
    fun passwordRequiredReason(): String? {
        if (!isBiometricEnabled()) return null
        val last = prefs.getLong(KEY_LAST_PASSWORD_UNLOCK, 0)
        return when {
            prefs.getInt(KEY_BOOT_COUNT, -1) != bootCount() -> "El teléfono se ha reiniciado: introduce tu contraseña maestra."
            System.currentTimeMillis() - last >= PASSWORD_EVERY_MS ->
                "Han pasado 14 días: introduce tu contraseña maestra para no olvidarla."
            else -> null
        }
    }

    fun canUseBiometricNow(): Boolean = isBiometricEnabled() && passwordRequiredReason() == null

    /** Step 1 of enabling: a new biometric key and a cipher to authorize with the prompt. */
    fun biometricEnableCipher(): Cipher = biometricKeys.newEncryptCipher()

    /** Step 2 of enabling: seals the vault key with the cipher the prompt authorized. */
    suspend fun enableBiometric(authorized: Cipher) = withVault { v ->
        val key = v.vaultKeyBytes()
        try {
            storage.writeBiometricVaultKey(byteArrayOf(BIO_VERSION) + authorized.iv + authorized.doFinal(key))
        } finally {
            key.fill(0)
        }
    }

    fun disableBiometric() {
        storage.deleteBiometricVaultKey()
        biometricKeys.delete()
    }

    /**
     * Step 1 of unlocking: a cipher to authorize with the prompt.
     * Returns null, and turns biometric unlock off, if Android invalidated the key
     * because biometrics changed.
     */
    fun biometricUnlockCipher(): Cipher? {
        val sealed = storage.readBiometricVaultKey()
        if (sealed.size <= 1 + BIO_IV_LEN || sealed[0] != BIO_VERSION) {
            disableBiometric()
            return null
        }
        return try {
            biometricKeys.decryptCipher(sealed.copyOfRange(1, 1 + BIO_IV_LEN))
        } catch (_: KeyPermanentlyInvalidatedException) {
            disableBiometric()
            null
        }
    }

    /** Step 2 of unlocking: opens the vault with the key the authorized cipher releases. */
    suspend fun unlockWithBiometric(authorized: Cipher): UnlockResult = mutex.withLock {
        withContext(Dispatchers.Default) {
            val sealed = storage.readBiometricVaultKey()
            val key = try {
                authorized.doFinal(sealed, 1 + BIO_IV_LEN, sealed.size - 1 - BIO_IV_LEN)
            } catch (_: GeneralSecurityException) {
                return@withContext UnlockResult.Failed("No se pudo usar la huella. Introduce tu contraseña maestra.")
            }
            try {
                val unlocked = Vault.unlockWithVaultKey(storage.readHeader(), key)
                val entries = storage.items().map { VaultEntry(it, unlocked.decryptOverview(it)) }
                replaceVault(unlocked, entries)
                UnlockResult.Success
            } catch (e: OpException) {
                UnlockResult.Failed(e.toUserMessage())
            } finally {
                key.fill(0)
            }
        }
    }

    private fun recordPasswordUnlock() {
        prefs.edit()
            .putLong(KEY_LAST_PASSWORD_UNLOCK, System.currentTimeMillis())
            .putInt(KEY_BOOT_COUNT, bootCount())
            .apply()
    }

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

    private fun remainingWait(): Long = unlockWaitSeconds(
        failures = prefs.getInt(KEY_FAILURES, 0),
        msSinceLastFailure = System.currentTimeMillis() - prefs.getLong(KEY_LAST_FAILURE, 0),
    )

    companion object {
        const val BACKGROUND_TIMEOUT_MS = 30_000L
        const val IDLE_TIMEOUT_MS = 5 * 60_000L
        const val FREE_ATTEMPTS = 4

        /** Seconds to wait before the next attempt: free for 4 failures, then 30 s doubling up to 1 h. */
        fun unlockWaitSeconds(failures: Int, msSinceLastFailure: Long): Long {
            if (failures < FREE_ATTEMPTS) return 0
            val delayMs = min(30_000L shl min(failures - FREE_ATTEMPTS, 7), 3_600_000L)
            return ((delayMs - msSinceLastFailure).coerceAtLeast(0) + 999) / 1000
        }

        private const val KEY_FAILURES = "unlock_failures"
        private const val KEY_LAST_FAILURE = "unlock_last_failure"
        private const val KEY_LAST_PASSWORD_UNLOCK = "last_password_unlock"
        private const val KEY_BOOT_COUNT = "boot_count_at_password_unlock"
        private const val PASSWORD_EVERY_MS = 14L * 24 * 3600 * 1000
        private const val BIO_VERSION: Byte = 1
        private const val BIO_IV_LEN = 12
    }
}

private fun vaultIdOf(headerJson: String): String = JSONObject(headerJson).getString("vault_id")

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
