package io.github.rldona.openpassword.session

import android.content.SharedPreferences
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.security.keystore.KeyPermanentlyInvalidatedException
import io.github.rldona.openpassword.core.EncryptedAttachmentRecord
import io.github.rldona.openpassword.core.EncryptedItemRecord
import io.github.rldona.openpassword.core.FieldKindRecord
import io.github.rldona.openpassword.core.ImportedItemRecord
import io.github.rldona.openpassword.core.ItemKindRecord
import io.github.rldona.openpassword.core.ItemDetailsRecord
import io.github.rldona.openpassword.core.ItemOverviewRecord
import io.github.rldona.openpassword.core.KdfProfile
import io.github.rldona.openpassword.core.InternalException
import io.github.rldona.openpassword.core.NewImageRecord
import io.github.rldona.openpassword.core.OpException
import io.github.rldona.openpassword.core.Vault
import io.github.rldona.openpassword.core.attachmentLimits
import io.github.rldona.openpassword.core.normalizeSecretKey
import io.github.rldona.openpassword.core.backupKdf
import io.github.rldona.openpassword.core.openBackup
import io.github.rldona.openpassword.data.VaultStorage
import io.github.rldona.openpassword.health.HealthInput
import io.github.rldona.openpassword.health.HealthReport
import io.github.rldona.openpassword.health.VaultHealth
import io.github.rldona.openpassword.security.BiometricKeyStore
import kotlinx.coroutines.CancellationException
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

/** What an import from another password manager did. */
data class ExternalImportSummary(val added: Int, val duplicates: Int)

/** What an import into the current vault did. */
data class ImportSummary(val added: Int, val updated: Int, val unchanged: Int)

/** The vault has reached the image space limit; nothing was written. */
class ImageQuotaExceeded : Exception("No cabe más imágenes en la caja fuerte.")

/** An item with its overview already decrypted, for the list and search. */
data class VaultEntry(val record: EncryptedItemRecord, val overview: ItemOverviewRecord) {
    val id: String get() = record.id
}

sealed interface SessionState {
    data object NoVault : SessionState
    data object Locked : SessionState
    /** [unreadable]: ids of rows that could not be decrypted; they stay untouched in storage (ID-INT-06). */
    data class Unlocked(val entries: List<VaultEntry>, val unreadable: List<String> = emptyList()) : SessionState
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
    /** Physical RAM of the device in bytes, to refuse a backup whose KDF would not fit. */
    private val totalMemory: () -> Long = { Long.MAX_VALUE },
) {
    private val mutex = Mutex()
    private val vault = KeyHolder<Vault>(Vault::discard)
    private val attempts = AttemptLimiter(PrefsAttemptStore(prefs))
    private val _state = MutableStateFlow<SessionState>(
        if (storage.hasVault()) SessionState.Locked else SessionState.NoVault,
    )
    val state: StateFlow<SessionState> = _state.asStateFlow()

    /** Called after any change to the items (save, delete, import). Used by automatic backup. */
    var onChanged: () -> Unit = {}
    /** Called every time the vault is unlocked, by password, fingerprint or restore. */
    var onUnlocked: () -> Unit = {}
    /** Called every time the session locks, even if it was already locked. Used to drop in-memory secrets. */
    var onLocked: () -> Unit = {}

    private var lastInteraction = SystemClock.elapsedRealtime()
    private var backgroundedAt: Long? = null

    suspend fun create(password: String, secretKey: String) = mutex.withLock {
        withContext(Dispatchers.Default) {
            val created = Vault.create(password, secretKey, kdfProfile)
            discardOnFailure(created::discard) {
                storage.clearItems()
                storage.saveSecretKey(secretKey)
                storage.writeHeader(created.headerJson())
                recordPasswordUnlock()
            }
            replaceVault(created, LoadedEntries(emptyList(), emptyList()))
        }
    }

    suspend fun unlock(password: String): UnlockResult = mutex.withLock {
        attempts.remainingWait().takeIf { it > 0 }?.let { return UnlockResult.MustWait(it) }
        withContext(Dispatchers.Default) {
            try {
                val unlocked = Vault.unlock(storage.readHeader(), password, storage.loadSecretKey())
                val entries = discardOnFailure(unlocked::discard) { loadEntries(storage.items(), unlocked::decryptOverview) }
                storage.sweepOrphans()
                attempts.recordSuccess()
                recordPasswordUnlock()
                replaceVault(unlocked, entries)
                UnlockResult.Success
            } catch (_: OpException.WrongCredentials) {
                attempts.recordFailure()
                UnlockResult.WrongPassword(attempts.remainingWait())
            } catch (e: OpException) {
                UnlockResult.Failed(e.toUserMessage())
            } catch (_: InternalException) {
                UnlockResult.Failed(INTERNAL_ERROR_MESSAGE)
            }
        }
    }

    /** Throws [OpException.KdfTooExpensive] if the backup's KDF asks for more memory than the device has. */
    private fun checkKdfFits(backup: ByteArray) {
        val kdf = backupKdf(backup)
        if (!kdfMemoryFits(kdf.mKib, totalMemory())) throw OpException.KdfTooExpensive(kdf.mKib, kdf.t, kdf.p)
    }

    /**
     * Makes a `.opvault` backup this device's vault: same vault key, same items.
     * Only allowed while there is no vault on the device.
     */
    suspend fun restore(backup: ByteArray, password: String, secretKey: String) = mutex.withLock {
        check(!storage.hasVault()) { "a vault already exists on this device" }
        withContext(Dispatchers.Default) {
            val normalizedKey = normalizeSecretKey(secretKey)
            checkKdfFits(backup)
            val contents = openBackup(backup, password, normalizedKey)
            val entries = discardOnFailure(contents.vault::discard) { loadEntries(contents.items, contents.vault::decryptOverview) }
            try {
                // One transaction: an interrupted restore never leaves items without images.
                storage.replaceAll(contents.items, contents.attachments)
                storage.saveSecretKey(normalizedKey)
                // Header last: until it exists the device still counts as having no vault.
                storage.writeHeader(contents.vault.headerJson())
            } catch (e: Exception) {
                storage.clearItems()
                contents.vault.discard()
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
            vault.use { current ->
                // No key given: a backup made on this device, so use the one stored here.
                val key = secretKey?.let(::normalizeSecretKey) ?: storage.loadSecretKey()
                checkKdfFits(backup)
                val contents = openBackup(backup, password, key)
                val source = contents.vault
                try {
                    val sameVault = vaultIdOf(source.headerJson()) == vaultIdOf(current.headerJson())
                    val local = storage.items().associateBy { it.id }
                    val byItem = contents.attachments.groupBy { it.itemId }
                    val itemsToWrite = mutableListOf<EncryptedItemRecord>()
                    val toInsert = mutableListOf<EncryptedAttachmentRecord>()
                    val toDelete = mutableListOf<Pair<String, String>>()
                    var added = 0
                    var updated = 0
                    var unchanged = 0

                    if (sameVault) {
                        for (record in contents.items) {
                            val mine = local[record.id]
                            val newRefs = runCatching { source.imageIds(record) }.getOrNull()
                            val theirs = byItem[record.id].orEmpty()
                                .filter { newRefs == null || it.id in newRefs }
                            when {
                                mine == null -> {
                                    itemsToWrite += record
                                    toInsert += theirs
                                    added++
                                }
                                record.revision > mine.revision -> {
                                    val oldRefs = runCatching { current.imageIds(mine) }.getOrNull()
                                    itemsToWrite += record
                                    toInsert += theirs
                                    // Only remove images when the new revision is readable and
                                    // says which ones it keeps: a damaged copy must not delete.
                                    if (oldRefs != null && newRefs != null) {
                                        oldRefs.filter { id -> id !in newRefs }
                                            .forEach { toDelete += mine.id to it }
                                    }
                                    updated++
                                }
                                else -> {
                                    // Keep the local revision; a copy can only fill gaps.
                                    val oldRefs = runCatching { current.imageIds(mine) }.getOrNull().orEmpty()
                                    toInsert += theirs.filter { it.id in oldRefs && storage.attachment(mine.id, it.id) == null }
                                    unchanged++
                                }
                            }
                        }
                    } else {
                        for (record in contents.items) {
                            val change = current.adoptItem(source, record, byItem[record.id].orEmpty())
                            itemsToWrite += change.item
                            toInsert += change.added
                            added++
                        }
                    }

                    val insertions = toInsert.distinctBy { it.itemId to it.id }
                    val deletions = toDelete.distinct()
                    val released = deletions.sumOf { (itemId, id) -> storage.attachmentSize(itemId, id) }
                    val taken = insertions.sumOf { it.data.size.toLong() }
                    if (storage.attachmentBytesTotal() - released + taken > attachmentLimits().maxVaultAttachmentBytes.toLong()) {
                        throw ImageQuotaExceeded()
                    }

                    if (itemsToWrite.isNotEmpty() || insertions.isNotEmpty() || deletions.isNotEmpty()) {
                        storage.applyImport(itemsToWrite, insertions, deletions)
                    }
                    val loaded = loadEntries(storage.items(), current::decryptOverview)
                    // A lock() during the import must not bring the state back to Unlocked without a key.
                    if (vault.current() === current) _state.value = SessionState.Unlocked(loaded.entries, loaded.unreadable)
                    if (added + updated > 0 || insertions.isNotEmpty() || deletions.isNotEmpty()) onChanged()
                    ImportSummary(added, updated, unchanged)
                } finally {
                    source.lock()
                    source.close()
                }
            }
        }
    }

    /**
     * Checks the master password again without changing the session (e.g. to reveal the secret key).
     * Shares the failure counter and the growing wait with [unlock] (ID-INT-09): the result is
     * [UnlockResult.Success], [UnlockResult.WrongPassword], [UnlockResult.MustWait] or [UnlockResult.Failed].
     */
    suspend fun verifyPassword(password: String): UnlockResult = mutex.withLock {
        attempts.remainingWait().takeIf { it > 0 }?.let { return UnlockResult.MustWait(it) }
        withContext(Dispatchers.Default) {
            try {
                Vault.unlock(storage.readHeader(), password, storage.loadSecretKey()).use { it.lock() }
                attempts.recordSuccess()
                UnlockResult.Success
            } catch (_: OpException.WrongCredentials) {
                attempts.recordFailure()
                UnlockResult.WrongPassword(attempts.remainingWait())
            } catch (e: OpException) {
                UnlockResult.Failed(e.toUserMessage())
            } catch (_: InternalException) {
                UnlockResult.Failed(INTERNAL_ERROR_MESSAGE)
            }
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
                val entries = discardOnFailure(unlocked::discard) { loadEntries(storage.items(), unlocked::decryptOverview) }
                storage.sweepOrphans()
                replaceVault(unlocked, entries)
                UnlockResult.Success
            } catch (e: OpException) {
                UnlockResult.Failed(e.toUserMessage())
            } catch (_: InternalException) {
                UnlockResult.Failed(INTERNAL_ERROR_MESSAGE)
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

    /**
     * Wipes the key at once and from any thread, without waiting for [mutex]: an operation in
     * flight finishes with [OpException.Locked] (see [KeyHolder]). Waiting would block the main
     * thread behind a long import, and taking the mutex from a locked path risks a deadlock
     * with [withVault].
     */
    fun lock() {
        vault.lock()
        onLocked()
        if (_state.value is SessionState.Unlocked) _state.value = SessionState.Locked
    }

    suspend fun details(entry: VaultEntry): ItemDetailsRecord = withVault { it.decryptDetails(entry.record) }

    suspend fun save(
        existing: VaultEntry?,
        overview: ItemOverviewRecord,
        details: ItemDetailsRecord,
        newImages: List<NewImageRecord> = emptyList(),
    ): VaultEntry =
        withVault { v ->
            val change = if (existing == null) {
                v.encryptItemWithImages(overview, details, newImages)
            } else {
                v.updateItemWithImages(existing.record, overview, details, newImages)
            }
            val released = change.removed.sumOf { storage.attachmentSize(change.item.id, it) }
            val taken = change.added.sumOf { it.data.size.toLong() }
            if (storage.attachmentBytesTotal() - released + taken > attachmentLimits().maxVaultAttachmentBytes.toLong()) {
                throw ImageQuotaExceeded()
            }
            storage.applyChange(change.item, change.added, change.removed)
            VaultEntry(change.item, overview).also { saved ->
                updateEntries { entries -> entries.filterNot { it.id == saved.id } + saved }
            }
        }.also { onChanged() }

    /** Decrypts one image. The caller owns the bytes and must wipe them as soon as it is done. */
    suspend fun image(entry: VaultEntry, attachmentId: String): ByteArray? = withVault { v ->
        val attachment = storage.attachment(entry.id, attachmentId) ?: return@withVault null
        v.decryptImage(entry.record, attachment)
    }

    suspend fun delete(entry: VaultEntry) = withVault {
        storage.delete(entry.id)
        updateEntries { entries -> entries.filterNot { it.id == entry.id } }
    }.also { onChanged() }

    /**
     * Encrypts items parsed from another manager's export under this vault's keys.
     * Items already in the vault (same type, name, user and website) are skipped, so
     * importing the same file twice does not duplicate anything.
     */
    suspend fun importExternal(items: List<ImportedItemRecord>): ExternalImportSummary = withVault { v ->
        fun key(o: ItemOverviewRecord) = listOf(o.kind.name, o.title.trim().lowercase(), o.subtitle.orEmpty().lowercase(), o.urls.sorted().joinToString())
        val existing = (_state.value as? SessionState.Unlocked)?.entries.orEmpty().map { key(it.overview) }.toMutableSet()
        val added = mutableListOf<VaultEntry>()
        var duplicates = 0
        for (item in items) {
            if (!existing.add(key(item.overview))) {
                duplicates++
                continue
            }
            val record = v.encryptItem(item.overview, item.details)
            storage.upsert(record)
            added += VaultEntry(record, item.overview)
        }
        updateEntries { it + added }
        ExternalImportSummary(added.size, duplicates)
    }.also { if (it.added > 0) onChanged() }

    /** Decrypts every item's details to check them, then drops them. Offline: nothing leaves the device. */
    suspend fun healthReport(): HealthReport = withVault { v ->
        val entries = (_state.value as? SessionState.Unlocked)?.entries.orEmpty()
        val inputs = entries.mapNotNull { entry ->
            val kind = entry.overview.kind
            if (kind != ItemKindRecord.LOGIN && kind != ItemKindRecord.CARD && kind != ItemKindRecord.IDENTITY) return@mapNotNull null
            val details = runCatching { v.decryptDetails(entry.record) }.getOrNull() ?: return@mapNotNull null
            HealthInput(
                id = entry.id,
                isLogin = kind == ItemKindRecord.LOGIN,
                isCard = kind == ItemKindRecord.CARD,
                passwords = details.fields.filter { it.kind == FieldKindRecord.CONCEALED && it.value.isNotBlank() }.map { it.value },
                cardExpiry = details.fields.firstOrNull { it.kind == FieldKindRecord.DATE }?.value,
                updatedAt = entry.overview.updatedAt.toLong(),
                documentExpiry = if (kind != ItemKindRecord.IDENTITY) null else details.fields.let { fields ->
                    // Imported documents may name the field differently; then the last date is the likeliest.
                    fields.firstOrNull { it.kind == FieldKindRecord.DATE && it.label.startsWith("Caducidad") }
                        ?: fields.lastOrNull { it.kind == FieldKindRecord.DATE }
                }?.value,
            )
        }
        VaultHealth.analyze(inputs, java.time.LocalDate.now())
    }

    suspend fun exportBackup(): ByteArray = withVault { v ->
        v.exportBackup(
            storage.items(),
            storage.allAttachments(),
            (System.currentTimeMillis() / 1000).toULong(),
        )
    }

    // ---- Auto-lock ----

    fun onUserInteraction() {
        lastInteraction = SystemClock.elapsedRealtime()
    }

    /**
     * Locks [BACKGROUND_TIMEOUT_MS] after the app leaves the screen, even if it never comes
     * back: otherwise the key would stay in memory and autofill would keep offering logins.
     */
    fun onAppBackgrounded() {
        backgroundedAt = SystemClock.elapsedRealtime()
        backgroundTimeout = if (pickerOpen) PICKER_TIMEOUT_MS else BACKGROUND_TIMEOUT_MS
        mainHandler.removeCallbacks(backgroundLock)
        mainHandler.postDelayed(backgroundLock, backgroundTimeout)
    }

    fun onAppForegrounded() {
        mainHandler.removeCallbacks(backgroundLock)
        pickerOpen = false
        // Backup check: delayed callbacks may not run while the device sleeps.
        val since = backgroundedAt?.let { SystemClock.elapsedRealtime() - it } ?: 0
        backgroundedAt = null
        if (since >= backgroundTimeout) lock()
    }

    /**
     * Call right before opening a system file or folder picker the user asked for: the next
     * trip to the background may last [PICKER_TIMEOUT_MS] instead of [BACKGROUND_TIMEOUT_MS],
     * so browsing for a folder does not lock the vault halfway through an export or import.
     * Applies once; turning the screen off still locks immediately.
     */
    fun beforeSystemPicker() {
        pickerOpen = true
    }

    private var pickerOpen = false
    private var backgroundTimeout = BACKGROUND_TIMEOUT_MS

    private val mainHandler = Handler(Looper.getMainLooper())
    private val backgroundLock = Runnable { lock() }

    /** Called periodically while the app is visible. */
    fun lockIfIdle() {
        if (SystemClock.elapsedRealtime() - lastInteraction >= IDLE_TIMEOUT_MS) lock()
    }

    // ---- Internals ----

    /**
     * The single point where a failed FFI call degrades the session: an [InternalException]
     * (a Rust panic) or an unexpected [OpException.Locked] (the vault is open here but the
     * native key is gone) locks the session and empties the entries.
     */
    private suspend fun <T> withVault(block: (Vault) -> T): T = mutex.withLock {
        try {
            withContext(Dispatchers.Default) { vault.use(block) }
        } catch (e: Exception) {
            if (e !is CancellationException && shouldLockAfter(e, _state.value is SessionState.Unlocked)) lock()
            throw e
        }
    }

    private fun replaceVault(newVault: Vault, loaded: LoadedEntries) {
        vault.replace(newVault)
        lastInteraction = SystemClock.elapsedRealtime()
        _state.value = SessionState.Unlocked(loaded.entries, loaded.unreadable)
        onUnlocked()
    }

    private fun updateEntries(transform: (List<VaultEntry>) -> List<VaultEntry>) {
        val current = _state.value as? SessionState.Unlocked ?: return
        _state.value = current.copy(entries = transform(current.entries))
    }

    private class PrefsAttemptStore(private val prefs: SharedPreferences) : AttemptStore {
        override val failures get() = prefs.getInt(KEY_FAILURES, 0)
        override val lastFailureAt get() = prefs.getLong(KEY_LAST_FAILURE, 0)
        override fun write(failures: Int, lastFailureAt: Long) {
            prefs.edit().putInt(KEY_FAILURES, failures).putLong(KEY_LAST_FAILURE, lastFailureAt).apply()
        }
    }

    companion object {
        /** Runs [block]; if it throws, calls [release] (best effort) and rethrows, so a half-opened vault never keeps its key. */
        internal inline fun <T> discardOnFailure(release: () -> Unit, block: () -> T): T =
            try {
                block()
            } catch (e: Throwable) {
                runCatching(release)
                throw e
            }

        /** True if [error] means the native vault can no longer be trusted. */
        internal fun shouldLockAfter(error: Throwable, sessionUnlocked: Boolean): Boolean =
            error is InternalException || (error is OpException.Locked && sessionUnlocked)

        const val BACKGROUND_TIMEOUT_MS = 30_000L
        const val PICKER_TIMEOUT_MS = 3 * 60_000L
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
    is OpException.WrongSecretKey -> "La clave secreta no corresponde a esta caja fuerte."
    is OpException.InvalidSecretKey -> "La clave secreta no es válida. Revisa si hay erratas."
    is OpException.InvalidInput -> when (reason) {
        "backup too large" -> "La caja fuerte no cabe en una copia de 64 MiB. Borra alguna imagen o reduce su tamaño."
        "image has metadata" -> "La imagen lleva datos de cámara que no se guardan. Prueba con otra foto."
        "image too large" -> "La imagen es demasiado grande. Prueba con una foto más pequeña."
        else -> "Dato no válido: $reason."
    }
    is OpException.Corrupted -> "Los datos están dañados o han sido modificados."
    is OpException.UnsupportedVersion -> "Este fichero es de una versión más nueva de OpenPassword."
    is OpException.KdfTooExpensive ->
        "Esta copia necesita ${mKib / 1024u} MiB de memoria para abrirse y este dispositivo no puede darlos. " +
            "Ábrela en un dispositivo con más memoria."
    is OpException.Locked -> "La caja fuerte está bloqueada."
    is OpException.Internal -> INTERNAL_ERROR_MESSAGE
}

/** Generic message for a failure inside the native core. The panic text is never shown. */
const val INTERNAL_ERROR_MESSAGE = "Ha ocurrido un error interno. Vuelve a desbloquear la caja fuerte."

/** Wipes the key and frees the native handle. */
internal fun Vault.discard() {
    runCatching { lock() }
    runCatching { close() }
}
