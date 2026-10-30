package io.github.rldona.openpassword.data

import android.content.Context
import io.github.rldona.openpassword.core.EncryptedItemRecord
import io.github.rldona.openpassword.security.DeviceKeyStore
import java.io.File

/**
 * Everything the app persists, all under `noBackupFilesDir` or the app database:
 * - the vault header (no user data),
 * - the secret key, sealed with Android Keystore,
 * - optionally, the vault key sealed with a biometric-bound Keystore key,
 * - the encrypted items.
 *
 * [namespace] keeps separate vaults apart (files, database and Keystore alias). The app
 * uses the default; tests use their own so they never touch real data.
 */
class VaultStorage(context: Context, namespace: String = "") {
    private val prefix = if (namespace.isEmpty()) "" else "$namespace-"
    private val dir = context.noBackupFilesDir
    private val headerFile = File(dir, "${prefix}vault-header.json")
    private val secretKeyFile = File(dir, "${prefix}secret-key.bin")
    private val biometricKeyFile = File(dir, "${prefix}vault-key.biometric")
    private val deviceKeys = DeviceKeyStore(alias = "${prefix}op-device-key-v1")
    private val db = ItemDatabase(context, name = "${prefix}items.db")

    /** Deletes every file and the Keystore key of this namespace. For tests. */
    fun destroy(context: Context) {
        db.close()
        context.deleteDatabase(db.databaseName)
        listOf(headerFile, secretKeyFile, biometricKeyFile).forEach(File::delete)
        deviceKeys.delete()
    }

    fun hasVault(): Boolean = headerFile.exists() && secretKeyFile.exists()

    fun readHeader(): String = headerFile.readText()

    fun writeHeader(json: String) = atomicWrite(headerFile, json.toByteArray())

    fun saveSecretKey(secretKey: String) = atomicWrite(secretKeyFile, deviceKeys.seal(secretKey.toByteArray()))

    fun loadSecretKey(): String {
        val bytes = deviceKeys.open(secretKeyFile.readBytes())
        return try {
            String(bytes)
        } finally {
            bytes.fill(0)
        }
    }

    fun hasBiometricVaultKey(): Boolean = biometricKeyFile.exists()

    /** Format: `version (1) ‖ iv (12) ‖ ciphertext ‖ tag`, sealed by [io.github.rldona.openpassword.security.BiometricKeyStore]. */
    fun readBiometricVaultKey(): ByteArray = biometricKeyFile.readBytes()

    fun writeBiometricVaultKey(sealed: ByteArray) = atomicWrite(biometricKeyFile, sealed)

    fun deleteBiometricVaultKey() {
        biometricKeyFile.delete()
    }

    fun items(): List<EncryptedItemRecord> = db.all()

    fun upsert(item: EncryptedItemRecord) = db.upsert(item)

    fun delete(id: String) = db.delete(id)

    /** Removes leftover rows, e.g. from a restore that failed half way. */
    fun clearItems() = db.clear()
}
