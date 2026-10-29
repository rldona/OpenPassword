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
 */
class VaultStorage(context: Context) {
    private val dir = context.noBackupFilesDir
    private val headerFile = File(dir, "vault-header.json")
    private val secretKeyFile = File(dir, "secret-key.bin")
    private val biometricKeyFile = File(dir, "vault-key.biometric")
    private val deviceKeys = DeviceKeyStore()
    private val db = ItemDatabase(context)

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

    private fun atomicWrite(target: File, bytes: ByteArray) {
        val tmp = File(target.parentFile, "${target.name}.tmp")
        tmp.writeBytes(bytes)
        check(tmp.renameTo(target)) { "could not write ${target.name}" }
    }
}
