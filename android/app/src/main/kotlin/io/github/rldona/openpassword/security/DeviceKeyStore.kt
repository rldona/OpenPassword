package io.github.rldona.openpassword.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Seals small secrets (the secret key) with an AES-256-GCM key that never leaves
 * Android Keystore, in StrongBox when the device has one.
 *
 * Format: `version (1) ‖ iv (12) ‖ ciphertext ‖ tag (16)`.
 */
class DeviceKeyStore(private val alias: String = "op-device-key-v1") {
    private val keyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

    fun seal(plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, key()) }
        val iv = cipher.iv
        check(iv.size == IV_LEN) { "unexpected IV length" }
        return byteArrayOf(VERSION) + iv + cipher.doFinal(plaintext)
    }

    fun open(sealed: ByteArray): ByteArray {
        require(sealed.size > 1 + IV_LEN && sealed[0] == VERSION) { "unknown sealed format" }
        val cipher = Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, sealed, 1, IV_LEN))
        }
        return cipher.doFinal(sealed, 1 + IV_LEN, sealed.size - 1 - IV_LEN)
    }

    fun delete() {
        if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
    }

    private fun key(): SecretKey = (keyStore.getKey(alias, null) as? SecretKey) ?: generate()

    private fun generate(): SecretKey {
        fun spec(strongBox: Boolean) = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
            .setUnlockedDeviceRequired(true)
            .setIsStrongBoxBacked(strongBox)
            .build()

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)
        return try {
            generator.init(spec(strongBox = true))
            generator.generateKey()
        } catch (_: StrongBoxUnavailableException) {
            generator.init(spec(strongBox = false))
            generator.generateKey()
        }
    }

    private companion object {
        const val PROVIDER = "AndroidKeyStore"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val VERSION: Byte = 1
        const val IV_LEN = 12
    }
}
