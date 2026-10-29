package io.github.rldona.openpassword.security

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * AES-256-GCM key that seals the vault key for biometric unlock (crypto-spec section 9).
 *
 * Every use needs a fresh strong-biometric authentication (no timeout), the key is
 * destroyed by Android when a new fingerprint or face is enrolled, and it only works
 * while the device is unlocked. In StrongBox when available.
 */
class BiometricKeyStore(private val alias: String = "op-biometric-key-v1") {
    private val keyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

    /** A fresh key and a cipher ready to seal the vault key once the user authenticates. */
    fun newEncryptCipher(): Cipher {
        delete()
        return Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, generate()) }
    }

    /** @throws KeyPermanentlyInvalidatedException if biometrics changed since the key was created. */
    fun decryptCipher(iv: ByteArray): Cipher {
        val key = keyStore.getKey(alias, null) as? SecretKey ?: throw KeyPermanentlyInvalidatedException()
        return Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv)) }
    }

    fun delete() {
        if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
    }

    private fun generate(): SecretKey {
        fun spec(strongBox: Boolean) = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        ).apply {
            setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            setKeySize(256)
            setUserAuthenticationRequired(true)
            setInvalidatedByBiometricEnrollment(true)
            setUnlockedDeviceRequired(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                // 0 s: a new authentication for every single use.
                setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            }
            setIsStrongBoxBacked(strongBox)
        }.build()

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
    }
}
