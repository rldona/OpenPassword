package io.github.rldona.openpassword.security

import android.content.Context
import android.content.pm.PackageManager
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import kotlinx.coroutines.suspendCancellableCoroutine
import javax.crypto.Cipher
import kotlin.coroutines.resume

sealed interface BiometricResult {
    /** The cipher is now authorized for exactly one operation. */
    data class Success(val cipher: Cipher) : BiometricResult
    data object Cancelled : BiometricResult
    data class Error(val message: String) : BiometricResult
}

/** True if the device has strong (class 3) biometrics enrolled. */
fun strongBiometricsAvailable(context: Context): Boolean {
    val manager = context.getSystemService(BiometricManager::class.java) ?: return false
    return when {
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.R ->
            manager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q ->
            @Suppress("DEPRECATION")
            (manager.canAuthenticate() == BiometricManager.BIOMETRIC_SUCCESS)
        else -> context.packageManager.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)
    }
}

/**
 * Shows the system biometric prompt bound to [cipher]. The Keystore key behind the
 * cipher only works if this authentication succeeds, so the prompt cannot be faked.
 */
suspend fun authenticateBiometric(context: Context, cipher: Cipher, title: String, subtitle: String? = null): BiometricResult =
    suspendCancellableCoroutine { cont ->
        val executor = context.mainExecutor
        val signal = CancellationSignal()
        fun finish(result: BiometricResult) {
            if (cont.isActive) cont.resume(result)
        }

        val prompt = BiometricPrompt.Builder(context)
            .setTitle(title)
            .apply { subtitle?.let(::setSubtitle) }
            .setConfirmationRequired(false)
            .apply {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                }
            }
            .setNegativeButton("Usar contraseña", executor) { _, _ -> finish(BiometricResult.Cancelled) }
            .build()

        prompt.authenticate(
            BiometricPrompt.CryptoObject(cipher),
            signal,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val authorized = result.cryptoObject?.cipher
                    finish(if (authorized != null) BiometricResult.Success(authorized) else BiometricResult.Error("El sistema no devolvió la clave."))
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    // The "Usar contraseña" button arrives through setNegativeButton's listener instead.
                    val cancelled = errorCode == BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED ||
                        errorCode == BiometricPrompt.BIOMETRIC_ERROR_CANCELED
                    finish(if (cancelled) BiometricResult.Cancelled else BiometricResult.Error(errString.toString()))
                }

                // onAuthenticationFailed: one unrecognized finger; the prompt stays open for another try.
            },
        )
        cont.invokeOnCancellation { signal.cancel() }
    }
