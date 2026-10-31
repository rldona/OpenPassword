package io.github.rldona.openpassword.security

import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import androidx.annotation.RequiresApi
import io.github.rldona.openpassword.R
import kotlinx.coroutines.suspendCancellableCoroutine
import javax.crypto.Cipher
import kotlin.coroutines.resume

sealed interface BiometricResult {
    /** The cipher is now authorized for exactly one operation. */
    data class Success(val cipher: Cipher) : BiometricResult
    data object Cancelled : BiometricResult
    data class Error(val message: String) : BiometricResult
}

/** How to ask the system whether strong biometrics are available, by Android version. */
internal enum class AvailabilityCheck {
    /** API 30+: BiometricManager with an explicit BIOMETRIC_STRONG authenticator. */
    ManagerStrong,

    /** API 29: BiometricManager without authenticators (the only form it has). */
    ManagerLegacy,

    /** API 28: no BiometricManager; the prompt is fingerprint-only, so ask FingerprintManager. */
    Fingerprint,
}

internal fun availabilityCheckFor(sdkInt: Int): AvailabilityCheck = when {
    sdkInt >= Build.VERSION_CODES.R -> AvailabilityCheck.ManagerStrong
    sdkInt >= Build.VERSION_CODES.Q -> AvailabilityCheck.ManagerLegacy
    else -> AvailabilityCheck.Fingerprint
}

/**
 * True if the device has strong (class 3) biometrics enrolled.
 * The branch is chosen by [availabilityCheckFor] (unit-tested), which lint cannot follow, hence the suppression.
 */
@SuppressLint("NewApi")
fun strongBiometricsAvailable(context: Context): Boolean = when (availabilityCheckFor(Build.VERSION.SDK_INT)) {
    AvailabilityCheck.ManagerStrong -> managerAvailable(context, strong = true)
    AvailabilityCheck.ManagerLegacy -> managerAvailable(context, strong = false)
    AvailabilityCheck.Fingerprint -> fingerprintAvailable(context)
}

@RequiresApi(Build.VERSION_CODES.Q)
private fun managerAvailable(context: Context, strong: Boolean): Boolean {
    val manager = context.getSystemService(BiometricManager::class.java) ?: return false
    val result = if (strong && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        manager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
    } else {
        @Suppress("DEPRECATION")
        manager.canAuthenticate()
    }
    return result == BiometricManager.BIOMETRIC_SUCCESS
}

/**
 * Android 9: fingerprints are the only biometric the platform prompt supports.
 * FingerprintManager is gone from the compileSdk 37 stubs, so it is called by reflection;
 * it still exists at runtime on the API 28 devices this branch is for.
 */
private fun fingerprintAvailable(context: Context): Boolean {
    if (!context.packageManager.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)) return false
    val manager = context.getSystemService("fingerprint") ?: return false
    fun ask(method: String): Boolean = manager.javaClass.getMethod(method).invoke(manager) == true
    return runCatching { ask("isHardwareDetected") && ask("hasEnrolledFingerprints") }.getOrDefault(false)
}

/**
 * Shows the system biometric prompt bound to [cipher]. The Keystore key behind the
 * cipher only works if this authentication succeeds, so the prompt cannot be faked.
 */
suspend fun authenticateBiometric(
    context: Context,
    cipher: Cipher,
    title: String,
    subtitle: String? = null,
    negativeButton: String,
): BiometricResult =
    suspendCancellableCoroutine { cont ->
        val executor = context.mainExecutor
        val signal = CancellationSignal()
        fun finish(result: BiometricResult) {
            if (cont.isActive) cont.resume(result)
        }

        val prompt = BiometricPrompt.Builder(context)
            .setTitle(title)
            .apply { subtitle?.let(::setSubtitle) }
            .apply {
                // Both are API 29+ / 30+; on Android 9 the prompt is fingerprint-only and always asks to confirm.
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) setConfirmationRequired(false)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                }
            }
            .setNegativeButton(negativeButton, executor) { _, _ -> finish(BiometricResult.Cancelled) }
            .build()

        prompt.authenticate(
            BiometricPrompt.CryptoObject(cipher),
            signal,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val authorized = result.cryptoObject?.cipher
                    finish(if (authorized != null) BiometricResult.Success(authorized) else BiometricResult.Error(context.getString(R.string.error_biometric_no_key)))
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    // The negative button arrives through setNegativeButton's listener instead.
                    val cancelled = errorCode == BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED ||
                        errorCode == BiometricPrompt.BIOMETRIC_ERROR_CANCELED
                    finish(if (cancelled) BiometricResult.Cancelled else BiometricResult.Error(errString.toString()))
                }

                // onAuthenticationFailed: one unrecognized finger; the prompt stays open for another try.
            },
        )
        cont.invokeOnCancellation { signal.cancel() }
    }
