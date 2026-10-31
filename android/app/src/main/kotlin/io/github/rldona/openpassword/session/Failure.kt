package io.github.rldona.openpassword.session

import android.content.res.Resources
import io.github.rldona.openpassword.R
import io.github.rldona.openpassword.core.InternalException
import io.github.rldona.openpassword.core.OpException

/**
 * Why an operation failed, as data. The layer that produced it does not know the interface
 * language; whoever paints it resolves the text.
 */
sealed interface Failure {
    data class Core(val error: OpException) : Failure
    data object Internal : Failure
    data object BiometricUnusable : Failure
    data object PasswordCheckFailed : Failure
    data object BiometricsChanged : Failure
    /** Text the platform already localized (a biometric error), shown as it arrives. */
    data class System(val text: String) : Failure
}

/** Why the master password is being asked for again. */
enum class PasswordReason { REBOOTED, PERIODIC }

fun Failure.message(res: Resources): String = when (this) {
    is Failure.Core -> error.toUserMessage(res)
    Failure.Internal -> res.getString(R.string.error_internal)
    Failure.BiometricUnusable -> res.getString(R.string.error_biometric_unusable)
    Failure.PasswordCheckFailed -> res.getString(R.string.error_password_check_failed)
    Failure.BiometricsChanged -> res.getString(R.string.error_biometrics_changed)
    is Failure.System -> text
}

fun PasswordReason.message(res: Resources): String = when (this) {
    PasswordReason.REBOOTED -> res.getString(R.string.password_reason_rebooted)
    PasswordReason.PERIODIC -> res.getString(R.string.password_reason_periodic)
}

/** The internal error, for the places that only have a flag instead of a caught exception. */
fun internalMessage(res: Resources): String = res.getString(R.string.error_internal)

/**
 * User-facing text for a core exception. Reasons that are not in the table show a generic
 * message instead of leaking the developer-facing English string.
 */
fun OpException.toUserMessage(res: Resources): String = when (this) {
    is OpException.WrongCredentials -> res.getString(R.string.error_wrong_credentials)
    is OpException.WrongSecretKey -> res.getString(R.string.error_wrong_secret_key)
    is OpException.InvalidSecretKey -> res.getString(R.string.error_invalid_secret_key)
    is OpException.InvalidInput -> when (reason) {
        "backup too large" -> res.getString(R.string.error_backup_too_large)
        "image has metadata" -> res.getString(R.string.error_image_metadata)
        "image too large" -> res.getString(R.string.error_image_too_large)
        else -> res.getString(R.string.error_invalid_data)
    }
    is OpException.Corrupted -> res.getString(R.string.error_corrupted)
    is OpException.UnsupportedVersion -> res.getString(R.string.error_unsupported_version)
    is OpException.KdfTooExpensive -> res.getString(R.string.error_kdf_too_expensive, (mKib / 1024u).toLong())
    is OpException.Locked -> res.getString(R.string.error_locked)
    is OpException.Internal -> res.getString(R.string.error_internal)
}

/** Same message for an [InternalException], which carries nothing to translate. */
fun InternalException.toUserMessage(res: Resources): String = internalMessage(res)
