package io.github.rldona.openpassword.ui.unlock

import android.content.Context
import io.github.rldona.openpassword.R
import io.github.rldona.openpassword.core.InternalException
import io.github.rldona.openpassword.core.OpException
import io.github.rldona.openpassword.security.BiometricResult
import io.github.rldona.openpassword.security.authenticateBiometric
import io.github.rldona.openpassword.session.Failure
import io.github.rldona.openpassword.session.UnlockResult
import io.github.rldona.openpassword.session.VaultSession
import io.github.rldona.openpassword.session.message
import io.github.rldona.openpassword.session.toUserMessage

/** Unlocks with the fingerprint. Null if the user dismissed the prompt. */
suspend fun biometricUnlock(context: Context, session: VaultSession): UnlockResult? {
    val cipher = session.biometricUnlockCipher()
        ?: return UnlockResult.Failed(Failure.BiometricsChanged)
    val title = context.getString(R.string.biometric_unlock_title)
    val negativeButton = context.getString(R.string.biometric_use_password)
    return when (val result = authenticateBiometric(context, cipher, title, negativeButton = negativeButton)) {
        is BiometricResult.Success -> session.unlockWithBiometric(result.cipher)
        BiometricResult.Cancelled -> null
        is BiometricResult.Error -> UnlockResult.Failed(Failure.System(result.message))
    }
}

/** Turns biometric unlock on. Returns the message to show. */
suspend fun enableBiometricUnlock(context: Context, session: VaultSession): String? {
    val res = context.resources
    val cipher = session.biometricEnableCipher()
    val title = context.getString(R.string.biometric_enable_title)
    val subtitle = context.getString(R.string.biometric_enable_subtitle)
    val negativeButton = context.getString(R.string.biometric_use_password)
    return when (val result = authenticateBiometric(context, cipher, title, subtitle, negativeButton = negativeButton)) {
        is BiometricResult.Success -> try {
            session.enableBiometric(result.cipher)
            context.getString(R.string.biometric_enabled)
        } catch (e: OpException) {
            session.disableBiometric()
            e.toUserMessage(res)
        } catch (_: InternalException) {
            session.disableBiometric()
            Failure.Internal.message(res)
        }
        BiometricResult.Cancelled -> {
            session.disableBiometric()
            null
        }
        is BiometricResult.Error -> {
            session.disableBiometric()
            result.message
        }
    }
}
