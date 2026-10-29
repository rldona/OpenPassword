package io.github.rldona.openpassword.ui.unlock

import android.content.Context
import io.github.rldona.openpassword.core.OpException
import io.github.rldona.openpassword.security.BiometricResult
import io.github.rldona.openpassword.security.authenticateBiometric
import io.github.rldona.openpassword.session.UnlockResult
import io.github.rldona.openpassword.session.VaultSession
import io.github.rldona.openpassword.session.toUserMessage

/** Unlocks with the fingerprint. Null if the user dismissed the prompt. */
suspend fun biometricUnlock(context: Context, session: VaultSession): UnlockResult? {
    val cipher = session.biometricUnlockCipher() ?: return UnlockResult.Failed(
        "Las huellas del teléfono han cambiado, así que hemos desactivado el desbloqueo con huella. " +
            "Usa tu contraseña maestra y vuelve a activarlo en Ajustes.",
    )
    return when (val result = authenticateBiometric(context, cipher, "Desbloquear OpenPassword")) {
        is BiometricResult.Success -> session.unlockWithBiometric(result.cipher)
        BiometricResult.Cancelled -> null
        is BiometricResult.Error -> UnlockResult.Failed(result.message)
    }
}

/** Turns biometric unlock on. Returns the message to show. */
suspend fun enableBiometricUnlock(context: Context, session: VaultSession): String? {
    val cipher = session.biometricEnableCipher()
    return when (val result = authenticateBiometric(context, cipher, "Activar desbloqueo con huella", "Confirma con tu huella")) {
        is BiometricResult.Success -> try {
            session.enableBiometric(result.cipher)
            "Desbloqueo con huella activado. Te pediremos la contraseña cada 14 días y tras reiniciar."
        } catch (e: OpException) {
            session.disableBiometric()
            e.toUserMessage()
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
