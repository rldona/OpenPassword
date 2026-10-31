package io.github.rldona.openpassword.ui.text

import android.content.res.Resources
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalContext
import io.github.rldona.openpassword.R
import io.github.rldona.openpassword.backup.BackupError

/** User-facing text for the automatic backup state. */
fun BackupError.message(res: Resources): String = res.getString(
    when (this) {
        BackupError.DISABLED -> R.string.backup_error_disabled
        BackupError.LOCKED -> R.string.backup_error_locked
        BackupError.ENCRYPT_FAILED -> R.string.backup_error_encrypt
        BackupError.PERMISSION_LOST -> R.string.backup_error_permission
        BackupError.WRITE_FAILED -> R.string.backup_error_write
        BackupError.LEGACY -> R.string.backup_error_legacy
    },
)

@Composable
fun backupErrorText(error: BackupError): String = error.message(LocalContext.current.resources)
