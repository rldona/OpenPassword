package io.github.rldona.openpassword.security

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle

/**
 * Copies secrets marked as sensitive (hidden from the clipboard preview on Android 13+)
 * and clears them after [CLEAR_AFTER_MS] if they are still the current clip.
 */
class SensitiveClipboard(context: Context) {
    private val clipboard = context.getSystemService(ClipboardManager::class.java)
    private val handler = Handler(Looper.getMainLooper())
    private var pendingClear: Runnable? = null

    fun copy(value: String) {
        val clip = ClipData.newPlainText(LABEL, value)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            clip.description.extras = PersistableBundle().apply {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            }
        }
        clipboard.setPrimaryClip(clip)
        pendingClear?.let(handler::removeCallbacks)
        pendingClear = Runnable { clearIfOurs() }.also { handler.postDelayed(it, CLEAR_AFTER_MS) }
    }

    /** Clears the clipboard only if it still holds what we copied. */
    fun clearIfOurs() {
        pendingClear?.let(handler::removeCallbacks)
        pendingClear = null
        // Android 10+ may deny clipboard access in the background: then the description is null.
        if (clipboard.primaryClipDescription?.label == LABEL) clipboard.clearPrimaryClip()
    }

    companion object {
        const val CLEAR_AFTER_MS = 30_000L
        private const val LABEL = "OpenPassword"
    }
}
