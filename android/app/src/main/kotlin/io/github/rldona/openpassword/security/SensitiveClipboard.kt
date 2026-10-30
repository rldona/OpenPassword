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
 * and clears them after [CLEAR_AFTER_MS] if they are still the clip we copied.
 *
 * The typical use is copy here, paste in another app, so at the deadline this app usually has
 * no focus and Android 10+ hides the clipboard from it (ID-INT-14). The design therefore does
 * not depend on an activity being alive or focused:
 * - the deadline is persisted ([PREFS]), so a restarted process still knows a copy is pending;
 * - a main-looper [Handler] of the process tries at the deadline, and `clipboardAction` clears
 *   only if the label shows the clip is still ours;
 * - if the clipboard cannot be read then, nothing is touched and the clear stays pending: it
 *   runs when the app next reaches the foreground ([onForeground], called from the process
 *   lifecycle and `Application.onCreate`) or the screen turns off ([clearIfOurs]).
 *
 * NOT VERIFIED ON A DEVICE (no phone could be used for this): (1) whether `primaryClipDescription`
 * is really null for a background app on API 29, 33 and 36, (2) whether `clearPrimaryClip()` is
 * allowed from the background (if it is, the label check would be the only reason not to clear
 * blindly, and `RETRY_LATER` could become a clear), (3) that the Handler fires while the app is
 * cached. Until then, a password copied and pasted in another app can remain on the clipboard
 * until the user returns to OpenPassword, the screen turns off, or something else is copied.
 * A WorkManager job would not fix (1): it has no focus either.
 */
class SensitiveClipboard(
    context: Context,
    /** Whether the app is in the foreground, i.e. whether Android lets it read the clipboard. */
    private val isForeground: () -> Boolean = { true },
    private val now: () -> Long = System::currentTimeMillis,
) {
    private val clipboard = context.getSystemService(ClipboardManager::class.java)
    private val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    private val handler = Handler(Looper.getMainLooper())
    private val tick = Runnable { evaluate(force = false) }

    fun copy(value: String) {
        val clip = ClipData.newPlainText(LABEL, value)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            clip.description.extras = PersistableBundle().apply {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            }
        }
        clipboard.setPrimaryClip(clip)
        prefs.edit().putLong(KEY_DEADLINE, now() + CLEAR_AFTER_MS).apply()
        schedule(CLEAR_AFTER_MS)
    }

    /** Clears the clipboard now (screen off) if it still holds what we copied. */
    fun clearIfOurs() = evaluate(force = true)

    /** Call when the app reaches the foreground or starts: finishes a clear that was due while it could not read the clipboard. */
    fun onForeground() = evaluate(force = false)

    private fun schedule(delayMs: Long) {
        handler.removeCallbacks(tick)
        handler.postDelayed(tick, delayMs)
    }

    private fun evaluate(force: Boolean) {
        val deadline = prefs.getLong(KEY_DEADLINE, 0).takeIf { it > 0 }
        val action = clipboardAction(
            deadlineAt = deadline,
            now = now(),
            clipLabel = clipboard.primaryClipDescription?.label?.toString(),
            canRead = isForeground(),
            ownLabel = LABEL,
            force = force,
        )
        when (action) {
            ClipboardAction.NOTHING -> Unit
            ClipboardAction.WAIT -> schedule((deadline!! - now()).coerceAtLeast(0))
            ClipboardAction.RETRY_LATER -> Unit
            ClipboardAction.CLEAR -> {
                clipboard.clearPrimaryClip()
                forget()
            }
            ClipboardAction.FORGET -> forget()
        }
    }

    private fun forget() {
        handler.removeCallbacks(tick)
        prefs.edit().remove(KEY_DEADLINE).apply()
    }

    companion object {
        const val CLEAR_AFTER_MS = 30_000L
        private const val LABEL = "OpenPassword"
        private const val PREFS = "clipboard"
        private const val KEY_DEADLINE = "clear_deadline"
    }
}
