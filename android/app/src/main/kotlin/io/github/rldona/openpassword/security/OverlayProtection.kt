package io.github.rldona.openpassword.security

import android.app.Activity
import android.os.Build
import android.view.MotionEvent
import android.view.Window
import android.widget.Toast
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.window.DialogWindowProvider
import io.github.rldona.openpassword.R
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** How much of a touch was covered by another app's window when it arrived. */
enum class Obscured { NONE, FULL, PARTIAL }

/**
 * Classifies the flags of a [MotionEvent]. The constants are parameters so the logic
 * can be tested on the JVM with arbitrary values.
 */
fun obscuredTouch(
    flags: Int,
    full: Int = MotionEvent.FLAG_WINDOW_IS_OBSCURED,
    partial: Int = MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED,
): Obscured = when {
    flags and full != 0 -> Obscured.FULL
    flags and partial != 0 -> Obscured.PARTIAL
    else -> Obscured.NONE
}

/** Set as soon as any protected window receives a touch that another app was covering. */
object OverlayWarning {
    private val _detected = MutableStateFlow(false)
    val detected: StateFlow<Boolean> = _detected.asStateFlow()

    /** Returns true only the first time, so the caller can warn once. */
    fun report(): Boolean = _detected.compareAndSet(expect = false, update = true)
}

private fun protectWindow(window: Window) {
    // Android drops touches that arrive while another app's window covers this one.
    window.decorView.filterTouchesWhenObscured = true
    // Android 12+: system-alert overlays of other apps are hidden while this window is on top.
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) window.setHideOverlayWindows(true)
}

/** Anti-tapjacking for the activity's own window. Call after setContent. */
fun protectFromOverlays(activity: Activity) = protectWindow(activity.window)

/**
 * Call from `dispatchTouchEvent` before `super`. A fully covered touch is already discarded
 * by the filter; a partly covered one is delivered (a chat bubble elsewhere is normal).
 * Either way the user is told once.
 */
fun warnIfObscured(activity: Activity, event: MotionEvent) {
    if (obscuredTouch(event.flags) == Obscured.NONE) return
    if (OverlayWarning.report()) {
        Toast.makeText(activity, activity.getString(R.string.overlay_warning), Toast.LENGTH_LONG).show()
    }
}

/**
 * Compose dialogs are separate windows and do not inherit the activity's protection.
 * Place inside the dialog content (done once by ProtectedAlertDialog).
 */
@Composable
fun ProtectDialogWindow() {
    val view = LocalView.current
    SideEffect {
        var node: android.view.ViewParent? = view.parent
        while (node != null && node !is DialogWindowProvider) node = node.parent
        (node as? DialogWindowProvider)?.window?.let(::protectWindow)
    }
}
