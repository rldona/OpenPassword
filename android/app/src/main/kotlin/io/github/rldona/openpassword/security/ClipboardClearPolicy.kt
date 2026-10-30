package io.github.rldona.openpassword.security

/** What to do with the clipboard we marked, at a given moment (ID-INT-14). */
enum class ClipboardAction {
    /** Nothing was copied by us, or it is already handled. */
    NOTHING,

    /** Not due yet. */
    WAIT,

    /** The clipboard still holds what we copied and it is due: empty it. */
    CLEAR,

    /** Due, but we cannot see the clipboard from here (background): do not touch it, try again later. */
    RETRY_LATER,

    /** Due, and the clipboard now holds something that is not ours (or nothing): leave it alone and stop tracking. */
    FORGET,
}

/**
 * The decision, free of Android so it can be tested on the JVM.
 *
 * - [deadlineAt]: wall-clock time (ms) after which the copy must be cleared, or null if we have
 *   nothing pending. Wall clock, not uptime, because it is persisted and must survive the process.
 * - [clipLabel]: label of the current clip, or null if there is none **or Android denied the read**
 *   (since Android 10 only the focused app can read the clipboard).
 * - [canRead]: whether this app can currently read the clipboard (it is in the foreground).
 *
 * Foreign content is never cleared: the label is compared first, and when the clipboard cannot be
 * read the answer is to wait until it can, never to clear blindly.
 * [force] ignores the deadline (screen off, app returns to the foreground after the deadline).
 */
fun clipboardAction(
    deadlineAt: Long?,
    now: Long,
    clipLabel: String?,
    canRead: Boolean,
    ownLabel: String,
    force: Boolean = false,
): ClipboardAction = when {
    deadlineAt == null -> ClipboardAction.NOTHING
    !force && now < deadlineAt -> ClipboardAction.WAIT
    clipLabel == ownLabel -> ClipboardAction.CLEAR
    clipLabel != null -> ClipboardAction.FORGET
    canRead -> ClipboardAction.FORGET
    else -> ClipboardAction.RETRY_LATER
}
