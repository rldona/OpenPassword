package io.github.rldona.openpassword.security

import android.app.Activity
import android.view.View

/**
 * Hides every field of [activity] from all autofill services, including the device's
 * default one (e.g. Google's), so none can read or offer to save the master password or
 * the secrets typed into the vault. Call after setContent.
 */
fun excludeFromAutofill(activity: Activity) {
    activity.window.decorView.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
}
