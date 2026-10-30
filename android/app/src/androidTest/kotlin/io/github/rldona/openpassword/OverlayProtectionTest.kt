package io.github.rldona.openpassword

import android.view.WindowManager
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * NOT run automatically on the author's phone: it launches the real activity, which touches
 * the real vault. Run only on an emulator or a device without data.
 * Pending: AutofillAuthActivity / SaveLoginActivity (need autofill intents) and the dialogs
 * (a Compose UI test with a delivered FLAG_WINDOW_IS_OBSCURED touch).
 */
@RunWith(AndroidJUnit4::class)
class OverlayProtectionTest {
    @Test
    fun mainActivityWindowIsProtected() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                assertTrue(activity.window.decorView.filterTouchesWhenObscured)
                assertEquals(
                    WindowManager.LayoutParams.FLAG_SECURE,
                    activity.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE,
                )
            }
        }
    }
}
