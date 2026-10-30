package io.github.rldona.openpassword

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.view.View
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.compose.material3.Text
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.window.DialogWindowProvider
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.rldona.openpassword.autofill.AutofillAuthActivity
import io.github.rldona.openpassword.autofill.AutofillRequestTokens
import io.github.rldona.openpassword.autofill.FillTarget
import io.github.rldona.openpassword.autofill.LoginRequest
import io.github.rldona.openpassword.autofill.PendingSave
import io.github.rldona.openpassword.autofill.PendingSaves
import io.github.rldona.openpassword.autofill.SaveLoginActivity
import io.github.rldona.openpassword.session.SessionState
import io.github.rldona.openpassword.ui.ProtectedAlertDialog
import io.github.rldona.openpassword.ui.theme.OpenPasswordTheme
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeFalse
import org.junit.Test
import org.junit.runner.RunWith

/**
 * ADR-AUD-06 / ID-INT-13: every window that can show secrets is protected against overlays
 * (tapjacking) and screenshots: the three activities and the dialogs.
 *
 * NOT run automatically and NOT to be run on a phone with real data: it launches the real
 * activities. Run only on an emulator or a device without data. It never unlocks the vault.
 *
 * - [AutofillAuthActivity] and [SaveLoginActivity] close themselves when there is no vault, so
 *   those two tests are skipped (assumption) unless the app already has a vault (it stays locked).
 * - Not covered here: `setHideOverlayWindows` (Android 12+) has no getter, and the
 *   `OverlayWarningBanner` exists only in `MainActivity`; the autofill activities warn with the
 *   same one-time `Toast`. A touch with `FLAG_WINDOW_IS_OBSCURED` needs a real overlay window.
 */
@RunWith(AndroidJUnit4::class)
class OverlayProtectionTest {
    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext
    private val app get() = context.applicationContext as OpenPasswordApp

    private fun assertProtected(activity: Activity) {
        assertTrue("filterTouchesWhenObscured", activity.window.decorView.filterTouchesWhenObscured)
        assertEquals(
            "FLAG_SECURE",
            WindowManager.LayoutParams.FLAG_SECURE,
            activity.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE,
        )
    }

    @Test
    fun mainActivityWindowIsProtected() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity(::assertProtected)
        }
    }

    @Test
    fun autofillAuthActivityWindowIsProtected() {
        assumeFalse("needs an existing vault, or the activity closes itself", app.session.state.value is SessionState.NoVault)
        val request = LoginRequest(FillTarget.App("com.example.test"), View(context).autofillId, null)
        val token = AutofillRequestTokens.shared.put(request)
        try {
            ActivityScenario.launch<AutofillAuthActivity>(AutofillAuthActivity.intent(context, token)).use { scenario ->
                scenario.onActivity(::assertProtected)
            }
        } finally {
            AutofillRequestTokens.shared.discard(token)
        }
    }

    @Test
    fun saveLoginActivityWindowIsProtected() {
        assumeFalse("needs an existing vault, or the activity closes itself", app.session.state.value is SessionState.NoVault)
        val token = PendingSaves.put(PendingSave(FillTarget.App("com.example.test"), "usuario", "no-es-real"))
        try {
            val intent: Intent = SaveLoginActivity.intent(context, token)
            ActivityScenario.launch<SaveLoginActivity>(intent).use { scenario ->
                scenario.onActivity(::assertProtected)
            }
        } finally {
            PendingSaves.remove(token)
        }
    }

    @Test
    fun protectedAlertDialogWindowIsProtected() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            var dialogView: View? = null
            val composed = CountDownLatch(1)
            scenario.onActivity { activity ->
                // Replaces the screen of this throwaway launch: only a dialog with fixed text.
                activity.setContent {
                    OpenPasswordTheme {
                        ProtectedAlertDialog(
                            onDismissRequest = {},
                            confirmButton = {},
                            text = {
                                val view = LocalView.current
                                // Runs after ProtectDialogWindow's own SideEffect in the same dialog.
                                SideEffect {
                                    dialogView = view
                                    composed.countDown()
                                }
                                Text("Prueba")
                            },
                        )
                    }
                }
            }
            assertTrue("the dialog was not composed in time", composed.await(10, TimeUnit.SECONDS))
            scenario.onActivity {
                var node = dialogView?.parent
                while (node != null && node !is DialogWindowProvider) node = node.parent
                val window = (node as? DialogWindowProvider)?.window
                assertNotNull("no DialogWindowProvider above the dialog content", window)
                assertTrue("filterTouchesWhenObscured", window!!.decorView.filterTouchesWhenObscured)
            }
        }
    }
}
