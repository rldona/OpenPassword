package io.github.rldona.openpassword

import android.os.Build
import android.os.Bundle
import android.view.MotionEvent
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import io.github.rldona.openpassword.security.excludeFromAutofill
import io.github.rldona.openpassword.security.protectFromOverlays
import io.github.rldona.openpassword.security.warnIfObscured
import io.github.rldona.openpassword.ui.AppRoot
import io.github.rldona.openpassword.ui.theme.OpenPasswordTheme
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import io.github.rldona.openpassword.locale.AppLocales

class MainActivity : ComponentActivity() {

    /** Applies the per-app language on Android 12 and below; 13+ does it in the platform. */
    override fun attachBaseContext(newBase: android.content.Context) {
        val override = AppLocales.overrideFor(newBase)
        if (override != null) applyOverrideConfiguration(override)
        super.attachBaseContext(newBase)
    }
    private val app get() = application as OpenPasswordApp

    override fun onCreate(savedInstanceState: Bundle?) {
        // No screenshots, screen recording or recents thumbnail of any screen.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) setRecentsScreenshotEnabled(false)
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)

        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                while (true) {
                    delay(15_000)
                    app.session.lockIfIdle()
                }
            }
        }

        setContent {
            OpenPasswordTheme {
                AppRoot(session = app.session, clipboard = app.clipboard, autoBackup = app.autoBackup)
            }
        }
        excludeFromAutofill(this)
        protectFromOverlays(this)
    }

    override fun dispatchTouchEvent(ev: MotionEvent): Boolean {
        warnIfObscured(this, ev)
        return super.dispatchTouchEvent(ev)
    }

    override fun onUserInteraction() {
        super.onUserInteraction()
        app.session.onUserInteraction()
    }
}
