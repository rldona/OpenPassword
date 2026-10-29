package io.github.rldona.openpassword

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import io.github.rldona.openpassword.ui.AppRoot
import io.github.rldona.openpassword.ui.theme.OpenPasswordTheme
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    private val app get() = application as OpenPasswordApp

    /** Locks as soon as the screen turns off. */
    private val screenOffReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            app.session.lock()
            app.clipboard.clearIfOurs()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        // No screenshots, screen recording or recents thumbnail of any screen.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) setRecentsScreenshotEnabled(false)
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)

        registerReceiver(screenOffReceiver, IntentFilter(Intent.ACTION_SCREEN_OFF))
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
                AppRoot(session = app.session, clipboard = app.clipboard)
            }
        }
    }

    override fun onUserInteraction() {
        super.onUserInteraction()
        app.session.onUserInteraction()
    }

    override fun onDestroy() {
        unregisterReceiver(screenOffReceiver)
        super.onDestroy()
    }
}
