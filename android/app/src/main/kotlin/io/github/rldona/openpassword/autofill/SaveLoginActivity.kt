package io.github.rldona.openpassword.autofill

import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.view.MotionEvent
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.rldona.openpassword.OpenPasswordApp
import io.github.rldona.openpassword.R
import io.github.rldona.openpassword.core.FieldKindRecord
import io.github.rldona.openpassword.core.FieldRecord
import io.github.rldona.openpassword.core.ItemDetailsRecord
import io.github.rldona.openpassword.core.ItemKindRecord
import io.github.rldona.openpassword.core.ItemOverviewRecord
import io.github.rldona.openpassword.core.InternalException
import io.github.rldona.openpassword.core.OpException
import io.github.rldona.openpassword.data.StoredLabels
import io.github.rldona.openpassword.security.excludeFromAutofill
import io.github.rldona.openpassword.security.protectFromOverlays
import io.github.rldona.openpassword.security.warnIfObscured
import io.github.rldona.openpassword.security.strongBiometricsAvailable
import io.github.rldona.openpassword.session.internalMessage
import io.github.rldona.openpassword.session.SessionState
import io.github.rldona.openpassword.session.VaultEntry
import io.github.rldona.openpassword.session.VaultSession
import io.github.rldona.openpassword.session.toUserMessage
import io.github.rldona.openpassword.ui.PasswordField
import io.github.rldona.openpassword.ui.theme.OpenPasswordTheme
import io.github.rldona.openpassword.ui.unlock.UnlockScreen
import io.github.rldona.openpassword.ui.unlock.biometricUnlock
import kotlinx.coroutines.launch
import io.github.rldona.openpassword.locale.AppLocales
import io.github.rldona.openpassword.session.message

/** Confirms saving (or updating) a login typed into another app or a website. */
class SaveLoginActivity : ComponentActivity() {

    /** Applies the per-app language on Android 12 and below; 13+ does it in the platform. */
    override fun attachBaseContext(newBase: android.content.Context) {
        AppLocales.overrideFor(newBase)?.let(::applyOverrideConfiguration)
        super.attachBaseContext(newBase)
    }
    private var token: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) setRecentsScreenshotEnabled(false)
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)

        token = intent.getStringExtra(EXTRA_TOKEN)
        val pending = token?.let(PendingSaves::peek)
        if (pending == null) {
            finish()
            return
        }
        val session = (application as OpenPasswordApp).session

        setContent {
            OpenPasswordTheme {
                val state by session.state.collectAsStateWithLifecycle()
                when (state) {
                    SessionState.NoVault -> LaunchedEffect(Unit) { finish() }
                    SessionState.Locked -> {
                        val context = LocalContext.current
                        val biometric = remember { session.canUseBiometricNow() && strongBiometricsAvailable(context) }
                        UnlockScreen(
                            onUnlock = session::unlock,
                            onBiometric = if (biometric) ({ biometricUnlock(context, session) }) else null,
                            notice = remember { session.passwordRequiredReason()?.message(context.resources) },
                        )
                    }
                    is SessionState.Unlocked -> SaveForm(
                        pending = pending,
                        entries = (state as SessionState.Unlocked).entries,
                        session = session,
                        appLabel = remember { appLabel(pending.target) },
                        onDone = ::finish,
                    )
                }
            }
        }
        excludeFromAutofill(this)
        protectFromOverlays(this)
    }

    override fun dispatchTouchEvent(ev: MotionEvent): Boolean {
        warnIfObscured(this, ev)
        return super.dispatchTouchEvent(ev)
    }

    override fun onDestroy() {
        // Saved or dismissed: the typed password is not kept any longer.
        if (isFinishing) token?.let(PendingSaves::remove)
        super.onDestroy()
    }

    private fun appLabel(target: FillTarget): String? = (target as? FillTarget.App)?.let {
        runCatching { packageManager.getApplicationLabel(packageManager.getApplicationInfo(it.packageName, 0)).toString() }.getOrNull()
    }

    companion object {
        private const val EXTRA_TOKEN = "op.save.token"

        fun intent(context: Context, token: String): Intent =
            Intent(context, SaveLoginActivity::class.java).putExtra(EXTRA_TOKEN, token)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SaveForm(pending: PendingSave, entries: List<VaultEntry>, session: VaultSession, appLabel: String?, onDone: () -> Unit) {
    val res = LocalContext.current.resources
    val target = pending.target
    val where = when (target) {
        is FillTarget.Web -> target.domain.removePrefix("www.")
        is FillTarget.App -> appLabel ?: target.packageName
    }
    var title by remember { mutableStateOf(where) }
    var username by remember { mutableStateOf(pending.username) }
    var password by remember { mutableStateOf(pending.password) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var plan by remember { mutableStateOf<SavePlan>(SavePlan.New) }
    val scope = rememberCoroutineScope()
    val matching = remember(entries) {
        entries.filter { it.overview.kind == ItemKindRecord.LOGIN && LoginMatcher.matches(it.overview.urls, target) }
    }

    // Matching logins keep their username in the encrypted details: decrypt just those.
    LaunchedEffect(matching, username) {
        val candidates = matching.map { entry -> entry.id to runCatching { session.details(entry).credentials().username }.getOrNull() }
        plan = SavePlanner.plan(candidates, username)
    }
    val existing = (plan as? SavePlan.Update)?.let { p -> matching.firstOrNull { it.id == p.entryId } }

    fun save(asNew: Boolean) {
        if (busy || password.isEmpty()) return
        busy = true
        error = null
        scope.launch {
            try {
                val now = (System.currentTimeMillis() / 1000).toULong()
                if (existing != null && !asNew) {
                    val details = session.details(existing)
                    var replaced = false
                    val fields = details.fields.map { f ->
                        if (!replaced && f.kind == FieldKindRecord.CONCEALED) {
                            replaced = true
                            f.copy(value = password)
                        } else {
                            f
                        }
                    }.let { if (replaced) it else it + FieldRecord(StoredLabels.PASSWORD, FieldKindRecord.CONCEALED, password) }
                    session.save(existing, existing.overview.copy(updatedAt = now), details.copy(fields = fields))
                } else {
                    val user = username.trim()
                    val fields = listOfNotNull(
                        user.takeIf(String::isNotEmpty)?.let { FieldRecord(StoredLabels.USERNAME, if ('@' in it) FieldKindRecord.EMAIL else FieldKindRecord.TEXT, it) },
                        FieldRecord(StoredLabels.PASSWORD, FieldKindRecord.CONCEALED, password),
                    )
                    val overview = ItemOverviewRecord(
                        kind = ItemKindRecord.LOGIN,
                        title = title.trim().ifEmpty { where },
                        subtitle = user.ifEmpty { null },
                        urls = listOf(SavePlanner.urlFor(target)),
                        tags = emptyList(),
                        favorite = false,
                        createdAt = now,
                        updatedAt = now,
                    )
                    session.save(null, overview, ItemDetailsRecord(fields, ""))
                }
                onDone()
            } catch (e: OpException) {
                error = e.toUserMessage(res)
                busy = false
            } catch (_: InternalException) {
                error = internalMessage(res)
                busy = false
            }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.save_login_title)) },
                navigationIcon = { IconButton(onClick = onDone) { Icon(Icons.Filled.Close, contentDescription = stringResource(R.string.save_login_close)) } },
            )
        },
    ) { padding ->
        Column(
            Modifier.padding(padding).imePadding().fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(stringResource(R.string.save_login_for, where), color = MaterialTheme.colorScheme.onSurfaceVariant)
            if (existing == null) {
                OutlinedTextField(
                    value = title,
                    onValueChange = { title = it },
                    label = { Text(stringResource(R.string.item_editor_name)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            OutlinedTextField(
                value = username,
                onValueChange = { username = it },
                label = { Text(stringResource(R.string.field_username)) },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email, imeAction = ImeAction.Next, autoCorrectEnabled = false),
                modifier = Modifier.fillMaxWidth(),
            )
            PasswordField(value = password, onValueChange = { password = it }, label = stringResource(R.string.field_password), modifier = Modifier.fillMaxWidth())
            error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            if (existing != null) {
                Text(
                    stringResource(R.string.save_login_update_notice, existing.overview.title),
                    style = MaterialTheme.typography.bodyMedium,
                )
                Button(onClick = { save(asNew = false) }, enabled = !busy && password.isNotEmpty(), modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.save_login_update_action, existing.overview.title))
                }
                OutlinedButton(onClick = { save(asNew = true) }, enabled = !busy && password.isNotEmpty(), modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.save_login_save_as_new))
                }
            } else {
                Button(onClick = { save(asNew = true) }, enabled = !busy && password.isNotEmpty(), modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.item_editor_save))
                }
            }
        }
    }
}
