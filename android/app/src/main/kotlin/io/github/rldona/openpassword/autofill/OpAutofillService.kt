package io.github.rldona.openpassword.autofill

import android.app.PendingIntent
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveInfo
import android.service.autofill.SaveRequest
import io.github.rldona.openpassword.OpenPasswordApp
import io.github.rldona.openpassword.core.ItemKindRecord
import io.github.rldona.openpassword.session.SessionState
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * Offers logins to other apps and browsers. Never fills on its own: Android shows the
 * suggestions and fills only the one the user taps.
 */
class OpAutofillService : AutofillService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private val browsers by lazy { CachedBrowserCheck.forPackageManager(packageManager) }

    override fun onConnected() {
        // Build the browser list off the main thread, before the first fill request needs it.
        scope.launch(Dispatchers.Default) { browsers.warm() }
    }

    override fun onFillRequest(request: FillRequest, cancellationSignal: CancellationSignal, callback: FillCallback) {
        val structure = request.fillContexts.lastOrNull()?.structure ?: return callback.onSuccess(null)
        val login = StructureParser.parse(structure, packageName, browsers) ?: return callback.onSuccess(null)
        val session = (application as OpenPasswordApp).session

        val job = scope.launch {
            val response = FillResponse.Builder()
            val state = session.state.value
            if (state is SessionState.Unlocked) {
                state.entries
                    .filter { it.overview.kind == ItemKindRecord.LOGIN && LoginMatcher.matches(it.overview.urls, login.target) }
                    .take(MAX_DIRECT)
                    .forEach { entry ->
                        val credentials = runCatching { session.details(entry).credentials() }.getOrNull() ?: return@forEach
                        Datasets.direct(this@OpAutofillService, login, entry, credentials)?.let(response::addDataset)
                    }
            }
            val openText = if (state is SessionState.Unlocked) "Buscar en OpenPassword" else "Desbloquear OpenPassword"
            response.addDataset(Datasets.openApp(this@OpAutofillService, login, openText))
            // Ask Android to offer "save to OpenPassword" when the user submits a password.
            login.password?.let { passwordId ->
                val types = SaveInfo.SAVE_DATA_TYPE_PASSWORD or (if (login.username != null) SaveInfo.SAVE_DATA_TYPE_USERNAME else 0)
                val save = SaveInfo.Builder(types, arrayOf(passwordId))
                    .apply { login.username?.let { setOptionalIds(arrayOf(it)) } }
                    // Apps often hide the form instead of finishing the activity after login.
                    .setFlags(SaveInfo.FLAG_SAVE_ON_ALL_VIEWS_INVISIBLE)
                    .build()
                response.setSaveInfo(save)
            }
            callback.onSuccess(response.build())
        }
        cancellationSignal.setOnCancelListener { job.cancel() }
    }

    /**
     * The user accepted "save to OpenPassword". The values stay in this process's memory;
     * the confirmation window gets only a token. Nothing is stored until the user confirms.
     */
    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        val structures = request.fillContexts.map { it.structure }
        val login = structures.lastOrNull()?.let { StructureParser.parse(it, packageName, browsers) }
        val password = login?.password?.let { StructureParser.textValue(structures, it) }
        if (login == null || password.isNullOrEmpty()) return callback.onSuccess()
        val username = login.username?.let { StructureParser.textValue(structures, it) }.orEmpty()

        val token = PendingSaves.put(PendingSave(login.target, username, password))
        val pending = PendingIntent.getActivity(
            this,
            token.hashCode(),
            SaveLoginActivity.intent(this, token),
            PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        callback.onSuccess(pending.intentSender)
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    private companion object {
        const val MAX_DIRECT = 5
    }
}
