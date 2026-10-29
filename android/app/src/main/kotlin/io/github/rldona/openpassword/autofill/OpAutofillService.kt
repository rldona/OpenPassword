package io.github.rldona.openpassword.autofill

import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
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

    override fun onFillRequest(request: FillRequest, cancellationSignal: CancellationSignal, callback: FillCallback) {
        val structure = request.fillContexts.lastOrNull()?.structure ?: return callback.onSuccess(null)
        val login = StructureParser.parse(structure, packageName) ?: return callback.onSuccess(null)
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
            callback.onSuccess(response.build())
        }
        cancellationSignal.setOnCancelListener { job.cancel() }
    }

    // Saving new logins from other apps comes later; nothing is offered for now.
    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) = callback.onSuccess()

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    private companion object {
        const val MAX_DIRECT = 5
    }
}
