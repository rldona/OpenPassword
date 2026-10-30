package io.github.rldona.openpassword.autofill

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.service.autofill.Dataset
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import io.github.rldona.openpassword.core.FieldKindRecord
import io.github.rldona.openpassword.core.ItemDetailsRecord
import io.github.rldona.openpassword.session.VaultEntry
import java.util.concurrent.atomic.AtomicInteger

/** Username and password of a login item, as the autofill framework needs them. */
data class Credentials(val username: String?, val password: String?)

fun ItemDetailsRecord.credentials(): Credentials = Credentials(
    username = fields.firstOrNull { it.kind == FieldKindRecord.EMAIL && it.value.isNotBlank() }?.value
        ?: fields.firstOrNull { it.kind == FieldKindRecord.TEXT && it.value.isNotBlank() }?.value,
    password = fields.firstOrNull { it.kind == FieldKindRecord.CONCEALED && it.value.isNotBlank() }?.value,
)

object Datasets {
    private val requestCodes = AtomicInteger()

    fun presentation(context: Context, text: String) =
        RemoteViews(context.packageName, android.R.layout.simple_list_item_1).apply {
            setTextViewText(android.R.id.text1, text)
        }

    fun label(entry: VaultEntry): String =
        entry.overview.subtitle?.let { "${entry.overview.title} · $it" } ?: entry.overview.title

    /** A suggestion that fills directly. Only built while the vault is unlocked. */
    @Suppress("DEPRECATION") // Dataset.Builder(RemoteViews) + setValue: the API that works from API 28.
    fun direct(context: Context, request: LoginRequest, entry: VaultEntry, credentials: Credentials): Dataset? {
        val builder = Dataset.Builder(presentation(context, label(entry)))
        var any = false
        request.username?.let { id -> credentials.username?.let { builder.setValue(id, AutofillValue.forText(it)); any = true } }
        request.password?.let { id -> credentials.password?.let { builder.setValue(id, AutofillValue.forText(it)); any = true } }
        return if (any) builder.build() else null
    }

    /** A suggestion that opens [AutofillAuthActivity] to unlock and/or pick a login. */
    @Suppress("DEPRECATION")
    fun openApp(context: Context, request: LoginRequest, text: String): Dataset {
        val intent = AutofillAuthActivity.intent(context, AutofillRequestTokens.shared.put(request))
        // Mutable: the framework adds the assist structure to the intent.
        val pending = PendingIntent.getActivity(
            context,
            requestCodes.incrementAndGet(),
            intent,
            PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_MUTABLE,
        )
        val builder = Dataset.Builder(presentation(context, text)).setAuthentication(pending.intentSender)
        request.ids.forEach { builder.setValue(it, null) }
        return builder.build()
    }

    /** The dataset returned by the activity once the user picked a login. */
    @Suppress("DEPRECATION")
    fun filled(context: Context, username: AutofillId?, password: AutofillId?, label: String, credentials: Credentials): Dataset {
        val builder = Dataset.Builder(presentation(context, label))
        username?.let { id -> builder.setValue(id, AutofillValue.forText(credentials.username.orEmpty())) }
        password?.let { id -> builder.setValue(id, AutofillValue.forText(credentials.password.orEmpty())) }
        return builder.build()
    }

    /** Only the random token goes in the Intent; see [AutofillRequestTokens]. */
    fun toIntentExtras(intent: Intent, token: String) = intent.putExtra(EXTRA_TOKEN, token)

    const val EXTRA_TOKEN = "op.autofill.token"

    /** Extras of older versions that carried the target. Never read; the activity strips them. */
    val LEGACY_EXTRAS = listOf("op.autofill.domain", "op.autofill.package", "op.autofill.username", "op.autofill.password")
}
