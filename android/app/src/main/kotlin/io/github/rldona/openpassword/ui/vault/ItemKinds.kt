package io.github.rldona.openpassword.ui.vault

import androidx.annotation.StringRes
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import io.github.rldona.openpassword.R
import io.github.rldona.openpassword.core.FieldKindRecord
import io.github.rldona.openpassword.core.FieldRecord
import io.github.rldona.openpassword.core.ItemKindRecord
import io.github.rldona.openpassword.core.ItemKindRecord.BANK_ACCOUNT
import io.github.rldona.openpassword.core.ItemKindRecord.CARD
import io.github.rldona.openpassword.core.ItemKindRecord.IDENTITY
import io.github.rldona.openpassword.core.ItemKindRecord.LOGIN
import io.github.rldona.openpassword.core.ItemKindRecord.PIN
import io.github.rldona.openpassword.core.ItemKindRecord.SECRET
import io.github.rldona.openpassword.core.ItemKindRecord.SECURE_NOTE
import io.github.rldona.openpassword.core.ItemKindRecord.WIFI
import io.github.rldona.openpassword.data.StoredLabels
import java.text.Normalizer

/** Item types offered by "+", in menu order. */
val CreatableKinds = listOf(LOGIN, CARD, BANK_ACCOUNT, PIN, IDENTITY, WIFI, SECRET, SECURE_NOTE)

@get:StringRes
val ItemKindRecord.labelRes: Int
    get() = when (this) {
        LOGIN -> R.string.kind_login
        CARD -> R.string.kind_card
        PIN -> R.string.kind_pin
        SECURE_NOTE -> R.string.kind_note
        SECRET -> R.string.kind_secret
        BANK_ACCOUNT -> R.string.kind_bank_account
        IDENTITY -> R.string.kind_document
        WIFI -> R.string.kind_wifi
    }

@get:StringRes
val ItemKindRecord.shortLabelRes: Int
    get() = when (this) {
        LOGIN -> R.string.kind_login_plural
        CARD -> R.string.kind_card_plural
        PIN -> R.string.kind_pin_plural
        SECURE_NOTE -> R.string.kind_note_plural
        SECRET -> R.string.kind_secret_plural
        BANK_ACCOUNT -> R.string.kind_bank_account_plural
        IDENTITY -> R.string.kind_document_plural
        WIFI -> R.string.kind_wifi
    }

@Composable
fun ItemKindRecord.labelText(): String = stringResource(labelRes)

@Composable
fun ItemKindRecord.shortLabelText(): String = stringResource(shortLabelRes)

fun ItemKindRecord.avatarColor(): Color = when (this) {
    LOGIN -> Color(0xFF3D5A80)
    CARD -> Color(0xFF0E6B5C)
    PIN -> Color(0xFFA15C00)
    SECURE_NOTE -> Color(0xFF6B6F3A)
    SECRET -> Color(0xFF6B4E9B)
    BANK_ACCOUNT -> Color(0xFF2F6F3E)
    IDENTITY -> Color(0xFF8A3B4E)
    WIFI -> Color(0xFF2B6C8F)
}

private fun f(label: String, kind: FieldKindRecord) = FieldRecord(label, kind, "")

/**
 * Templates write [StoredLabels], which are what the vault keeps. The interface translates them
 * when showing them, never when saving.
 */
fun ItemKindRecord.template(): List<FieldRecord> = when (this) {
    LOGIN -> listOf(
        f(StoredLabels.USERNAME, FieldKindRecord.EMAIL),
        f(StoredLabels.PASSWORD, FieldKindRecord.CONCEALED),
        f(StoredLabels.TOTP, FieldKindRecord.TOTP),
    )
    CARD -> listOf(
        f(StoredLabels.HOLDER, FieldKindRecord.TEXT),
        f(StoredLabels.NUMBER, FieldKindRecord.CARD_NUMBER),
        f(StoredLabels.CARD_EXPIRY, FieldKindRecord.DATE),
        f(StoredLabels.CVV, FieldKindRecord.CONCEALED),
        f(StoredLabels.PIN, FieldKindRecord.PIN),
    )
    PIN -> listOf(f(StoredLabels.CODE, FieldKindRecord.PIN))
    SECRET -> listOf(f(StoredLabels.SECRET, FieldKindRecord.CONCEALED), f(StoredLabels.SERVICE, FieldKindRecord.TEXT))
    SECURE_NOTE -> emptyList()
    BANK_ACCOUNT -> listOf(
        f(StoredLabels.BANK, FieldKindRecord.TEXT),
        f(StoredLabels.HOLDER, FieldKindRecord.TEXT),
        f(StoredLabels.IBAN, FieldKindRecord.TEXT),
        f(StoredLabels.BIC, FieldKindRecord.TEXT),
    )
    IDENTITY -> listOf(
        f(StoredLabels.DOCUMENT_TYPE, FieldKindRecord.TEXT),
        f(StoredLabels.NUMBER, FieldKindRecord.TEXT),
        f(StoredLabels.FULL_NAME, FieldKindRecord.TEXT),
        f(StoredLabels.ISSUED, FieldKindRecord.DATE),
        f(StoredLabels.DOCUMENT_EXPIRY, FieldKindRecord.DATE),
    )
    WIFI -> listOf(f(StoredLabels.WIFI_SSID, FieldKindRecord.TEXT), f(StoredLabels.PASSWORD, FieldKindRecord.CONCEALED))
}

/**
 * The line under the title in the list. Never contains a secret, and it is stored in the vault,
 * so it uses stable values: the interface translates it when showing it.
 */
fun ItemKindRecord.subtitleFor(fields: List<FieldRecord>): String? {
    fun value(kind: FieldKindRecord) = fields.firstOrNull { it.kind == kind && it.value.isNotBlank() }?.value
    fun labelled(label: String) = fields.firstOrNull { it.label == label && it.value.isNotBlank() }?.value
    return when (this) {
        LOGIN -> value(FieldKindRecord.EMAIL) ?: value(FieldKindRecord.TEXT)
        CARD -> value(FieldKindRecord.CARD_NUMBER)?.let { number ->
            listOfNotNull(CardNumber.network(number), "•••• " + CardNumber.digits(number).takeLast(4)).joinToString(" ")
        }
        PIN -> value(FieldKindRecord.PIN)?.let { StoredLabels.pinDigits(it.length) }
        SECRET -> labelled(StoredLabels.SERVICE)
        WIFI -> value(FieldKindRecord.TEXT)
        BANK_ACCOUNT -> listOfNotNull(
            labelled(StoredLabels.BANK),
            labelled(StoredLabels.IBAN)?.let(Iban::normalize)?.takeIf { it.length > 4 }?.let { "•••• ${it.takeLast(4)}" },
        ).joinToString(" · ").ifEmpty { null }
        IDENTITY -> labelled(StoredLabels.DOCUMENT_TYPE)
        else -> null
    }
}

val FieldKindRecord.isSecret: Boolean
    get() = this == FieldKindRecord.CONCEALED || this == FieldKindRecord.PIN ||
        this == FieldKindRecord.CARD_NUMBER || this == FieldKindRecord.TOTP

/** The value of an image field is an attachment id, never shown to the user. */
val FieldKindRecord.isImage: Boolean
    get() = this == FieldKindRecord.IMAGE

fun FieldRecord.masked(): String = when (kind) {
    FieldKindRecord.IMAGE -> ""
    FieldKindRecord.CARD_NUMBER -> "•••• " + value.filter(Char::isDigit).takeLast(4)
    else -> "•".repeat(value.length.coerceIn(4, 12))
}

fun FieldRecord.formatted(): String = when (kind) {
    FieldKindRecord.IMAGE -> ""
    FieldKindRecord.CARD_NUMBER -> value.filter(Char::isDigit).chunked(4).joinToString(" ")
    else -> value
}

/** Lowercase without accents, so "contrasena" finds "Contraseña". */
fun String.searchKey(): String =
    Normalizer.normalize(lowercase(), Normalizer.Form.NFD).replace(Regex("\\p{Mn}+"), "")
