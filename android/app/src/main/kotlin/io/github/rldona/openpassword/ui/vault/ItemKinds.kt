package io.github.rldona.openpassword.ui.vault

import androidx.compose.ui.graphics.Color
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
import java.text.Normalizer

/** Item types offered by "+", in menu order. */
val CreatableKinds = listOf(LOGIN, CARD, BANK_ACCOUNT, PIN, IDENTITY, WIFI, SECRET, SECURE_NOTE)

/** Field labels other code looks up. */
const val IBAN_LABEL = "IBAN"
const val DOCUMENT_EXPIRY_LABEL = "Caducidad (DD/MM/AAAA)"
const val DOCUMENT_TYPE_LABEL = "Tipo (DNI, pasaporte, carné…)"
const val WIFI_SSID_LABEL = "Red (SSID)"

fun ItemKindRecord.label(): String = when (this) {
    LOGIN -> "Login"
    CARD -> "Tarjeta"
    PIN -> "PIN o código"
    SECURE_NOTE -> "Nota segura"
    SECRET -> "Secreto o clave API"
    BANK_ACCOUNT -> "Cuenta bancaria"
    IDENTITY -> "Documento"
    WIFI -> "Wi-Fi"
}

fun ItemKindRecord.shortLabel(): String = when (this) {
    LOGIN -> "Logins"
    CARD -> "Tarjetas"
    PIN -> "PINs"
    SECURE_NOTE -> "Notas"
    SECRET -> "Secretos"
    BANK_ACCOUNT -> "Cuentas"
    IDENTITY -> "Documentos"
    WIFI -> "Wi-Fi"
}

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

fun ItemKindRecord.template(): List<FieldRecord> = when (this) {
    LOGIN -> listOf(f("Usuario", FieldKindRecord.EMAIL), f("Contraseña", FieldKindRecord.CONCEALED), f("Código TOTP", FieldKindRecord.TOTP))
    CARD -> listOf(
        f("Titular", FieldKindRecord.TEXT),
        f("Número", FieldKindRecord.CARD_NUMBER),
        f("Caducidad (MM/AA)", FieldKindRecord.DATE),
        f("CVV", FieldKindRecord.CONCEALED),
        f("PIN", FieldKindRecord.PIN),
    )
    PIN -> listOf(f("Código", FieldKindRecord.PIN))
    SECRET -> listOf(f("Secreto", FieldKindRecord.CONCEALED), f("Servicio", FieldKindRecord.TEXT))
    SECURE_NOTE -> emptyList()
    BANK_ACCOUNT -> listOf(
        f("Banco", FieldKindRecord.TEXT),
        f("Titular", FieldKindRecord.TEXT),
        f(IBAN_LABEL, FieldKindRecord.TEXT),
        f("BIC / SWIFT", FieldKindRecord.TEXT),
    )
    IDENTITY -> listOf(
        f(DOCUMENT_TYPE_LABEL, FieldKindRecord.TEXT),
        f("Número", FieldKindRecord.TEXT),
        f("Nombre completo", FieldKindRecord.TEXT),
        f("Expedición (DD/MM/AAAA)", FieldKindRecord.DATE),
        f(DOCUMENT_EXPIRY_LABEL, FieldKindRecord.DATE),
    )
    WIFI -> listOf(f(WIFI_SSID_LABEL, FieldKindRecord.TEXT), f("Contraseña", FieldKindRecord.CONCEALED))
}

/** The line under the title in the list. Never contains a secret. */
fun ItemKindRecord.subtitleFor(fields: List<FieldRecord>): String? {
    fun value(kind: FieldKindRecord) = fields.firstOrNull { it.kind == kind && it.value.isNotBlank() }?.value
    fun labelled(label: String) = fields.firstOrNull { it.label == label && it.value.isNotBlank() }?.value
    return when (this) {
        LOGIN -> value(FieldKindRecord.EMAIL) ?: value(FieldKindRecord.TEXT)
        CARD -> value(FieldKindRecord.CARD_NUMBER)?.filter(Char::isDigit)?.takeLast(4)?.let { "•••• $it" }
        PIN -> value(FieldKindRecord.PIN)?.let { "${it.length} dígitos" }
        SECRET -> labelled("Servicio")
        WIFI -> value(FieldKindRecord.TEXT)
        BANK_ACCOUNT -> listOfNotNull(
            labelled("Banco"),
            labelled(IBAN_LABEL)?.let(Iban::normalize)?.takeIf { it.length > 4 }?.let { "•••• ${it.takeLast(4)}" },
        ).joinToString(" · ").ifEmpty { null }
        IDENTITY -> labelled(DOCUMENT_TYPE_LABEL)
        else -> null
    }
}

val FieldKindRecord.isSecret: Boolean
    get() = this == FieldKindRecord.CONCEALED || this == FieldKindRecord.PIN ||
        this == FieldKindRecord.CARD_NUMBER || this == FieldKindRecord.TOTP

fun FieldRecord.masked(): String = when (kind) {
    FieldKindRecord.CARD_NUMBER -> "•••• " + value.filter(Char::isDigit).takeLast(4)
    else -> "•".repeat(value.length.coerceIn(4, 12))
}

fun FieldRecord.formatted(): String = when (kind) {
    FieldKindRecord.CARD_NUMBER -> value.filter(Char::isDigit).chunked(4).joinToString(" ")
    else -> value
}

/** Lowercase without accents, so "contrasena" finds "Contraseña". */
fun String.searchKey(): String =
    Normalizer.normalize(lowercase(), Normalizer.Form.NFD).replace(Regex("\\p{Mn}+"), "")
