package io.github.rldona.openpassword.ui.vault

import android.content.res.Resources
import androidx.annotation.StringRes
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import io.github.rldona.openpassword.R
import io.github.rldona.openpassword.core.FieldRecord
import io.github.rldona.openpassword.data.StoredLabels

/**
 * Presentation of [StoredLabels]: what the user reads, never what the vault keeps.
 *
 * A label that is not in the table (a field the user named themselves) is shown as it is.
 */
object FieldLabels {
    private val RESOURCES: Map<String, Int> = mapOf(
        StoredLabels.USERNAME to R.string.field_username,
        StoredLabels.PASSWORD to R.string.field_password,
        StoredLabels.TOTP to R.string.field_totp,
        StoredLabels.HOLDER to R.string.field_holder,
        StoredLabels.NUMBER to R.string.field_number,
        StoredLabels.CARD_EXPIRY to R.string.field_card_expiry,
        StoredLabels.CVV to R.string.field_cvv,
        StoredLabels.PIN to R.string.field_pin,
        StoredLabels.CODE to R.string.field_code,
        StoredLabels.SECRET to R.string.field_secret,
        StoredLabels.SERVICE to R.string.field_service,
        StoredLabels.BANK to R.string.field_bank,
        StoredLabels.IBAN to R.string.field_iban,
        StoredLabels.BIC to R.string.field_bic,
        StoredLabels.DOCUMENT_TYPE to R.string.field_document_type,
        StoredLabels.FULL_NAME to R.string.field_full_name,
        StoredLabels.ISSUED to R.string.field_issued,
        StoredLabels.DOCUMENT_EXPIRY to R.string.field_document_expiry,
        StoredLabels.WIFI_SSID to R.string.field_wifi_ssid,
        StoredLabels.IMAGE_FRONT to R.string.field_image_front,
        StoredLabels.IMAGE_BACK to R.string.field_image_back,
        StoredLabels.FIELD to R.string.field_default,
    )

    private val IMAGE_N = Regex("""^Imagen (\d+)$""")

    @StringRes
    fun resourceFor(stored: String): Int? = RESOURCES[stored]

    /** Index of a numbered image label ("Imagen 3"), or null. */
    fun imageIndex(stored: String): Int? = IMAGE_N.matchEntire(stored)?.groupValues?.get(1)?.toIntOrNull()

    /** Digit count of a stored PIN subtitle ("4 dígitos"), or null. */
    fun pinDigits(stored: String): Int? = StoredLabels.pinDigitsOf(stored)

    /** Text to show for a stored label, translated when known. */
    fun display(stored: String, res: Resources): String {
        resourceFor(stored)?.let { return res.getString(it) }
        pinDigits(stored)?.let { return res.getQuantityString(R.plurals.field_pin_digits, it, it) }
        imageIndex(stored)?.let { return res.getString(R.string.field_image_n, it) }
        return stored
    }

    /**
     * A label the user edited in the editor. If the text is exactly the translation that was
     * shown, they did not change anything and the stable value is kept.
     */
    fun editedLabel(edited: String, previous: String, res: Resources): String =
        if (edited == display(previous, res)) previous else edited
}

/** Translated label for a stored field, ready to paint. */
@Composable
fun FieldRecord.displayLabel(): String {
    FieldLabels.resourceFor(label)?.let { return stringResource(it) }
    FieldLabels.pinDigits(label)?.let { return pluralStringResource(R.plurals.field_pin_digits, it, it) }
    FieldLabels.imageIndex(label)?.let { return stringResource(R.string.field_image_n, it) }
    return label
}

/** Translated version of any stored label, subtitle included. */
@Composable
fun storedLabelText(stored: String): String {
    FieldLabels.resourceFor(stored)?.let { return stringResource(it) }
    FieldLabels.pinDigits(stored)?.let { return pluralStringResource(R.plurals.field_pin_digits, it, it) }
    FieldLabels.imageIndex(stored)?.let { return stringResource(R.string.field_image_n, it) }
    return stored
}
