package io.github.rldona.openpassword.data

/**
 * Field labels written **inside** the vault.
 *
 * They are part of the data format, not of the interface: a vault created before the app was
 * bilingual keeps the same values, and a vault created in English and opened in Spanish still
 * matches its fields. Never translate these strings. Only their presentation is translated
 * (see `ui/vault/FieldLabels.kt`).
 */
object StoredLabels {
    const val USERNAME = "Usuario"
    const val PASSWORD = "Contraseña"
    const val TOTP = "Código TOTP"
    const val HOLDER = "Titular"
    const val NUMBER = "Número"
    const val CARD_EXPIRY = "Caducidad (MM/AA)"
    const val CVV = "CVV"
    const val PIN = "PIN"
    const val CODE = "Código"
    const val SECRET = "Secreto"
    const val SERVICE = "Servicio"
    const val BANK = "Banco"
    const val IBAN = "IBAN"
    const val BIC = "BIC / SWIFT"
    const val DOCUMENT_TYPE = "Tipo (DNI, pasaporte, carné…)"
    const val FULL_NAME = "Nombre completo"
    const val ISSUED = "Expedición (DD/MM/AAAA)"
    const val DOCUMENT_EXPIRY = "Caducidad (DD/MM/AAAA)"
    const val WIFI_SSID = "Red (SSID)"
    const val IMAGE_FRONT = "Anverso"
    const val IMAGE_BACK = "Reverso"
    /** Default label the core importer gives to an unnamed extra field. */
    const val FIELD = "Campo"

    /** Image attachments are numbered, not titled. */
    fun image(n: Int): String = "Imagen $n"

    /** Subtitle of a PIN item: the number of digits, which is not a secret. */
    fun pinDigits(n: Int): String = "$n dígitos"

    private val PIN_DIGITS = Regex("""^(\d+) dígitos$""")

    /** Reads the digit count back from a stored PIN subtitle, or null if it is something else. */
    fun pinDigitsOf(stored: String): Int? = PIN_DIGITS.matchEntire(stored)?.groupValues?.get(1)?.toIntOrNull()

    /**
     * Document expiry dates are matched by prefix so that old vaults (which may store a bare
     * "Caducidad" written by the CLI) keep working.
     */
    fun isDocumentExpiry(label: String): Boolean = label.startsWith("Caducidad")
}
