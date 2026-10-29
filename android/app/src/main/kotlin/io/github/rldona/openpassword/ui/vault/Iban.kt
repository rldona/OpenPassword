package io.github.rldona.openpassword.ui.vault

import java.math.BigInteger

/** ISO 13616 IBAN: country length plus the mod-97 check digits. Catches typos, not fake accounts. */
object Iban {
    // SWIFT IBAN registry: country → total length.
    private val LENGTHS = mapOf(
        "AD" to 24, "AE" to 23, "AL" to 28, "AT" to 20, "AZ" to 28, "BA" to 20, "BE" to 16, "BG" to 22,
        "BH" to 22, "BI" to 27, "BR" to 29, "BY" to 28, "CH" to 21, "CR" to 22, "CY" to 28, "CZ" to 24,
        "DE" to 22, "DJ" to 27, "DK" to 18, "DO" to 28, "EE" to 20, "EG" to 29, "ES" to 24, "FI" to 18,
        "FK" to 18, "FO" to 18, "FR" to 27, "GB" to 22, "GE" to 22, "GI" to 23, "GL" to 18, "GR" to 27,
        "GT" to 28, "HN" to 28, "HR" to 21, "HU" to 28, "IE" to 22, "IL" to 23, "IQ" to 23, "IS" to 26,
        "IT" to 27, "JO" to 30, "KW" to 30, "KZ" to 20, "LB" to 28, "LC" to 32, "LI" to 21, "LT" to 20,
        "LU" to 20, "LV" to 21, "LY" to 25, "MC" to 27, "MD" to 24, "ME" to 22, "MK" to 19, "MN" to 20,
        "MR" to 27, "MT" to 31, "MU" to 30, "NI" to 28, "NL" to 18, "NO" to 15, "OM" to 23, "PK" to 24,
        "PL" to 28, "PS" to 29, "PT" to 25, "QA" to 29, "RO" to 24, "RS" to 22, "RU" to 33, "SA" to 24,
        "SC" to 31, "SD" to 18, "SE" to 24, "SI" to 19, "SK" to 24, "SM" to 27, "SO" to 23, "ST" to 25,
        "SV" to 28, "TL" to 23, "TN" to 24, "TR" to 26, "UA" to 29, "VA" to 22, "VG" to 24, "XK" to 20,
        "YE" to 30,
    )

    /** Uppercase, without spaces or dashes. */
    fun normalize(raw: String): String = raw.filterNot { it.isWhitespace() || it == '-' }.uppercase()

    fun isValid(raw: String): Boolean {
        val iban = normalize(raw)
        if (!iban.all { it in 'A'..'Z' || it in '0'..'9' }) return false
        if (LENGTHS[iban.take(2)] != iban.length || !iban.substring(2, 4).all(Char::isDigit)) return false
        val digits = (iban.drop(4) + iban.take(4)).map { if (it.isDigit()) "$it" else "${it - 'A' + 10}" }.joinToString("")
        return BigInteger(digits).mod(BigInteger.valueOf(97)).toInt() == 1
    }

    /** "ES9121000418450200051332" → "ES91 2100 0418 4502 0005 1332". */
    fun format(raw: String): String = normalize(raw).chunked(4).joinToString(" ")
}
