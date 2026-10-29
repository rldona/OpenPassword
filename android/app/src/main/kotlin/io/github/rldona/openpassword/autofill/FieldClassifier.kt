package io.github.rldona.openpassword.autofill

import android.text.InputType

enum class FieldType { USERNAME, PASSWORD }

/**
 * Everything we look at to decide what a field is. Plain data, so the rules can be
 * unit-tested without an AssistStructure.
 */
data class FieldSignals(
    val autofillHints: List<String> = emptyList(),
    val inputType: Int = 0,
    /** HTML attributes from browsers, e.g. "type" to "password", "autocomplete" to "username". */
    val htmlAttributes: List<Pair<String, String>> = emptyList(),
    /** View id name, hint and visible text. */
    val texts: List<String> = emptyList(),
    val isEditable: Boolean = true,
)

object FieldClassifier {
    private val USERNAME_HINTS = setOf("username", "emailaddress", "email", "phone", "newusername")
    private val PASSWORD_HINTS = setOf("password", "currentpassword", "newpassword")
    private val USERNAME_WORDS = Regex("(user|usuario|e-?mail|correo|login|identifier|account|cuenta|dni|nif)", RegexOption.IGNORE_CASE)
    private val PASSWORD_WORDS = Regex("(pass|contrase|clave|pwd|\\bpin\\b)", RegexOption.IGNORE_CASE)
    // Fields that look like credentials by name but must never receive a password.
    private val EXCLUDED_WORDS = Regex("(search|buscar|captcha|otp|2fa|one[- ]?time|código de verificación|verification)", RegexOption.IGNORE_CASE)

    fun classify(s: FieldSignals): FieldType? {
        if (!s.isEditable) return null

        val hints = s.autofillHints.map { it.lowercase().replace("_", "") }
        if (hints.any { it in PASSWORD_HINTS }) return FieldType.PASSWORD
        if (hints.any { it in USERNAME_HINTS }) return FieldType.USERNAME

        val html = s.htmlAttributes.map { (k, v) -> k.lowercase() to v.lowercase() }
        if (html.any { (k, v) -> k == "type" && v == "password" }) return FieldType.PASSWORD
        val autocomplete = html.filter { it.first == "autocomplete" }.flatMap { it.second.split(' ') }
        if (autocomplete.any { it == "current-password" || it == "new-password" }) return FieldType.PASSWORD
        if (autocomplete.any { it == "username" || it == "email" }) return FieldType.USERNAME
        if (html.any { (k, v) -> k == "type" && v == "email" }) return FieldType.USERNAME

        val cls = s.inputType and InputType.TYPE_MASK_CLASS
        val variation = s.inputType and InputType.TYPE_MASK_VARIATION
        if (cls == InputType.TYPE_CLASS_TEXT && variation in TEXT_PASSWORD_VARIATIONS) return FieldType.PASSWORD
        if (cls == InputType.TYPE_CLASS_NUMBER && variation == InputType.TYPE_NUMBER_VARIATION_PASSWORD) return FieldType.PASSWORD

        val text = (s.texts + html.filter { it.first in setOf("name", "id") }.map { it.second }).joinToString(" ")
        if (EXCLUDED_WORDS.containsMatchIn(text)) return null
        if (cls == InputType.TYPE_CLASS_TEXT && variation in TEXT_EMAIL_VARIATIONS) return FieldType.USERNAME
        if (PASSWORD_WORDS.containsMatchIn(text)) return FieldType.PASSWORD
        if (USERNAME_WORDS.containsMatchIn(text)) return FieldType.USERNAME
        return null
    }

    private val TEXT_PASSWORD_VARIATIONS = setOf(
        InputType.TYPE_TEXT_VARIATION_PASSWORD,
        InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD,
        InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD,
    )
    private val TEXT_EMAIL_VARIATIONS = setOf(
        InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS,
        InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS,
    )
}

/**
 * Picks the fields to fill from the classified editable fields, in screen order.
 * With a password but no explicit username, the text field right before the password is
 * taken as the username, which is how most login forms are laid out.
 */
fun <T> pickLoginFields(fields: List<Pair<T, FieldType?>>): Pair<T?, T?> {
    val passwordIndex = fields.indexOfFirst { it.second == FieldType.PASSWORD }
    val username = fields.firstOrNull { it.second == FieldType.USERNAME }?.first
        ?: if (passwordIndex > 0) fields[passwordIndex - 1].takeIf { it.second == null }?.first else null
    return username to fields.getOrNull(passwordIndex)?.first
}
