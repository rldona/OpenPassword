package io.github.rldona.openpassword

import android.text.InputType
import io.github.rldona.openpassword.autofill.FieldClassifier
import io.github.rldona.openpassword.autofill.FieldSignals
import io.github.rldona.openpassword.autofill.FieldType
import io.github.rldona.openpassword.autofill.pickLoginFields
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class FieldClassifierTest {
    private fun classify(s: FieldSignals) = FieldClassifier.classify(s)
    private val text = InputType.TYPE_CLASS_TEXT

    @Test
    fun autofillHintsWin() {
        assertEquals(FieldType.PASSWORD, classify(FieldSignals(autofillHints = listOf("password"))))
        assertEquals(FieldType.PASSWORD, classify(FieldSignals(autofillHints = listOf("current_password"))))
        assertEquals(FieldType.USERNAME, classify(FieldSignals(autofillHints = listOf("emailAddress"))))
        assertEquals(FieldType.USERNAME, classify(FieldSignals(autofillHints = listOf("username"))))
    }

    @Test
    fun inputTypes() {
        assertEquals(FieldType.PASSWORD, classify(FieldSignals(inputType = text or InputType.TYPE_TEXT_VARIATION_PASSWORD)))
        assertEquals(FieldType.PASSWORD, classify(FieldSignals(inputType = text or InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD)))
        assertEquals(FieldType.PASSWORD, classify(FieldSignals(inputType = InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD)))
        assertEquals(FieldType.USERNAME, classify(FieldSignals(inputType = text or InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS)))
    }

    @Test
    fun htmlFromBrowsers() {
        assertEquals(FieldType.PASSWORD, classify(FieldSignals(htmlAttributes = listOf("type" to "password"))))
        assertEquals(FieldType.PASSWORD, classify(FieldSignals(htmlAttributes = listOf("type" to "text", "autocomplete" to "current-password"))))
        assertEquals(FieldType.USERNAME, classify(FieldSignals(htmlAttributes = listOf("autocomplete" to "section-login username"))))
        assertEquals(FieldType.USERNAME, classify(FieldSignals(htmlAttributes = listOf("type" to "email"))))
        assertEquals(FieldType.USERNAME, classify(FieldSignals(htmlAttributes = listOf("type" to "text", "name" to "login_email"))))
    }

    @Test
    fun spanishAndEnglishNames() {
        assertEquals(FieldType.PASSWORD, classify(FieldSignals(inputType = text, texts = listOf("et_contrasena"))))
        assertEquals(FieldType.PASSWORD, classify(FieldSignals(inputType = text, texts = listOf("Clave de acceso"))))
        assertEquals(FieldType.USERNAME, classify(FieldSignals(inputType = text, texts = listOf("Usuario o correo"))))
        assertEquals(FieldType.USERNAME, classify(FieldSignals(inputType = text, texts = listOf("input_user"))))
    }

    @Test
    fun searchAndOneTimeCodesAreNotCredentials() {
        assertNull(classify(FieldSignals(inputType = text, texts = listOf("Buscar usuario"))))
        assertNull(classify(FieldSignals(inputType = text, texts = listOf("otp_password"))))
        assertNull(classify(FieldSignals(inputType = text, texts = listOf("Código de verificación"))))
        assertNull(classify(FieldSignals(inputType = text, texts = listOf("Nombre"))))
    }

    @Test
    fun disabledFieldsAreSkipped() {
        assertNull(classify(FieldSignals(autofillHints = listOf("password"), isEditable = false)))
    }

    @Test
    fun usernameFallsBackToTheFieldBeforeThePassword() {
        val (u, p) = pickLoginFields(listOf("nombre" to null, "dni" to null, "pass" to FieldType.PASSWORD))
        assertEquals("dni", u)
        assertEquals("pass", p)
    }

    @Test
    fun explicitUsernameIsPreferred() {
        val (u, p) = pickLoginFields(listOf("email" to FieldType.USERNAME, "x" to null, "pass" to FieldType.PASSWORD))
        assertEquals("email", u)
        assertEquals("pass", p)
    }

    @Test
    fun noFieldsNoFill() {
        assertEquals(null to null, pickLoginFields(listOf("a" to null, "b" to null)))
    }
}
