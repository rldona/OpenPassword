package io.github.rldona.openpassword

import io.github.rldona.openpassword.data.StoredLabels
import io.github.rldona.openpassword.ui.vault.FieldLabels
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * The stored labels are part of the vault format: changing one silently hides fields from
 * vaults written by an older version. These values are frozen on purpose.
 */
class StoredLabelsTest {
    @Test
    fun storedLabelsKeepTheirExactValues() {
        val expected = mapOf(
            "USERNAME" to "Usuario",
            "PASSWORD" to "Contraseña",
            "TOTP" to "Código TOTP",
            "HOLDER" to "Titular",
            "NUMBER" to "Número",
            "CARD_EXPIRY" to "Caducidad (MM/AA)",
            "CVV" to "CVV",
            "PIN" to "PIN",
            "CODE" to "Código",
            "SECRET" to "Secreto",
            "SERVICE" to "Servicio",
            "BANK" to "Banco",
            "IBAN" to "IBAN",
            "BIC" to "BIC / SWIFT",
            "DOCUMENT_TYPE" to "Tipo (DNI, pasaporte, carné…)",
            "FULL_NAME" to "Nombre completo",
            "ISSUED" to "Expedición (DD/MM/AAAA)",
            "DOCUMENT_EXPIRY" to "Caducidad (DD/MM/AAAA)",
            "WIFI_SSID" to "Red (SSID)",
            "IMAGE_FRONT" to "Anverso",
            "IMAGE_BACK" to "Reverso",
            "FIELD" to "Campo",
        )
        for ((name, value) in expected) {
            val actual = StoredLabels::class.java.getDeclaredField(name).apply { isAccessible = true }.get(StoredLabels)
            assertEquals(name, value, actual)
        }
        assertEquals("Imagen 3", StoredLabels.image(3))
        assertEquals("4 dígitos", StoredLabels.pinDigits(4))
    }

    @Test
    fun pinDigitsRoundTrip() {
        assertEquals(4, StoredLabels.pinDigitsOf("4 dígitos"))
        assertEquals(8, StoredLabels.pinDigitsOf("8 dígitos"))
        assertNull(StoredLabels.pinDigitsOf("Contraseña"))
    }

    @Test
    fun documentExpiryAcceptsLegacyLabel() {
        assertEquals(true, StoredLabels.isDocumentExpiry("Caducidad (DD/MM/AAAA)"))
        assertEquals(true, StoredLabels.isDocumentExpiry("Caducidad"))
        assertEquals(false, StoredLabels.isDocumentExpiry("Expedición (DD/MM/AAAA)"))
    }

    @Test
    fun everyStoredLabelHasAPresentation() {
        for (field in StoredLabels::class.java.declaredFields) {
            if (field.type != String::class.java) continue
            field.isAccessible = true
            val value = field.get(StoredLabels) as String
            assertNotNull("no presentation for ${field.name} = $value", FieldLabels.resourceFor(value))
        }
    }

    @Test
    fun unknownLabelsAreShownAsTheyAre() {
        assertNull(FieldLabels.resourceFor("Mi campo propio"))
        assertNull(FieldLabels.imageIndex("Mi campo propio"))
        assertEquals(3, FieldLabels.imageIndex("Imagen 3"))
        assertNull(FieldLabels.imageIndex("Anverso"))
    }
}
