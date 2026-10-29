package io.github.rldona.openpassword

import io.github.rldona.openpassword.core.FieldKindRecord
import io.github.rldona.openpassword.core.FieldRecord
import io.github.rldona.openpassword.core.ItemKindRecord
import io.github.rldona.openpassword.ui.vault.formatted
import io.github.rldona.openpassword.ui.vault.isSecret
import io.github.rldona.openpassword.ui.vault.masked
import io.github.rldona.openpassword.ui.vault.searchKey
import io.github.rldona.openpassword.ui.vault.subtitleFor
import io.github.rldona.openpassword.ui.vault.template
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ItemKindsTest {
    private fun card(number: String, cvv: String = "317", pin: String = "2958") = listOf(
        FieldRecord("Número", FieldKindRecord.CARD_NUMBER, number),
        FieldRecord("CVV", FieldKindRecord.CONCEALED, cvv),
        FieldRecord("PIN", FieldKindRecord.PIN, pin),
    )

    @Test
    fun cardSubtitleShowsOnlyTheLastFourDigits() {
        val subtitle = ItemKindRecord.CARD.subtitleFor(card("4940 1923 5567 4821"))
        assertEquals("Visa •••• 4821", subtitle)
        assertFalse(subtitle!!.contains("4940"))
    }

    @Test
    fun subtitlesNeverContainSecrets() {
        val secret = FieldRecord("Contraseña", FieldKindRecord.CONCEALED, "s3creto!")
        val login = listOf(FieldRecord("Usuario", FieldKindRecord.EMAIL, "raul@ejemplo.com"), secret)
        assertEquals("raul@ejemplo.com", ItemKindRecord.LOGIN.subtitleFor(login))
        assertEquals("4 dígitos", ItemKindRecord.PIN.subtitleFor(listOf(FieldRecord("Código", FieldKindRecord.PIN, "2958"))))
        assertNull(ItemKindRecord.SECRET.subtitleFor(listOf(secret)))
        for (kind in ItemKindRecord.entries) {
            val s = kind.subtitleFor(login + card("4940192355674821")) ?: continue
            assertFalse("$kind: $s", s.contains("s3creto") || s.contains("317") || s.contains("2958"))
        }
    }

    @Test
    fun maskingHidesValuesAndTheirLength() {
        assertEquals("•••• 4821", card("4940192355674821")[0].masked())
        assertEquals("••••", FieldRecord("CVV", FieldKindRecord.CONCEALED, "317").masked())
        assertEquals("••••••••••••", FieldRecord("x", FieldKindRecord.CONCEALED, "a".repeat(40)).masked())
    }

    @Test
    fun cardNumbersAreGroupedWhenRevealed() {
        assertEquals("4940 1923 5567 4821", card("4940192355674821")[0].formatted())
    }

    @Test
    fun secretFieldKinds() {
        assertTrue(FieldKindRecord.CONCEALED.isSecret && FieldKindRecord.PIN.isSecret && FieldKindRecord.CARD_NUMBER.isSecret && FieldKindRecord.TOTP.isSecret)
        assertFalse(FieldKindRecord.TEXT.isSecret || FieldKindRecord.EMAIL.isSecret || FieldKindRecord.URL.isSecret || FieldKindRecord.DATE.isSecret)
    }

    @Test
    fun templatesStartEmpty() {
        ItemKindRecord.entries.forEach { kind -> assertTrue(kind.template().all { it.value.isEmpty() }) }
    }

    @Test
    fun searchIgnoresCaseAndAccents() {
        assertEquals("contrasena", "Contraseña".searchKey())
        assertEquals("cafe", "CAFÉ".searchKey())
    }
}
