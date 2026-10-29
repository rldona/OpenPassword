package io.github.rldona.openpassword

import io.github.rldona.openpassword.core.FieldKindRecord
import io.github.rldona.openpassword.core.FieldRecord
import io.github.rldona.openpassword.core.ItemKindRecord
import io.github.rldona.openpassword.health.HealthInput
import io.github.rldona.openpassword.health.VaultHealth
import io.github.rldona.openpassword.qr.WifiQr
import io.github.rldona.openpassword.ui.vault.IBAN_LABEL
import io.github.rldona.openpassword.ui.vault.Iban
import io.github.rldona.openpassword.ui.vault.subtitleFor
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.LocalDate

class NewKindsTest {
    @Test
    fun validIbans() {
        // Published examples from the SWIFT IBAN registry.
        for (iban in listOf("ES91 2100 0418 4502 0005 1332", "DE89370400440532013000", "GB82 WEST 1234 5698 7654 32", "fr1420041010050500013m02606", "NO9386011117947")) {
            assertTrue(iban, Iban.isValid(iban))
        }
    }

    @Test
    fun invalidIbans() {
        for (iban in listOf("ES92 2100 0418 4502 0005 1332", "ES91 2100 0418 4502 0005 133", "XX91 2100 0418 4502 0005 1332", "ES9A 2100 0418 4502 0005 1332", "ES91-2100-0418-4502-0005-133Ñ", "")) {
            assertFalse(iban, Iban.isValid(iban))
        }
    }

    @Test
    fun ibanIsGroupedByFour() {
        assertEquals("ES91 2100 0418 4502 0005 1332", Iban.format(" es91-21000418 450200051332"))
    }

    @Test
    fun bankSubtitleShowsBankAndLastFour() {
        val fields = listOf(FieldRecord("Banco", FieldKindRecord.TEXT, "CaixaBank"), FieldRecord(IBAN_LABEL, FieldKindRecord.TEXT, "ES91 2100 0418 4502 0005 1332"))
        assertEquals("CaixaBank · •••• 1332", ItemKindRecord.BANK_ACCOUNT.subtitleFor(fields))
    }

    @Test
    fun wifiPayloadEscapesSpecialCharacters() {
        assertEquals("""WIFI:T:WPA;S:Casa\;5G;P:a\:b\,c\\d\"e;;""", WifiQr.payload("Casa;5G", """a:b,c\d"e"""))
        assertEquals("WIFI:T:nopass;S:Bar;;", WifiQr.payload("Bar", ""))
    }

    @Test
    fun documentDates() {
        val aug15 = LocalDate.of(2029, 8, 15)
        for (s in listOf("15/08/2029", "15-08-2029", "15.08.2029", "15082029", "2029-08-15", " 15 / 08 / 2029 ")) {
            assertEquals(s, aug15, VaultHealth.parseDocumentDate(s))
        }
        assertEquals(LocalDate.of(2029, 2, 28), VaultHealth.parseDocumentDate("02/2029"))
        for (s in listOf("31/02/2029", "15/13/2029", "agosto", "", "15/08/29")) {
            assertNull(s, VaultHealth.parseDocumentDate(s))
        }
    }

    @Test
    fun documentExpiry() {
        val today = LocalDate.of(2026, 10, 29)
        fun doc(id: String, expiry: String?) =
            HealthInput(id, isLogin = false, isCard = false, passwords = emptyList(), cardExpiry = null, updatedAt = 1, documentExpiry = expiry)
        val report = VaultHealth.analyze(
            listOf(doc("ayer", "28/10/2026"), doc("hoy", "29/10/2026"), doc("enero", "29/01/2027"), doc("lejos", "30/01/2027"), doc("sin-fecha", null)),
            today,
        )
        assertEquals(listOf("ayer"), report.expiredDocuments)
        assertEquals(listOf("hoy", "enero"), report.expiringDocuments)
        assertEquals(3, report.affected)
    }
}
