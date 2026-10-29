package io.github.rldona.openpassword

import io.github.rldona.openpassword.health.HealthInput
import io.github.rldona.openpassword.health.VaultHealth
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.LocalDate
import java.time.YearMonth

class VaultHealthTest {
    private val today = LocalDate.of(2026, 10, 29)
    private val recent = LocalDate.of(2026, 9, 1).toEpochDay() * 86_400
    private val strong = "caballo-bateria-grapa-correcta"

    private fun login(id: String, vararg passwords: String, updatedAt: Long = recent) =
        HealthInput(id, isLogin = true, isCard = false, passwords = passwords.toList(), cardExpiry = null, updatedAt = updatedAt)

    private fun card(id: String, expiry: String?) =
        HealthInput(id, isLogin = false, isCard = true, passwords = emptyList(), cardExpiry = expiry, updatedAt = recent)

    @Test
    fun cleanVault() {
        val report = VaultHealth.analyze(listOf(login("a", strong), login("b", "otra-frase-larga-distinta-2026"), card("c", "08/29")), today)
        assertTrue(report.isClean)
        assertEquals(0, report.affected)
    }

    @Test
    fun weakPasswords() {
        val report = VaultHealth.analyze(listOf(login("a", "123456"), login("b", "contraseña"), login("c", strong)), today)
        assertEquals(listOf("a", "b"), report.weak)
    }

    @Test
    fun reusedPasswordsAreGroupedLargestFirst() {
        val report = VaultHealth.analyze(
            listOf(login("a", strong), login("b", strong), login("c", strong), login("d", "x1-otra-larga-2026"), login("e", "x1-otra-larga-2026"), login("f", "unica-y-larga-2026")),
            today,
        )
        assertEquals(listOf(listOf("a", "b", "c"), listOf("d", "e")), report.reused)
        assertEquals(5, report.affected)
    }

    @Test
    fun theSamePasswordTwiceInOneItemIsNotReuse() {
        val report = VaultHealth.analyze(listOf(login("a", strong, strong)), today)
        assertTrue(report.reused.isEmpty())
    }

    @Test
    fun oldLogins() {
        val twoYearsAgo = LocalDate.of(2024, 10, 1).toEpochDay() * 86_400
        val report = VaultHealth.analyze(listOf(login("a", strong, updatedAt = twoYearsAgo), login("b", "otra-frase-larga-distinta-2026")), today)
        assertEquals(listOf("a"), report.old)
    }

    @Test
    fun cardExpiry() {
        val report = VaultHealth.analyze(
            listOf(card("caducada", "09/26"), card("este-mes", "10/26"), card("pronto", "12/2026"), card("lejos", "2029-08"), card("ilegible", "pronto"), card("vacia", null)),
            today,
        )
        assertEquals(listOf("caducada"), report.expiredCards)
        assertEquals(listOf("este-mes", "pronto"), report.expiringCards)
    }

    @Test
    fun expiryFormats() {
        val aug29 = YearMonth.of(2029, 8)
        for (s in listOf("08/29", "8/29", "0829", "08-29", "08/2029", "2029-08", " 08 / 29 ")) {
            assertEquals(s, aug29, VaultHealth.parseCardExpiry(s))
        }
        for (s in listOf("13/29", "00/29", "agosto", "", "2029")) {
            assertNull(s, VaultHealth.parseCardExpiry(s))
        }
    }

    @Test
    fun onlyLoginsAreCheckedForPasswords() {
        val secret = HealthInput("s", isLogin = false, isCard = false, passwords = listOf("123"), cardExpiry = null, updatedAt = recent)
        assertTrue(VaultHealth.analyze(listOf(secret), today).isClean)
    }
}
