package io.github.rldona.openpassword.health

import io.github.rldona.openpassword.ui.onboarding.strengthOf
import java.security.MessageDigest
import java.time.LocalDate
import java.time.YearMonth
import java.time.format.DateTimeFormatter

/** What the health check needs from one item. Built from decrypted details, then dropped. */
data class HealthInput(
    val id: String,
    val isLogin: Boolean,
    val isCard: Boolean,
    val passwords: List<String>,
    val cardExpiry: String?,
    /** Unix seconds of the last edit of the item. */
    val updatedAt: Long,
    /** Expiry date of an ID document (DNI, passport…), as typed. */
    val documentExpiry: String? = null,
)

data class HealthReport(
    val weak: List<String>,
    /** Groups of item ids sharing the same password, largest first. */
    val reused: List<List<String>>,
    val old: List<String>,
    val expiredCards: List<String>,
    val expiringCards: List<String>,
    val expiredDocuments: List<String> = emptyList(),
    val expiringDocuments: List<String> = emptyList(),
) {
    val reusedIds: Set<String> get() = reused.flatten().toSet()
    /** Number of items with at least one problem. */
    val affected: Int get() = (weak + reusedIds + old + expiredCards + expiringCards + expiredDocuments + expiringDocuments).toSet().size
    val isClean: Boolean get() = affected == 0

    companion object {
        val EMPTY = HealthReport(emptyList(), emptyList(), emptyList(), emptyList(), emptyList())
    }
}

object VaultHealth {
    const val OLD_AFTER_DAYS = 365L
    const val EXPIRING_MONTHS = 2L
    /** Renewing a passport or ID card can take weeks, so documents are flagged earlier than cards. */
    const val DOCUMENT_EXPIRING_MONTHS = 3L
    val DOCUMENT_DATE: DateTimeFormatter = DateTimeFormatter.ofPattern("dd/MM/uuuu")

    fun analyze(items: List<HealthInput>, today: LocalDate): HealthReport {
        val logins = items.filter { it.isLogin && it.passwords.isNotEmpty() }

        val weak = logins.filter { item -> item.passwords.any { strengthOf(it).level == 0 } }.map { it.id }

        // Group by a digest so no plaintext copy is kept in the map.
        val reused = logins
            .flatMap { item -> item.passwords.distinct().map { digest(it) to item.id } }
            .groupBy({ it.first }, { it.second })
            .values
            .map { it.distinct() }
            .filter { it.size > 1 }
            .sortedByDescending { it.size }

        val cutoff = today.minusDays(OLD_AFTER_DAYS).toEpochDay() * 86_400
        val old = logins.filter { it.updatedAt in 1 until cutoff }.map { it.id }

        val thisMonth = YearMonth.from(today)
        val cards = items.filter { it.isCard }.mapNotNull { item -> parseCardExpiry(item.cardExpiry)?.let { item.id to it } }
        val expired = cards.filter { (_, expiry) -> expiry < thisMonth }.map { it.first }
        val expiring = cards.filter { (_, expiry) -> expiry >= thisMonth && expiry <= thisMonth.plusMonths(EXPIRING_MONTHS) }.map { it.first }

        val documents = items.mapNotNull { item -> parseDocumentDate(item.documentExpiry)?.let { item.id to it } }
        val expiredDocs = documents.filter { (_, date) -> date < today }.map { it.first }
        val expiringDocs = documents.filter { (_, date) -> date >= today && date <= today.plusMonths(DOCUMENT_EXPIRING_MONTHS) }.map { it.first }

        return HealthReport(weak, reused, old, expired, expiring, expiredDocs, expiringDocs)
    }

    /** "15/08/2029", "15-08-2029", "15.08.2029", "15082029", "2029-08-15"; "08/2029" → 31/08/2029. Null if unreadable. */
    fun parseDocumentDate(raw: String?): LocalDate? {
        val s = raw?.trim()?.replace(" ", "") ?: return null
        val parts = when {
            Regex("""\d{4}-\d{1,2}-\d{1,2}""").matches(s) -> s.split('-').let { Triple(it[2].toInt(), it[1].toInt(), it[0].toInt()) }
            Regex("""\d{1,2}[/.-]\d{1,2}[/.-]\d{4}""").matches(s) -> s.split('/', '.', '-').let { Triple(it[0].toInt(), it[1].toInt(), it[2].toInt()) }
            Regex("""\d{8}""").matches(s) -> Triple(s.take(2).toInt(), s.substring(2, 4).toInt(), s.takeLast(4).toInt())
            Regex("""\d{1,2}[/.-]\d{4}""").matches(s) ->
                return s.split('/', '.', '-').let { (m, y) -> runCatching { YearMonth.of(y.toInt(), m.toInt()).atEndOfMonth() }.getOrNull() }
            else -> return null
        }
        return runCatching { LocalDate.of(parts.third, parts.second, parts.first) }.getOrNull()
    }

    /** "08/29", "0829", "8/29", "08/2029", "08-29", "2029-08" → August 2029. Null if unreadable. */
    fun parseCardExpiry(raw: String?): YearMonth? {
        val s = raw?.trim()?.replace(" ", "") ?: return null
        val (month, year) = when {
            Regex("""\d{4}-\d{1,2}""").matches(s) -> s.substringAfter('-').toInt() to s.substringBefore('-').toInt()
            Regex("""\d{1,2}[/-]\d{2}""").matches(s) -> s.split('/', '-').let { it[0].toInt() to 2000 + it[1].toInt() }
            Regex("""\d{1,2}[/-]\d{4}""").matches(s) -> s.split('/', '-').let { it[0].toInt() to it[1].toInt() }
            Regex("""\d{4}""").matches(s) -> s.take(2).toInt() to 2000 + s.takeLast(2).toInt()
            else -> return null
        }
        return if (month in 1..12) YearMonth.of(year, month) else null
    }

    private fun digest(password: String): String =
        MessageDigest.getInstance("SHA-256").digest(password.toByteArray()).joinToString("") { "%02x".format(it) }
}
