package io.github.rldona.openpassword.health

import io.github.rldona.openpassword.ui.onboarding.strengthOf
import java.security.MessageDigest
import java.time.LocalDate
import java.time.YearMonth

/** What the health check needs from one item. Built from decrypted details, then dropped. */
data class HealthInput(
    val id: String,
    val isLogin: Boolean,
    val isCard: Boolean,
    val passwords: List<String>,
    val cardExpiry: String?,
    /** Unix seconds of the last edit of the item. */
    val updatedAt: Long,
)

data class HealthReport(
    val weak: List<String>,
    /** Groups of item ids sharing the same password, largest first. */
    val reused: List<List<String>>,
    val old: List<String>,
    val expiredCards: List<String>,
    val expiringCards: List<String>,
) {
    val reusedIds: Set<String> get() = reused.flatten().toSet()
    /** Number of items with at least one problem. */
    val affected: Int get() = (weak + reusedIds + old + expiredCards + expiringCards).toSet().size
    val isClean: Boolean get() = affected == 0

    companion object {
        val EMPTY = HealthReport(emptyList(), emptyList(), emptyList(), emptyList(), emptyList())
    }
}

object VaultHealth {
    const val OLD_AFTER_DAYS = 365L
    const val EXPIRING_MONTHS = 2L

    fun analyze(items: List<HealthInput>, today: LocalDate): HealthReport {
        val logins = items.filter { it.isLogin && it.passwords.isNotEmpty() }

        val weak = logins.filter { item -> item.passwords.any { strengthOf(it).label == "Débil" } }.map { it.id }

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

        return HealthReport(weak, reused, old, expired, expiring)
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
