package io.github.rldona.openpassword.ui.vault

/** Payment card checks done offline: Luhn checksum and the network from the number's prefix. */
object CardNumber {
    fun digits(raw: String): String = raw.filter(Char::isDigit)

    /** Only spaces and dashes are allowed between digits; 12 to 19 digits (ISO/IEC 7812). */
    fun isValid(raw: String): Boolean {
        if (!raw.all { it.isDigit() || it == ' ' || it == '-' }) return false
        val d = digits(raw)
        if (d.length !in 12..19) return false
        val sum = d.reversed().mapIndexed { i, c ->
            val n = c - '0'
            if (i % 2 == 1) (n * 2).let { if (it > 9) it - 9 else it } else n
        }.sum()
        return sum % 10 == 0
    }

    /** "Visa", "Mastercard"… or null if the prefix is unknown. */
    fun network(raw: String): String? {
        val d = digits(raw)
        fun prefix(n: Int) = d.take(n).toIntOrNull() ?: -1
        return when {
            d.startsWith("4") -> "Visa"
            prefix(2) in 51..55 || prefix(4) in 2221..2720 -> "Mastercard"
            prefix(2) == 34 || prefix(2) == 37 -> "American Express"
            d.startsWith("6011") || d.startsWith("65") || prefix(3) in 644..649 -> "Discover"
            prefix(4) in 3528..3589 -> "JCB"
            prefix(2) == 36 || prefix(3) in 300..305 || d.startsWith("38") || d.startsWith("39") -> "Diners Club"
            d.startsWith("62") -> "UnionPay"
            prefix(2) in 50..69 -> "Maestro"
            else -> null
        }
    }
}
