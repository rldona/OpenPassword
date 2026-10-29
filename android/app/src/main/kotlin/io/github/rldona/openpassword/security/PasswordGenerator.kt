package io.github.rldona.openpassword.security

import java.security.SecureRandom

/** Random passwords from the system CSPRNG, without look-alike characters. */
object PasswordGenerator {
    private const val LOWER = "abcdefghijkmnopqrstuvwxyz"
    private const val UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    private const val DIGITS = "23456789"
    private const val SYMBOLS = "!#$%&*+-=?@^_~"
    private val random = SecureRandom()

    fun password(length: Int = 20): String {
        require(length >= 8)
        val classes = listOf(LOWER, UPPER, DIGITS, SYMBOLS)
        val all = classes.joinToString("")
        // One character from each class, the rest from all, then shuffle.
        val chars = classes.map { it[random.nextInt(it.length)] } +
            List(length - classes.size) { all[random.nextInt(all.length)] }
        return chars.shuffled(random).joinToString("")
    }

    fun pin(digits: Int = 6): String = List(digits) { random.nextInt(10) }.joinToString("")
}
