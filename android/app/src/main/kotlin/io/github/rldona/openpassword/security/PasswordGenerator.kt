package io.github.rldona.openpassword.security

import android.content.Context
import java.security.SecureRandom
import kotlin.math.log2

/** Random passwords, passphrases and PINs from the system CSPRNG. */
object PasswordGenerator {
    private const val LOWER = "abcdefghijkmnopqrstuvwxyz"
    private const val UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    private const val DIGITS = "23456789"
    private const val SYMBOLS = "!#$%&*+-=?@^_~"
    private val classes = listOf(LOWER, UPPER, DIGITS, SYMBOLS)

    /** Characters a password may contain: no look-alikes such as l/1 or O/0. */
    val PASSWORD_ALPHABET: String = classes.joinToString("")

    /** One character from each class, the rest from all of them, then shuffled. */
    fun password(length: Int = 20, random: SecureRandom = SecureRandom()): String {
        require(length >= classes.size) { "length must be at least ${classes.size}" }
        val chars = classes.map { it[random.nextInt(it.length)] } +
            List(length - classes.size) { PASSWORD_ALPHABET[random.nextInt(PASSWORD_ALPHABET.length)] }
        return chars.shuffled(random).joinToString("")
    }

    /**
     * Words drawn uniformly from [wordlist] (the EFF large list: 7776 words, ~12.9 bits each).
     * 6 words ≈ 77 bits, plenty for a master password stretched with Argon2id.
     * Spaces by default: four EFF words contain a hyphen (e.g. "t-shirt"), so "-" would make a
     * phrase you have to memorise ambiguous. Use "-" only where spaces are not accepted.
     */
    fun passphrase(wordlist: List<String>, words: Int = 6, separator: String = " ", random: SecureRandom = SecureRandom()): String {
        require(words >= 1)
        require(wordlist.size >= 2) { "wordlist is empty" }
        return List(words) { wordlist[random.nextInt(wordlist.size)] }.joinToString(separator)
    }

    fun passphraseBits(wordlistSize: Int, words: Int): Double = words * log2(wordlistSize.toDouble())

    fun pin(digits: Int = 6, random: SecureRandom = SecureRandom()): String {
        require(digits >= 1)
        return List(digits) { random.nextInt(10) }.joinToString("")
    }
}

/** The EFF large wordlist (CC BY 3.0 US, www.eff.org/dice), bundled as an asset. Loaded once. */
object Wordlist {
    const val EXPECTED_SIZE = 7776
    @Volatile private var cached: List<String>? = null

    fun eff(context: Context): List<String> = cached ?: synchronized(this) {
        cached ?: context.assets.open("eff_large_wordlist.txt").bufferedReader().use { r ->
            r.readLines().filter(String::isNotBlank)
        }.also {
            check(it.size == EXPECTED_SIZE) { "wordlist has ${it.size} words" }
            cached = it
        }
    }
}
