package io.github.rldona.openpassword

import io.github.rldona.openpassword.security.PasswordGenerator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class PasswordGeneratorTest {
    private val wordlist: List<String> = File("src/main/assets/eff_large_wordlist.txt").readLines()

    @Test
    fun passwordsHaveTheLengthEveryClassAndNoLookAlikes() {
        repeat(500) {
            val p = PasswordGenerator.password(20)
            assertEquals(20, p.length)
            assertTrue(p.any(Char::isLowerCase))
            assertTrue(p.any(Char::isUpperCase))
            assertTrue(p.any(Char::isDigit))
            assertTrue(p.any { !it.isLetterOrDigit() })
            assertTrue("only allowed characters: $p", p.all { it in PasswordGenerator.PASSWORD_ALPHABET })
            assertTrue("no ambiguous characters: $p", p.none { it in "lIO01" })
        }
    }

    @Test(expected = IllegalArgumentException::class)
    fun passwordsShorterThanTheClassesAreRejected() {
        PasswordGenerator.password(3)
    }

    @Test
    fun passwordsDoNotRepeat() {
        val seen = List(2000) { PasswordGenerator.password(16) }.toSet()
        assertEquals(2000, seen.size)
    }

    @Test
    fun passphrasesUseWordsFromTheList() {
        val words = wordlist.toSet()
        repeat(200) {
            val phrase = PasswordGenerator.passphrase(wordlist, words = 6)
            val parts = phrase.split(" ")
            assertEquals(6, parts.size)
            assertTrue(parts.all { it in words })
        }
        assertEquals(3, PasswordGenerator.passphrase(wordlist, words = 3, separator = ".").split(".").size)
    }

    @Test
    fun defaultSeparatorIsUnambiguousBecauseSomeWordsHaveHyphens() {
        assertTrue(wordlist.any { '-' in it })
        assertTrue(wordlist.none { ' ' in it })
    }

    @Test
    fun sixEffWordsGiveAbout77Bits() {
        assertEquals(77.5, PasswordGenerator.passphraseBits(7776, 6), 0.1)
    }

    @Test
    fun pinsAreDigitsAndRoughlyUniform() {
        val counts = IntArray(10)
        repeat(5000) {
            val pin = PasswordGenerator.pin(6)
            assertEquals(6, pin.length)
            pin.forEach { counts[it - '0']++ }
        }
        // 30 000 digits: each should appear ~3000 times; 2500..3500 is a very loose bound.
        assertTrue(counts.joinToString(), counts.all { it in 2500..3500 })
    }
}
