package io.github.rldona.openpassword

import io.github.rldona.openpassword.security.Wordlist
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/** Guards the bundled EFF large wordlist against truncation or accidental edits. */
class WordlistAssetTest {
    private val file = File("src/main/assets/eff_large_wordlist.txt")
    private val words = file.readLines()

    @Test
    fun hasAll7776UniqueLowercaseWords() {
        assertEquals(Wordlist.EXPECTED_SIZE, words.size)
        assertEquals(words.size, words.toSet().size)
        assertTrue(words.all { it.matches(Regex("[a-z-]{3,9}")) })
        assertEquals("abacus", words.first())
        assertEquals("zoom", words.last())
    }

    @Test
    fun contentIsUnchanged() {
        // SHA-256 of the words-only file derived from eff.org/files/2016/07/18/eff_large_wordlist.txt
        // (original file: addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e).
        val digest = MessageDigest.getInstance("SHA-256").digest(file.readBytes()).joinToString("") { "%02x".format(it) }
        assertEquals(EXPECTED_SHA256, digest)
    }

    companion object {
        const val EXPECTED_SHA256 = "6d557f0693958fb5e650b68b5bee585eb82cf4da32965505c789e924743bc522"
    }
}
