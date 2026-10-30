package io.github.rldona.openpassword

import io.github.rldona.openpassword.ui.readWiping
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** ID-INT-12: intermediate buffers of a plaintext export are zeroed. */
class WipingReadTest {
    @Test
    fun `returns exactly the bytes of the input across several growths`() {
        val data = ByteArray(1000) { (it % 251 + 1).toByte() }
        assertArrayEquals(data, readWiping(ByteArrayInputStream(data), maxBytes = 5000, initialSize = 16))
    }

    @Test
    fun `empty input gives an empty array`() {
        assertEquals(0, readWiping(ByteArrayInputStream(ByteArray(0)), maxBytes = 10).size)
    }

    @Test
    fun `exactly the limit is accepted, one more is refused`() {
        assertEquals(100, readWiping(ByteArrayInputStream(ByteArray(100) { 1 }), maxBytes = 100, initialSize = 8).size)
        val error = runCatching { readWiping(ByteArrayInputStream(ByteArray(101) { 1 }), maxBytes = 100, initialSize = 8) }.exceptionOrNull()
        assertTrue(error is IllegalArgumentException)
    }

    /** Records every array handed to read(), to look at them after the call returns. */
    private class Spy(private val data: ByteArray, private val failAfter: Int = Int.MAX_VALUE) : InputStream() {
        val seen = mutableListOf<ByteArray>()
        private var pos = 0
        override fun read(): Int = throw UnsupportedOperationException()
        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (seen.none { it === b }) seen += b
            if (pos >= failAfter) throw IOException("boom")
            if (pos >= data.size) return -1
            val n = minOf(len, data.size - pos, 7)
            data.copyInto(b, off, pos, pos + n)
            pos += n
            return n
        }
    }

    @Test
    fun `every internal buffer is zero afterwards`() {
        val spy = Spy(ByteArray(300) { 9 })
        val result = readWiping(spy, maxBytes = 1000, initialSize = 16)
        assertEquals(300, result.size)
        assertTrue("expected several buffers, got ${spy.seen.size}", spy.seen.size > 1)
        spy.seen.forEach { buf -> assertTrue(buf.all { it == 0.toByte() }) }
        assertTrue(result.all { it == 9.toByte() })
    }

    @Test
    fun `buffers are zeroed also when reading fails or the limit is exceeded`() {
        val failing = Spy(ByteArray(300) { 9 }, failAfter = 100)
        assertTrue(runCatching { readWiping(failing, maxBytes = 1000, initialSize = 16) }.exceptionOrNull() is IOException)
        failing.seen.forEach { buf -> assertTrue(buf.all { it == 0.toByte() }) }

        val big = Spy(ByteArray(300) { 9 })
        assertTrue(runCatching { readWiping(big, maxBytes = 100, initialSize = 16) }.exceptionOrNull() is IllegalArgumentException)
        big.seen.forEach { buf -> assertTrue(buf.all { it == 0.toByte() }) }
    }
}
