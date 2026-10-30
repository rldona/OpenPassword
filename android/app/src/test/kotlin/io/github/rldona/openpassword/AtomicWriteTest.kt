package io.github.rldona.openpassword

import io.github.rldona.openpassword.data.atomicWrite
import java.io.File
import java.io.IOException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** ID-INT-10. The fsync itself cannot be observed from the JVM; this covers the contract around it. */
class AtomicWriteTest {
    @get:Rule val folder = TemporaryFolder()

    @Test
    fun `writes the bytes under the final name and leaves no temp file`() {
        val target = File(folder.root, "vault-header.json")
        atomicWrite(target, "hola".toByteArray())
        assertArrayEquals("hola".toByteArray(), target.readBytes())
        assertEquals(listOf("vault-header.json"), folder.root.list().orEmpty().toList())
    }

    @Test
    fun `replaces existing content`() {
        val target = File(folder.root, "secret-key.bin").apply { writeText("viejo") }
        atomicWrite(target, "nuevo".toByteArray())
        assertEquals("nuevo", target.readText())
    }

    @Test
    fun `a failed rename keeps the old file and removes the temp one`() {
        val target = File(folder.root, "dir").apply { mkdir(); File(this, "x").writeText("x") }
        // Renaming a file over a non-empty directory fails.
        val failure = runCatching { atomicWrite(target, "z".toByteArray()) }.exceptionOrNull()
        assertTrue(failure is IOException)
        assertTrue(File(target, "x").exists())
        assertFalse(File(folder.root, "dir.tmp").exists())
    }
}
