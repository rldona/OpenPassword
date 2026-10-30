package io.github.rldona.openpassword.ui

import java.io.InputStream

/**
 * Reads [input] to the end into one array, never keeping more than [maxBytes], and zeroes every
 * intermediate buffer (ID-INT-12). `ByteArrayOutputStream` would leave its growing internal
 * buffer, and the copy `toByteArray()` makes, in the heap until the next GC; here each buffer
 * that is replaced or no longer needed is filled with zeros, also when reading fails or the
 * limit is exceeded.
 *
 * The caller owns the returned array and must zero it as soon as it is parsed.
 *
 * Residue that cannot be wiped from here: what the system, the content provider and the kernel
 * hold while serving the file, and the `String`s the parsers later build from these bytes
 * (immutable, collected by the GC).
 */
internal fun readWiping(input: InputStream, maxBytes: Int, initialSize: Int = 64 * 1024): ByteArray {
    // One byte of slack over the limit: reading it proves the input is too large.
    val limit = maxBytes.toLong() + 1
    var buffer = ByteArray(minOf(maxOf(initialSize, 1).toLong(), limit).toInt())
    var size = 0
    try {
        while (true) {
            if (size == buffer.size) {
                require(buffer.size < limit) { "too large" }
                val grown = buffer.copyOf(minOf(buffer.size.toLong() * 2, limit).toInt())
                buffer.fill(0)
                buffer = grown
            }
            val n = input.read(buffer, size, buffer.size - size)
            if (n < 0) break
            size += n
        }
        return buffer.copyOf(size)
    } finally {
        buffer.fill(0)
    }
}
