package io.github.rldona.openpassword.data

import java.io.File
import java.io.FileOutputStream
import java.io.IOException

/**
 * Writes [bytes] to a temporary file next to [target], forces them to disk, and renames it
 * over [target]. The `sync()` comes before the rename (ID-INT-10): otherwise after a power cut
 * the rename could be persisted before the data and leave an empty file. If anything fails the
 * temporary file is removed and [target] keeps its previous content.
 *
 * Not covered: the rename itself is not flushed (Java cannot `fsync` a directory), so a cut
 * right after may still lose the new file, but never leave a half-written one.
 */
internal fun atomicWrite(target: File, bytes: ByteArray) {
    val tmp = File(target.parentFile, "${target.name}.tmp")
    try {
        FileOutputStream(tmp).use { out ->
            out.write(bytes)
            out.flush()
            out.fd.sync()
        }
        if (!tmp.renameTo(target)) throw IOException("could not write ${target.name}")
    } catch (e: IOException) {
        tmp.delete()
        throw e
    }
}
