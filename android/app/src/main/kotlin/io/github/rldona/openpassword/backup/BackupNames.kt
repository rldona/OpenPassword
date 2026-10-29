package io.github.rldona.openpassword.backup

import java.time.LocalDateTime
import java.time.format.DateTimeFormatter

/** Names of automatic backups. Pure, so rotation can be unit-tested. */
object BackupNames {
    const val PREFIX = "openpassword-auto-"
    const val SUFFIX = ".opvault"
    private val STAMP = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")
    private val PATTERN = Regex("""^openpassword-auto-\d{8}-\d{6}\.opvault$""")

    fun nameFor(time: LocalDateTime): String = PREFIX + time.format(STAMP) + SUFFIX

    /** Only names this app produces: rotation never touches anything else in the folder. */
    fun isAutomatic(name: String): Boolean = PATTERN.matches(name)

    /** Automatic backups to delete so that only the newest [keep] remain. */
    fun toDelete(names: List<String>, keep: Int): List<String> =
        names.filter(::isAutomatic).sortedDescending().drop(keep.coerceAtLeast(1))
}
