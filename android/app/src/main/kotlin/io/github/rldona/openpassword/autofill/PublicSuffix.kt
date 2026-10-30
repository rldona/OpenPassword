package io.github.rldona.openpassword.autofill

import java.net.IDN
import java.util.Locale

/**
 * Public Suffix List (https://publicsuffix.org, MPL 2.0), loaded once and kept in memory
 * from the unmodified `public_suffix_list.dat` bundled as a classpath resource.
 *
 * If the list cannot be loaded, [isAvailable] is false and callers must fail closed
 * (exact host match only): never guess a suffix.
 */
object PublicSuffix {
    private const val RESOURCE = "public_suffix_list.dat"

    private class Rules(val normal: Set<String>, val wildcard: Set<String>, val exception: Set<String>)

    private val rules: Rules? by lazy { load(readResource()) }

    /** The list's lines, or null if it is missing or unreadable (also half-way): fail closed, never throw. */
    private fun readResource(): List<String>? = try {
        PublicSuffix::class.java.classLoader?.getResourceAsStream(RESOURCE)?.bufferedReader(Charsets.UTF_8)?.useLines { it.toList() }
    } catch (_: java.io.IOException) {
        null
    }

    val isAvailable: Boolean get() = rules != null

    private fun load(lines: List<String>?): Rules? {
        if (lines == null) return null
        val normal = HashSet<String>()
        val wildcard = HashSet<String>()
        val exception = HashSet<String>()
        for (raw in lines) {
            // A rule ends at the first whitespace; comments start with "//".
            val line = raw.trim().substringBefore(' ').substringBefore('\t')
            if (line.isEmpty() || line.startsWith("//")) continue
            val rule = line.lowercase(Locale.ROOT)
            val forms = listOfNotNull(rule, asciiForm(rule)).distinct()
            when {
                rule.startsWith("!") -> forms.forEach { exception += it.removePrefix("!") }
                rule.startsWith("*.") -> forms.forEach { wildcard += it.removePrefix("*.") }
                else -> normal += forms
            }
        }
        // An empty or truncated list is not a list.
        return if (normal.size < 100) null else Rules(normal, wildcard, exception)
    }

    /** Punycode form of a Unicode rule, so "xn--" hosts hit IDN rules too. Null if not applicable. */
    private fun asciiForm(rule: String): String? {
        if (rule.all { it.code < 128 }) return null
        return runCatching { IDN.toASCII(rule, IDN.ALLOW_UNASSIGNED) }.getOrNull()?.takeIf { it != rule }
    }

    /** Number of trailing labels of [labels] that form the public suffix, or null without a list. */
    private fun suffixLength(labels: List<String>): Int? {
        val r = rules ?: return null
        val n = labels.size
        var best = 1 // Implicit "*" rule: an unknown TLD is a public suffix.
        for (i in 0 until n) {
            val candidate = labels.subList(i, n).joinToString(".")
            if (candidate in r.exception) return n - i - 1
            val len = n - i
            if (len > best) {
                val isNormal = candidate in r.normal
                val isWildcard = i + 1 < n && labels.subList(i + 1, n).joinToString(".") in r.wildcard
                if (isNormal || isWildcard) best = len
            }
        }
        return best
    }

    private fun labelsOf(host: String): List<String>? {
        val h = host.trim().trimEnd('.').lowercase(Locale.ROOT)
        if (h.isEmpty()) return null
        val labels = h.split('.')
        return labels.takeIf { l -> l.none { it.isEmpty() } }
    }

    /** True if [host] is itself a public suffix ("co.uk", "github.io"). False without a list. */
    fun isPublicSuffix(host: String): Boolean {
        val labels = labelsOf(host) ?: return false
        return suffixLength(labels) == labels.size
    }

    /** "a.b.example.co.uk" → "example.co.uk". Null if [host] is a public suffix or there is no list. */
    fun registrableDomain(host: String): String? {
        val labels = labelsOf(host) ?: return null
        val suffix = suffixLength(labels) ?: return null
        if (labels.size <= suffix) return null
        return labels.takeLast(suffix + 1).joinToString(".")
    }
}
