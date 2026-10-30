package io.github.rldona.openpassword.autofill

import java.net.URI
import java.util.Locale

/** Where a fill request comes from: a web page in a browser, or a native app. */
sealed interface FillTarget {
    data class Web(val domain: String) : FillTarget
    data class App(val packageName: String) : FillTarget
}

/**
 * Decides whether a saved login belongs to a fill target. Strict on purpose: a password
 * is only offered to the exact host saved or one of its subdomains, never to a look-alike
 * like "google.com.example.net", and to apps only by their (OS-verified) package name.
 */
object LoginMatcher {
    const val APP_SCHEME = "androidapp://"

    fun appUrl(packageName: String) = APP_SCHEME + packageName

    fun matches(savedUrls: List<String>, target: FillTarget): Boolean = savedUrls.any { url ->
        when (target) {
            is FillTarget.App -> {
                val trimmed = url.trim()
                target.packageName.isNotBlank() &&
                    trimmed.startsWith(APP_SCHEME, ignoreCase = true) &&
                    trimmed.substring(APP_SCHEME.length) == target.packageName
            }
            is FillTarget.Web -> {
                val saved = hostOf(url) ?: return@any false
                val visited = normalizeHost(target.domain) ?: return@any false
                hostMatches(saved, visited)
            }
        }
    }

    /**
     * Exact host, or a real subdomain of a saved *registrable* domain. IP literals and public
     * suffixes ("co.uk", "github.io") only match themselves; without the suffix list we fail
     * closed to exact match.
     */
    private fun hostMatches(saved: String, visited: String): Boolean {
        if (visited == saved) return true
        if (isIpLiteral(saved) || isIpLiteral(visited)) return false
        if (!visited.endsWith(".$saved")) return false
        return PublicSuffix.isAvailable && !PublicSuffix.isPublicSuffix(saved)
    }

    private val IPV4 = Regex("""\d{1,3}(\.\d{1,3}){3}""")

    private fun isIpLiteral(host: String) = IPV4.matches(host) || ':' in host || host.startsWith("[")

    /** "https://Accounts.Google.com/login" → "accounts.google.com". Null for app links and junk. */
    fun hostOf(url: String): String? {
        val trimmed = url.trim()
        if (trimmed.isEmpty() || trimmed.startsWith(APP_SCHEME, ignoreCase = true)) return null
        val withScheme = if ("://" in trimmed) trimmed else "https://$trimmed"
        val host = try {
            URI(withScheme).host
        } catch (_: Exception) {
            null
        }
        return normalizeHost(host)
    }

    private fun normalizeHost(host: String?): String? {
        val h = host?.trim()?.trimEnd('.')?.lowercase(Locale.ROOT)?.removePrefix("www.") ?: return null
        // A single label ("localhost", "com") or an IP literal is never matched by suffix.
        return h.takeIf { it.contains('.') && it.isNotBlank() }
    }
}
