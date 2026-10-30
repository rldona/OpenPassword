package io.github.rldona.openpassword.autofill

import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri

/**
 * Whether a package is a real web browser. `ViewStructure.setWebDomain` is filled in by the
 * app being filled, so a page's domain is only believed when it comes from a browser.
 */
fun interface BrowserCheck {
    fun isBrowser(packageName: String): Boolean
}

/** The packages that handle a VIEW intent for the URL scheme [scheme] (one URL, any host). */
fun interface ViewHandlers {
    fun packagesFor(scheme: String): Set<String>
}

/** The package of the user's default browser (the one `https://` opens without a chooser), if any. */
fun interface DefaultBrowser {
    fun packageName(): String?
}

/** Packages of well-known browsers. An app cannot claim one of these names: package names are unique per device. */
object KnownBrowsers {
    val PACKAGES: Set<String> = setOf(
        "com.android.chrome", "com.chrome.beta", "com.chrome.dev", "com.chrome.canary", "org.chromium.chrome",
        "org.mozilla.firefox", "org.mozilla.firefox_beta", "org.mozilla.fenix", "org.mozilla.fennec_fdroid",
        "org.mozilla.focus", "org.mozilla.klar", "io.github.forkmaintainers.iceraven", "us.spotco.fennec_dos",
        "com.brave.browser", "com.brave.browser_beta", "com.brave.browser_nightly",
        "com.microsoft.emmx", "com.microsoft.emmx.beta", "com.microsoft.emmx.dev", "com.microsoft.emmx.canary",
        "com.opera.browser", "com.opera.browser.beta", "com.opera.mini.native", "com.opera.gx",
        "com.sec.android.app.sbrowser", "com.sec.android.app.sbrowser.beta",
        "com.duckduckgo.mobile.android", "com.vivaldi.browser", "com.kiwibrowser.browser",
        "org.cromite.cromite", "org.bromite.bromite", "org.torproject.torbrowser", "org.torproject.torbrowser_alpha",
        "com.yandex.browser", "org.lineageos.jelly", "org.gnu.icecat",
    )
}

/**
 * A package is a browser if it is in [KnownBrowsers], or it is the user's default browser
 * (choosing it is a user decision) and handles both `https://` and `http://` links.
 * Declaring a VIEW/BROWSABLE intent-filter needs no permission, so a filter alone proves nothing.
 *
 * The handler set is cached and rebuilt after [ttlMs]; the lookup is a binder call, so
 * [warm] can be called off the main thread beforehand.
 */
class CachedBrowserCheck(
    private val handlers: ViewHandlers,
    private val defaultBrowser: DefaultBrowser = DefaultBrowser { null },
    private val now: () -> Long = { System.nanoTime() / 1_000_000 },
    private val ttlMs: Long = TTL_MS,
    private val known: Set<String> = KnownBrowsers.PACKAGES,
) : BrowserCheck {
    private class Snapshot(val at: Long, val packages: Set<String>, val default: String?)

    @Volatile private var snapshot: Snapshot? = null

    fun warm() {
        snapshot = Snapshot(
            now(),
            handlers.packagesFor("https") intersect handlers.packagesFor("http"),
            defaultBrowser.packageName(),
        )
    }

    override fun isBrowser(packageName: String): Boolean {
        if (packageName.isEmpty()) return false
        if (packageName in known) return true
        val current = snapshot?.takeIf { now() - it.at < ttlMs } ?: run { warm(); snapshot!! }
        return packageName == current.default && packageName in current.packages
    }

    companion object {
        const val TTL_MS = 5 * 60_000L

        /** Needs the `<queries>` entry for VIEW https/http in the manifest (no QUERY_ALL_PACKAGES). */
        fun forPackageManager(pm: PackageManager) = CachedBrowserCheck(
            ViewHandlers { scheme -> pm.queryIntentActivities(viewIntent(scheme), PackageManager.MATCH_DEFAULT_ONLY)
                .mapNotNull { it.activityInfo?.packageName }
                .toSet() },
            DefaultBrowser {
                // "android" is the system chooser: no default has been picked.
                pm.resolveActivity(viewIntent("https"), PackageManager.MATCH_DEFAULT_ONLY)
                    ?.activityInfo?.packageName?.takeIf { it != "android" }
            },
        )

        private fun viewIntent(scheme: String) =
            Intent(Intent.ACTION_VIEW, Uri.parse("$scheme://www.example.com/")).addCategory(Intent.CATEGORY_BROWSABLE)
    }
}
