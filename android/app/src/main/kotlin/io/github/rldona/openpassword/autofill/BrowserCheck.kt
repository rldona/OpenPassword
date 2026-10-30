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

/**
 * A browser handles both `https://` and `http://` links, so only packages that appear for
 * both count. The set is cached and rebuilt after [ttlMs]; the lookup is a binder call, so
 * [warm] can be called off the main thread beforehand.
 */
class CachedBrowserCheck(
    private val handlers: ViewHandlers,
    private val now: () -> Long = { System.nanoTime() / 1_000_000 },
    private val ttlMs: Long = TTL_MS,
) : BrowserCheck {
    private class Snapshot(val at: Long, val packages: Set<String>)

    @Volatile private var snapshot: Snapshot? = null

    fun warm() {
        snapshot = Snapshot(now(), handlers.packagesFor("https") intersect handlers.packagesFor("http"))
    }

    override fun isBrowser(packageName: String): Boolean {
        val current = snapshot?.takeIf { now() - it.at < ttlMs } ?: run { warm(); snapshot!! }
        return packageName in current.packages
    }

    companion object {
        const val TTL_MS = 5 * 60_000L

        /** Needs the `<queries>` entry for VIEW https/http in the manifest (no QUERY_ALL_PACKAGES). */
        fun forPackageManager(pm: PackageManager) = CachedBrowserCheck(ViewHandlers { scheme ->
            val intent = Intent(Intent.ACTION_VIEW, Uri.parse("$scheme://www.example.com/"))
                .addCategory(Intent.CATEGORY_BROWSABLE)
            pm.queryIntentActivities(intent, PackageManager.MATCH_DEFAULT_ONLY)
                .mapNotNull { it.activityInfo?.packageName }
                .toSet()
        })
    }
}
