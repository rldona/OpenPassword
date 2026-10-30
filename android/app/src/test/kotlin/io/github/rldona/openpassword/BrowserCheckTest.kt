package io.github.rldona.openpassword

import io.github.rldona.openpassword.autofill.BrowserCheck
import io.github.rldona.openpassword.autofill.CachedBrowserCheck
import io.github.rldona.openpassword.autofill.DefaultBrowser
import io.github.rldona.openpassword.autofill.FillTarget
import io.github.rldona.openpassword.autofill.KnownBrowsers
import io.github.rldona.openpassword.autofill.StructureParser
import io.github.rldona.openpassword.autofill.ViewHandlers
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BrowserCheckTest {
    private class FakeHandlers(val https: Set<String>, val http: Set<String>) : ViewHandlers {
        var calls = 0
        override fun packagesFor(scheme: String): Set<String> {
            calls++
            return if (scheme == "https") https else http
        }
    }

    private val chrome = "com.android.chrome"
    private val firefox = "org.mozilla.firefox"
    private val handlers = FakeHandlers(
        https = setOf(chrome, firefox, "com.bank.app"),
        http = setOf(chrome, firefox),
    )

    @Test fun knownBrowsersAreBrowsers() {
        val check = CachedBrowserCheck(handlers)
        assertTrue(check.isBrowser(chrome))
        assertTrue(check.isBrowser(firefox))
    }

    @Test fun anAppThatOnlyHandlesHttpsLinksIsNotABrowser() {
        assertFalse(CachedBrowserCheck(handlers).isBrowser("com.bank.app"))
    }

    @Test fun anUnknownPackageIsNotABrowser() {
        val check = CachedBrowserCheck(handlers)
        assertFalse(check.isBrowser("com.evil.nonexistent"))
        assertFalse(check.isBrowser(""))
    }

    @Test fun theSetIsCachedAndRebuiltAfterTheTtl() {
        var now = 0L
        val check = CachedBrowserCheck(handlers, DefaultBrowser { "com.other.browser" }, now = { now }, ttlMs = 1_000)
        repeat(50) { check.isBrowser("com.other.browser") }
        assertEquals(2, handlers.calls)
        now = 1_000
        check.isBrowser("com.other.browser")
        assertEquals(4, handlers.calls)
    }

    @Test fun warmingAheadAvoidsTheLookupOnTheFillRequest() {
        val check = CachedBrowserCheck(handlers)
        check.warm()
        val before = handlers.calls
        check.isBrowser("com.other.browser")
        assertEquals(before, handlers.calls)
    }

    @Test fun aBrowserKeepsItsWebDomain() {
        val target = StructureParser.targetFor(chrome, "banco.example", CachedBrowserCheck(handlers))
        assertEquals(FillTarget.Web("banco.example"), target)
    }

    @Test fun aNonBrowserAppClaimingADomainIsTreatedAsAnApp() {
        val check = CachedBrowserCheck(handlers)
        for (pkg in listOf("com.evil.app", "com.bank.app", "com.evil.nonexistent")) {
            val target = StructureParser.targetFor(pkg, "banco.example", check)
            assertEquals(FillTarget.App(pkg), target)
            assertFalse(target is FillTarget.Web)
        }
    }

    @Test fun noDomainMeansAnAppEvenInABrowser() {
        assertEquals(FillTarget.App(chrome), StructureParser.targetFor(chrome, null, BrowserCheck { true }))
    }

    @Test fun theDefaultBrowserIsABrowserEvenIfNotInTheList() {
        val both = FakeHandlers(setOf("org.new.browser"), setOf("org.new.browser"))
        assertTrue(CachedBrowserCheck(both, DefaultBrowser { "org.new.browser" }).isBrowser("org.new.browser"))
    }

    @Test fun anAppWithABrowsableFilterThatIsNeitherListedNorDefaultIsNotABrowser() {
        val spoof = FakeHandlers(setOf("com.evil.app", chrome), setOf("com.evil.app", chrome))
        val check = CachedBrowserCheck(spoof, DefaultBrowser { chrome })
        assertFalse(check.isBrowser("com.evil.app"))
        assertEquals(FillTarget.App("com.evil.app"), StructureParser.targetFor("com.evil.app", "accounts.google.com", check))
    }

    @Test fun withoutADefaultBrowserOnlyTheListCounts() {
        val spoof = FakeHandlers(setOf("com.evil.app"), setOf("com.evil.app"))
        val check = CachedBrowserCheck(spoof, DefaultBrowser { null })
        assertFalse(check.isBrowser("com.evil.app"))
        assertTrue(check.isBrowser(firefox))
    }

    @Test fun aDefaultAppThatDoesNotHandleBothSchemesIsNotABrowser() {
        val httpsOnly = FakeHandlers(setOf("com.bank.app"), emptySet())
        assertFalse(CachedBrowserCheck(httpsOnly, DefaultBrowser { "com.bank.app" }).isBrowser("com.bank.app"))
    }

    @Test fun theKnownListHasRealPackageNames() {
        for (pkg in listOf("com.android.chrome", "org.mozilla.firefox", "org.mozilla.focus", "com.brave.browser", "com.microsoft.emmx",
            "com.opera.browser", "com.sec.android.app.sbrowser", "com.duckduckgo.mobile.android", "com.vivaldi.browser",
            "com.kiwibrowser.browser", "org.torproject.torbrowser", "us.spotco.fennec_dos")) {
            assertTrue(pkg, pkg in KnownBrowsers.PACKAGES)
        }
    }
}
