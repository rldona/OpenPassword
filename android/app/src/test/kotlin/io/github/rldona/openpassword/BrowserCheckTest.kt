package io.github.rldona.openpassword

import io.github.rldona.openpassword.autofill.BrowserCheck
import io.github.rldona.openpassword.autofill.CachedBrowserCheck
import io.github.rldona.openpassword.autofill.FillTarget
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
        val check = CachedBrowserCheck(handlers, now = { now }, ttlMs = 1_000)
        repeat(50) { check.isBrowser(chrome) }
        assertEquals(2, handlers.calls)
        now = 1_000
        check.isBrowser(chrome)
        assertEquals(4, handlers.calls)
    }

    @Test fun warmingAheadAvoidsTheLookupOnTheFillRequest() {
        val check = CachedBrowserCheck(handlers)
        check.warm()
        val before = handlers.calls
        check.isBrowser(chrome)
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
}
