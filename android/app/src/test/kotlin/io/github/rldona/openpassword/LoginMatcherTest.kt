package io.github.rldona.openpassword

import io.github.rldona.openpassword.autofill.FillTarget
import io.github.rldona.openpassword.autofill.LoginMatcher
import io.github.rldona.openpassword.autofill.PublicSuffix
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.random.Random

class LoginMatcherTest {
    private fun web(saved: String, visited: String) = LoginMatcher.matches(listOf(saved), FillTarget.Web(visited))

    @Test
    fun aWebDomainThatIsNotABareHostNameNeverMatches() {
        for (bad in listOf("evil.com/google.com", "https://google.com", "google.com:443", "google.com/", "user@google.com",
            "evil.com?x=.google.com", "evil.com #.google.com", "a..google.com", "evil.com/.google.com", "")) {
            assertFalse(bad, web("google.com", bad))
        }
    }

    @Test
    fun exactHostAndSubdomainsMatch() {
        assertTrue(web("https://accounts.google.com", "accounts.google.com"))
        assertTrue(web("google.com", "accounts.google.com"))
        assertTrue(web("https://www.google.com/login", "google.com"))
        assertTrue(web("https://www.google.com/login", "mail.google.com"))
        assertTrue(web("HTTPS://Google.COM", "GOOGLE.com."))
    }

    @Test
    fun lookAlikeDomainsNeverMatch() {
        assertFalse(web("google.com", "google.com.phishing.net"))
        assertFalse(web("google.com", "evilgoogle.com"))
        assertFalse(web("google.com", "google.co"))
        assertFalse(web("accounts.google.com", "google.com"))
        assertFalse(web("bbva.es", "bbva.es-login.com"))
        assertFalse(web("bbva.es", "xn--bbva-esa.es"))
    }

    @Test
    fun parentDomainOfTheSavedHostDoesNotMatch() {
        assertFalse(web("banca.ejemplo.es", "ejemplo.es"))
        assertFalse(web("banca.ejemplo.es", "otra.ejemplo.es"))
    }

    @Test
    fun singleLabelsAndJunkNeverMatch() {
        assertFalse(web("localhost", "localhost"))
        assertFalse(web("com", "google.com"))
        assertFalse(web("", "google.com"))
        assertFalse(web("not a url", "google.com"))
        assertNull(LoginMatcher.hostOf("androidapp://com.google.android.gm"))
    }

    @Test
    fun appsMatchOnlyByExactPackageName() {
        val urls = listOf("https://bbva.es", LoginMatcher.appUrl("com.bbva.bbvacontigo"))
        assertTrue(LoginMatcher.matches(urls, FillTarget.App("com.bbva.bbvacontigo")))
        assertFalse(LoginMatcher.matches(urls, FillTarget.App("com.bbva.bbvacontigo.fake")))
        assertFalse(LoginMatcher.matches(urls, FillTarget.App("com.bbva")))
        // A website URL never authorizes an app, whatever its package name looks like.
        assertFalse(LoginMatcher.matches(listOf("https://bbva.es"), FillTarget.App("es.bbva")))
        // And an app link never authorizes a website.
        assertFalse(LoginMatcher.matches(listOf(LoginMatcher.appUrl("google.com")), FillTarget.Web("google.com")))
    }

    @Test
    fun hostExtraction() {
        assertEquals("accounts.google.com", LoginMatcher.hostOf("https://accounts.google.com/signin?x=1"))
        assertEquals("google.com", LoginMatcher.hostOf("www.google.com"))
        assertEquals("ejemplo.es", LoginMatcher.hostOf("  http://ejemplo.es:8080/  "))
    }

    // --- Invariants (ADR-AUD-05): deterministic, no new dependencies. ---

    private fun app(saved: String, pkg: String) = LoginMatcher.matches(listOf(saved), FillTarget.App(pkg))

    @Test
    fun hostOfNeverThrowsAndMatchesNeverThrow() {
        val random = Random(20260630)
        val alphabet = "abcXYZ019.-_:/@?#%\\ \t\n[]é\u0430\u202e\u0000xn--"
        repeat(5_000) {
            val junk = String(CharArray(random.nextInt(0, 40)) { alphabet[random.nextInt(alphabet.length)] })
            LoginMatcher.hostOf(junk)
            LoginMatcher.matches(listOf(junk), FillTarget.Web(junk))
            LoginMatcher.matches(listOf(junk), FillTarget.App(junk))
        }
    }

    @Test
    fun anyHostMatchesItsSubdomainsAndNeverALookAlike() {
        val random = Random(7)
        fun label() = String(CharArray(random.nextInt(1, 9)) { "abcdefghijklmnopqrstuvwxyz0123456789"[random.nextInt(36)] })
        repeat(2_000) {
            val saved = "${label()}.test"
            val sub = "${label()}.$saved"
            assertTrue(saved, web("https://$saved/x", saved))
            assertTrue(sub, web("https://$saved/x", sub))
            // A different registrable domain never matches, however it is built around the saved one.
            assertFalse(web(saved, "${saved}x"))
            assertFalse(web(saved, "x$saved"))
            assertFalse(web(saved, "$saved.${label()}.net"))
            assertFalse(web(sub, saved))
        }
    }

    @Test
    fun portsAndPathsAreIgnoredOnTheSavedSide() {
        assertTrue(web("https://google.com:8443/login?next=a.b", "google.com"))
        assertTrue(web("google.com:8080", "accounts.google.com"))
        assertEquals("google.com", LoginMatcher.hostOf("http://google.com:80"))
        // A port in the visited domain is not a domain: it must not match by accident.
        assertFalse(web("google.com", "google.com:8080.evil.net"))
        assertFalse(web("evil.net", "google.com:8080"))
    }

    @Test
    fun userinfoNeverChangesTheHost() {
        assertEquals("evil.com", LoginMatcher.hostOf("https://google.com@evil.com/"))
        assertEquals("evil.com", LoginMatcher.hostOf("https://google.com:secret@evil.com/"))
        assertFalse(web("https://google.com@evil.com/", "google.com"))
        assertTrue(web("https://evil.com@google.com/", "google.com"))
        assertFalse(web("https://evil.com\\@google.com/", "evil.com"))
        assertFalse(web("https://google.com%40evil.com/", "evil.com"))
        assertTrue(web("user@google.com", "google.com"))
    }

    @Test
    fun caseTrailingDotsAndWhitespaceAreNormalized() {
        assertTrue(web("  GOOGLE.com.  ", "Mail.Google.COM."))
        assertTrue(web("https://WWW.Google.com", "google.com"))
        assertEquals("google.com", LoginMatcher.hostOf("https://google.com."))
        assertFalse(web("google.com", "google.com.evil"))
        assertFalse(web("https://www.", "www.com"))
    }

    @Test
    fun ipAddressesOnlyMatchThemselves() {
        assertTrue(web("http://192.168.1.1/admin", "192.168.1.1"))
        assertFalse(web("http://192.168.1.1", "192.168.1.10"))
        assertFalse(web("http://192.168.1.1", "168.1.1"))
        assertFalse(web("http://[::1]/", "::1"))
        assertFalse(web("http://[2001:db8::1]/", "2001:db8::1"))
        // Octets of an IP are not a domain.
        assertFalse(web("http://1.1", "192.168.1.1"))
    }

    @Test
    fun punycodeAndUnicodeNeverCrossRegistrableDomains() {
        assertTrue(web("https://xn--bcher-kva.de", "xn--bcher-kva.de"))
        assertTrue(web("https://xn--bcher-kva.de", "www.xn--bcher-kva.de"))
        assertFalse(web("https://xn--bcher-kva.de", "bucher.de"))
        assertFalse(web("https://bucher.de", "xn--bcher-kva.de"))
        // Homographs: Cyrillic "а" is not Latin "a".
        assertFalse(web("https://apple.com", "\u0430pple.com"))
        assertFalse(web("https://\u0430pple.com", "apple.com"))
        assertFalse(web("https://xn--pple-43d.com", "apple.com"))
        // Unicode on one side and punycode on the other is not matched: it fails closed.
        assertFalse(web("https://b\u00fccher.de", "xn--bcher-kva.de"))
        assertFalse(web("https://xn--bcher-kva.de", "b\u00fccher.de"))
    }

    @Test
    fun webTargetsAndAppTargetsNeverCross() {
        val urls = listOf("https://google.com", LoginMatcher.appUrl("com.google.android.gm"))
        assertTrue(LoginMatcher.matches(urls, FillTarget.Web("mail.google.com")))
        assertTrue(LoginMatcher.matches(urls, FillTarget.App("com.google.android.gm")))
        // The app's package name is not a domain, nor a domain a package name.
        assertFalse(LoginMatcher.matches(listOf(LoginMatcher.appUrl("com.google.android.gm")), FillTarget.Web("com.google.android.gm")))
        assertFalse(LoginMatcher.matches(listOf("https://google.com"), FillTarget.App("google.com")))
        assertFalse(LoginMatcher.matches(listOf("https://com.example.app"), FillTarget.App("com.example.app")))
        assertFalse(LoginMatcher.matches(listOf("https://com.example.app"), FillTarget.Web("com.example.app").let { FillTarget.App("com.example.app") }))
        assertFalse(LoginMatcher.matches(emptyList(), FillTarget.App("com.example.app")))
    }

    @Test
    fun packageNamesAreExactCaseSensitiveAndNotPrefixes() {
        val saved = LoginMatcher.appUrl("com.bank.app")
        assertTrue(app(saved, "com.bank.app"))
        assertTrue(app("  $saved  ", "com.bank.app"))
        assertFalse(app(saved, "com.bank.App"))
        assertFalse(app(saved, "com.bank.app2"))
        assertFalse(app(saved, "com.bank.app."))
        assertFalse(app(saved, "x.com.bank.app"))
        assertFalse(app(saved, ""))
        assertFalse(app(saved, "com.bank.app/evil"))
    }

    @Test
    fun appsPretendingToBeBrowsersGetNothingFromWebLogins() {
        // A malicious app can name itself like a browser or a site; its package is never a domain.
        val webLogin = listOf("https://bank.example", "https://chrome.google.com", "https://google.com")
        for (pkg in listOf("com.android.chrome", "org.mozilla.firefox", "bank.example", "google.com", "com.evil.fakechrome")) {
            assertFalse(pkg, LoginMatcher.matches(webLogin, FillTarget.App(pkg)))
        }
        // And a browser's package never authorizes the sites it can open: only webDomain does.
        val chromeLogin = listOf(LoginMatcher.appUrl("com.android.chrome"))
        assertFalse(LoginMatcher.matches(chromeLogin, FillTarget.Web("bank.example")))
        assertFalse(LoginMatcher.matches(chromeLogin, FillTarget.Web("com.android.chrome")))
    }

    @Test
    fun appLinksAreNotHostsWhateverTheirCase() {
        assertNull(LoginMatcher.hostOf("androidapp://com.example.app"))
        assertNull(LoginMatcher.hostOf("  androidapp://com.example.app/path "))
    }

    @Test
    fun appLinksInAnyCaseAreNotHosts() {
        assertNull(LoginMatcher.hostOf("ANDROIDAPP://com.example.app"))
        assertFalse(web("ANDROIDAPP://com.example.app", "com.example.app"))
    }

    @Test
    fun ipAddressesAreNeverMatchedBySuffix() {
        assertFalse(web("http://192.168.1.1", "10.192.168.1.1"))
    }

    @Test
    fun emptyPackageNameNeverMatches() {
        assertFalse(app("androidapp://", ""))
    }

    @Test
    fun savedUrlsAreIndependent() {
        val urls = listOf("not a url", "", "androidapp://x.y", "https://google.com")
        assertTrue(LoginMatcher.matches(urls, FillTarget.Web("google.com")))
        assertFalse(LoginMatcher.matches(urls.dropLast(1), FillTarget.Web("google.com")))
    }

    @Test
    fun publicSuffixesDoNotMatchTheirSubdomains() {
        assertFalse(web("https://co.uk", "evil.co.uk"))
        assertFalse(web("https://github.io", "evil.github.io"))
        assertFalse(web("https://blogspot.com", "evil.blogspot.com"))
        // A suffix still matches itself exactly.
        assertTrue(web("https://github.io", "github.io"))
    }

    @Test
    fun registrableDomainsUnderASuffixStillWork() {
        assertFalse(web("https://bbc.co.uk", "evil.co.uk"))
        assertTrue(web("https://bbc.co.uk", "news.bbc.co.uk"))
        assertTrue(web("https://alice.github.io", "alice.github.io"))
        assertTrue(web("https://alice.github.io", "www.alice.github.io"))
        assertTrue(web("https://alice.github.io", "x.alice.github.io"))
        assertFalse(web("https://alice.github.io", "bob.github.io"))
        assertTrue(web("https://blog.blogspot.com", "a.blog.blogspot.com"))
        assertFalse(web("https://blog.blogspot.com", "evil.blogspot.com"))
    }

    @Test
    fun wildcardRulesTreatTheWholeNameAsSuffix() {
        // "*.ck": any "x.ck" is a public suffix.
        assertFalse(web("https://foo.ck", "evil.foo.ck"))
        assertTrue(web("https://bar.foo.ck", "x.bar.foo.ck"))
        assertFalse(web("https://bar.foo.ck", "evil.foo.ck"))
        assertTrue(PublicSuffix.isPublicSuffix("foo.ck"))
        assertEquals("bar.foo.ck", PublicSuffix.registrableDomain("x.bar.foo.ck"))
    }

    @Test
    fun exceptionRulesMakeTheNameRegistrable() {
        // "!www.ck": www.ck is a normal domain even though "*.ck" is a suffix.
        assertFalse(PublicSuffix.isPublicSuffix("www.ck"))
        assertEquals("www.ck", PublicSuffix.registrableDomain("a.www.ck"))
    }

    @Test
    fun idnSuffixesAreRecognizedInUnicodeAndPunycode() {
        assertTrue(PublicSuffix.isPublicSuffix("\u516c\u53f8.cn"))
        assertTrue(PublicSuffix.isPublicSuffix("xn--55qx5d.cn"))
        assertEquals("example.\u516c\u53f8.cn", PublicSuffix.registrableDomain("a.example.\u516c\u53f8.cn"))
        assertFalse(web("https://\u516c\u53f8.cn", "evil.\u516c\u53f8.cn"))
        assertFalse(web("https://xn--55qx5d.cn", "evil.xn--55qx5d.cn"))
        assertTrue(web("https://example.xn--55qx5d.cn", "a.example.xn--55qx5d.cn"))
    }

    @Test
    fun publicSuffixApi() {
        assertEquals("example.com", PublicSuffix.registrableDomain("a.b.example.com"))
        assertEquals("example.co.uk", PublicSuffix.registrableDomain("www.example.co.uk"))
        assertNull(PublicSuffix.registrableDomain("co.uk"))
        assertNull(PublicSuffix.registrableDomain("com"))
        assertEquals("alice.github.io", PublicSuffix.registrableDomain("alice.github.io"))
        assertFalse(PublicSuffix.isPublicSuffix("example.com"))
        // Unknown TLD: the implicit "*" rule makes the last label the suffix.
        assertEquals("example.zzzz", PublicSuffix.registrableDomain("a.example.zzzz"))
    }

    @Test
    fun ipv6LiteralsOnlyMatchThemselves() {
        assertFalse(web("http://[2001:db8::1]/", "[2001:db8::1]"))
        assertFalse(web("http://[2001:db8::1]/", "a.[2001:db8::1]"))
    }

    @Test
    fun appSchemeIsCaseInsensitiveAndBlankPackagesNeverMatch() {
        assertTrue(app("ANDROIDAPP://com.example.app", "com.example.app"))
        assertFalse(app("androidapp://", " "))
        assertFalse(app("androidapp://  ", "  "))
    }
}
