package io.github.rldona.openpassword

import io.github.rldona.openpassword.autofill.FillTarget
import io.github.rldona.openpassword.autofill.LoginMatcher
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class LoginMatcherTest {
    private fun web(saved: String, visited: String) = LoginMatcher.matches(listOf(saved), FillTarget.Web(visited))

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
}
