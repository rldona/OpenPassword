package io.github.rldona.openpassword

import io.github.rldona.openpassword.autofill.AutofillRequestTokens
import io.github.rldona.openpassword.autofill.FillTarget
import io.github.rldona.openpassword.autofill.LoginRequest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class AutofillRequestTokensTest {
    private var now = 0L
    private val store = AutofillRequestTokens(now = { now }, ttlMs = 1_000)
    private val request = LoginRequest(FillTarget.Web("evil.example"), null, null)

    @Test fun theTokenResolvesToTheRequestedTarget() {
        val token = store.put(request)
        assertEquals(FillTarget.Web("evil.example"), store.take(token)?.target)
    }

    /** The activity only ever calls take(token): a domain/package added to the Intent is not an input. */
    @Test fun nothingButTheTokenDecidesTheTarget() {
        val token = store.put(request)
        val other = store.put(LoginRequest(FillTarget.App("com.victim"), null, null))
        assertNotEquals(token, other)
        assertEquals(FillTarget.Web("evil.example"), store.take(token)?.target)
        // Guessing a target as a token never works.
        assertNull(store.take("accounts.google.com"))
        assertNull(store.take("op.autofill.domain"))
    }

    @Test fun unknownOrMissingTokensResolveToNothing() {
        assertNull(store.take(null))
        assertNull(store.take(""))
        assertNull(store.take("00".repeat(16)))
    }

    @Test fun aTokenIsSingleUse() {
        val token = store.put(request)
        assertNotNull(store.take(token))
        assertNull(store.take(token))
    }

    @Test fun aTokenExpires() {
        val token = store.put(request)
        now = 1_000
        assertNull(store.take(token))
        assertNull(store.take(token))
    }

    @Test fun aDiscardedTokenIsGone() {
        val token = store.put(request)
        store.discard(token)
        assertNull(store.take(token))
    }

    @Test fun tokensAreRandomHex() {
        val tokens = List(50) { store.put(request) }.toSet()
        assertEquals(50, tokens.size)
        assertEquals(true, tokens.all { it.length == 32 && it.all { c -> c in "0123456789abcdef" } })
    }
}
