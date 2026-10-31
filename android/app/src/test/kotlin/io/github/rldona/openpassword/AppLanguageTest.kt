package io.github.rldona.openpassword

import io.github.rldona.openpassword.locale.AppLanguage
import org.junit.Assert.assertEquals
import org.junit.Test

class AppLanguageTest {
    @Test
    fun `system is the default and unknown tags fall back to it`() {
        assertEquals(AppLanguage.SYSTEM, AppLanguage.fromTag(null))
        assertEquals(AppLanguage.SYSTEM, AppLanguage.fromTag(""))
        assertEquals(AppLanguage.SYSTEM, AppLanguage.fromTag("fr"))
        assertEquals(AppLanguage.SYSTEM, AppLanguage.fromTag("es-ES-exploded"))
    }

    @Test
    fun `known tags map to their language`() {
        assertEquals(AppLanguage.ENGLISH, AppLanguage.fromTag("en"))
        assertEquals(AppLanguage.SPANISH, AppLanguage.fromTag("es"))
    }

    @Test
    fun `system has no tag and the others use the platform form`() {
        assertEquals(null, AppLanguage.SYSTEM.tag)
        assertEquals("en", AppLanguage.ENGLISH.tag)
        assertEquals("es", AppLanguage.SPANISH.tag)
    }
}
