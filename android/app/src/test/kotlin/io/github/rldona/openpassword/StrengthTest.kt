package io.github.rldona.openpassword

import io.github.rldona.openpassword.ui.onboarding.strengthOf
import org.junit.Assert.assertEquals
import org.junit.Test

class StrengthTest {
    @Test
    fun levelsFollowEstimatedBits() {
        assertEquals(0, strengthOf("abc").level)
        assertEquals(0, strengthOf("contraseña").level)
        assertEquals(1, strengthOf("Contrasena2026").level)
        assertEquals(2, strengthOf("caballo-bateria-grapa-correcta").level)
    }

    @Test
    fun fractionStaysWithinBounds() {
        for (p in listOf("", "a", "x".repeat(200))) {
            val f = strengthOf(p).fraction
            assert(f in 0f..1f) { "$p -> $f" }
        }
    }
}
