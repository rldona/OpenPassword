package io.github.rldona.openpassword

import io.github.rldona.openpassword.ui.onboarding.strengthOf
import org.junit.Assert.assertEquals
import org.junit.Test

class StrengthTest {
    @Test
    fun labelsFollowEstimatedBits() {
        assertEquals("Débil", strengthOf("abc").label)
        assertEquals("Débil", strengthOf("contraseña").label)
        assertEquals("Aceptable", strengthOf("Contrasena2026").label)
        assertEquals("Fuerte", strengthOf("caballo-bateria-grapa-correcta").label)
    }

    @Test
    fun fractionStaysWithinBounds() {
        for (p in listOf("", "a", "x".repeat(200))) {
            val f = strengthOf(p).fraction
            assert(f in 0f..1f) { "$p -> $f" }
        }
    }
}
