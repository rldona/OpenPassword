package io.github.rldona.openpassword.ui.onboarding

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import kotlin.math.log2

/** Rough guidance only: length dominates, character variety helps a little. */
data class Strength(val fraction: Float, val label: String, private val level: Int) {
    @Composable
    fun color(): Color = when (level) {
        0 -> MaterialTheme.colorScheme.error
        1 -> MaterialTheme.colorScheme.tertiary
        else -> MaterialTheme.colorScheme.primary
    }
}

fun strengthOf(password: String): Strength {
    val pool = listOf(
        password.any(Char::isLowerCase) to 26,
        password.any(Char::isUpperCase) to 26,
        password.any(Char::isDigit) to 10,
        password.any { !it.isLetterOrDigit() } to 20,
    ).filter { it.first }.sumOf { it.second }.coerceAtLeast(1)
    val bits = password.length * log2(pool.toDouble())
    return when {
        bits < 45 -> Strength((bits / 100).toFloat(), "Débil", 0)
        bits < 70 -> Strength((bits / 100).toFloat(), "Aceptable", 1)
        else -> Strength((bits / 100).toFloat().coerceAtMost(1f), "Fuerte", 2)
    }
}
