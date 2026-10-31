package io.github.rldona.openpassword.ui.onboarding

import androidx.annotation.StringRes
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import io.github.rldona.openpassword.R
import kotlin.math.log2

/**
 * Rough guidance only, with no dictionary: a common word with an accent still looks
 * "random" by bits alone, so length gates each level. "Acceptable" needs 12 characters
 * and "Strong" 16, which favours passphrases.
 */
data class Strength(val fraction: Float, val level: Int) {
    @Composable
    fun color(): Color = when (level) {
        0 -> MaterialTheme.colorScheme.error
        1 -> MaterialTheme.colorScheme.tertiary
        else -> MaterialTheme.colorScheme.primary
    }
}

@get:StringRes
val Strength.labelRes: Int
    get() = when (level) {
        0 -> R.string.strength_weak
        1 -> R.string.strength_acceptable
        else -> R.string.strength_strong
    }

fun strengthOf(password: String): Strength {
    val pool = listOf(
        password.any(Char::isLowerCase) to 26,
        password.any(Char::isUpperCase) to 26,
        password.any(Char::isDigit) to 10,
        password.any { !it.isLetterOrDigit() } to 20,
    ).filter { it.first }.sumOf { it.second }.coerceAtLeast(1)
    val bits = password.length * log2(pool.toDouble())
    val fraction = (bits / 100).toFloat().coerceIn(0f, 1f)
    return when {
        password.length >= 16 && bits >= 75 -> Strength(fraction, 2)
        password.length >= 12 && bits >= 50 -> Strength(fraction.coerceAtMost(0.74f), 1)
        else -> Strength(fraction.coerceAtMost(0.44f), 0)
    }
}
