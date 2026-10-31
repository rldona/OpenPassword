package io.github.rldona.openpassword.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

// Palette from docs/proposal.html: steel neutrals with a vault green accent.
private val Light = lightColorScheme(
    primary = Color(0xFF0E6B5C),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFDCEFEA),
    onPrimaryContainer = Color(0xFF0B4A40),
    secondary = Color(0xFF5A6763),
    secondaryContainer = Color(0xFFE3E9E7),
    onSecondaryContainer = Color(0xFF15201D),
    tertiary = Color(0xFFA15C00),
    tertiaryContainer = Color(0xFFFBEBD3),
    background = Color(0xFFF7F9F8),
    onBackground = Color(0xFF15201D),
    surface = Color(0xFFF7F9F8),
    onSurface = Color(0xFF15201D),
    surfaceVariant = Color(0xFFE3E9E7),
    onSurfaceVariant = Color(0xFF5A6763),
    surfaceContainerLowest = Color(0xFFFFFFFF),
    surfaceContainerLow = Color(0xFFFFFFFF),
    surfaceContainer = Color(0xFFF0F3F2),
    surfaceContainerHigh = Color(0xFFEAEFED),
    outline = Color(0xFFB8C3BF),
    outlineVariant = Color(0xFFD5DCD9),
    error = Color(0xFFB3261E),
    errorContainer = Color(0xFFF9DEDC),
)

private val Dark = darkColorScheme(
    primary = Color(0xFF4FC2A9),
    onPrimary = Color(0xFF00382F),
    primaryContainer = Color(0xFF143B33),
    onPrimaryContainer = Color(0xFFB6EBDD),
    secondary = Color(0xFF98A6A1),
    secondaryContainer = Color(0xFF26312E),
    onSecondaryContainer = Color(0xFFE4ECE9),
    tertiary = Color(0xFFE6A64B),
    tertiaryContainer = Color(0xFF3A2A12),
    background = Color(0xFF101716),
    onBackground = Color(0xFFE4ECE9),
    surface = Color(0xFF101716),
    onSurface = Color(0xFFE4ECE9),
    surfaceVariant = Color(0xFF26312E),
    onSurfaceVariant = Color(0xFF98A6A1),
    surfaceContainerLowest = Color(0xFF0B1110),
    surfaceContainerLow = Color(0xFF18211F),
    surfaceContainer = Color(0xFF1C2523),
    surfaceContainerHigh = Color(0xFF222C2A),
    outline = Color(0xFF4A5753),
    outlineVariant = Color(0xFF2A3532),
    error = Color(0xFFF2867E),
    errorContainer = Color(0xFF3D1A18),
)

val SecretFont: FontFamily = FontFamily.Monospace

private fun typography(): Typography {
    val base = Typography()
    return base.copy(
        headlineMedium = base.headlineMedium.copy(fontWeight = FontWeight.Bold, letterSpacing = (-0.3).sp),
        titleLarge = base.titleLarge.copy(fontWeight = FontWeight.Bold),
        labelSmall = base.labelSmall.copy(letterSpacing = 0.8.sp),
    )
}

val SecretText = TextStyle(fontFamily = SecretFont, fontSize = 16.sp, letterSpacing = 0.5.sp)

@Composable
fun OpenPasswordTheme(content: @Composable () -> Unit) {
    val colors: ColorScheme = if (isSystemInDarkTheme()) Dark else Light
    MaterialTheme(colorScheme = colors, typography = typography(), content = content)
}
