package app.kukuvpn.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext

private val Accent = Color(0xFF2DD4A7)
private val AccentDark = Color(0xFF1FB68D)
private val BgDark = Color(0xFF0E1116)
private val SurfaceDark = Color(0xFF161B22)
private val BgLight = Color(0xFFF7F9F8)
private val SurfaceLight = Color(0xFFFFFFFF)
private val Danger = Color(0xFFEF5350)

private val DarkScheme = darkColorScheme(
    primary = Accent,
    onPrimary = Color(0xFF04241C),
    secondary = AccentDark,
    background = BgDark,
    surface = SurfaceDark,
    surfaceVariant = Color(0xFF1D242C),
    error = Danger,
)

private val LightScheme = lightColorScheme(
    primary = AccentDark,
    onPrimary = Color.White,
    secondary = Accent,
    background = BgLight,
    surface = SurfaceLight,
    surfaceVariant = Color(0xFFE9EFEA),
    error = Danger,
)

@Composable
fun KukuTheme(themeSetting: Int = 0, content: @Composable () -> Unit) {
    val dark = when (themeSetting) {
        1 -> false
        2 -> true
        else -> isSystemInDarkTheme()
    }
    MaterialTheme(
        colorScheme = if (dark) DarkScheme else LightScheme,
        content = content,
    )
}
