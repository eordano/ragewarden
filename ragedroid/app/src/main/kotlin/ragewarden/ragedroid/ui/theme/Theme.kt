package ragewarden.ragedroid.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider

@Composable
fun RageTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    val rage = if (darkTheme) DarkRageColors else LightRageColors
    val material = if (darkTheme) DarkColorScheme else LightColorScheme

    CompositionLocalProvider(LocalRageColors provides rage) {
        MaterialTheme(
            colorScheme = material,
            typography = RageTypography,
            content = content,
        )
    }
}
