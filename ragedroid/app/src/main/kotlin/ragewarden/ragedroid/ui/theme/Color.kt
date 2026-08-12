package ragewarden.ragedroid.ui.theme

import androidx.compose.material3.ColorScheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color

private val Cream = Color(0xFFF2EDE4)
private val Charcoal = Color(0xFF2B2B2B)
private val Black = Color(0xFF1A1A1A)
private val WarmGray = Color(0xFF645C55)
private val LightGray = Color(0xFFD4CFC9)

private val DarkBase = Color(0xFF1E1E1E)
private val DarkSurface = Color(0xFF2D2D2D)
private val DarkSurfaceElevated = Color(0xFF353535)
private val DarkSurfaceSunken = Color(0xFF262626)
private val WarmGrayDark = Color(0xFF9B9590)
private val DarkBorder = Color(0xFF3D3D3D)
private val DarkDivider = Color(0xFF353535)

private val SurfaceElevatedLight = Color(0xFFFAF6EE)
private val SurfaceSunkenLight = Color(0xFFECE6DB)
private val TileLight = Color(0xFFEAE3D6)
private val DividerLight = Color(0xFFE2DBD0)

private val BronzeLight = Color(0xFF6E5A3C)
private val BronzeDark = Color(0xFFA8906A)
private val SageLight = Color(0xFF5A6E5A)
private val SageDark = Color(0xFF7F9B7F)
private val SlateBlueLight = Color(0xFF5A6B7A)
private val SlateBlueDark = Color(0xFF7A92A8)
private val ScarletLight = Color(0xFF7A4848)
private val ScarletDark = Color(0xFFB88080)
private val DangerStrongLight = Color(0xFFA8201A)
private val DangerStrongDark = Color(0xFFC47272)
private val AmberLight = Color(0xFF8B6B2A)
private val AmberDark = Color(0xFFC4A45A)

@Immutable
data class RageColors(
    val background: Color,
    val surface: Color,
    val surfaceElevated: Color,
    val surfaceSunken: Color,
    val tile: Color,
    val fgPrimary: Color,
    val fgEmphasis: Color,
    val fgSecondary: Color,
    val border: Color,
    val divider: Color,
    val accent: Color,
    val accentHover: Color,
    val accentPress: Color,
    val success: Color,
    val info: Color,
    val danger: Color,
    val dangerStrong: Color,
    val warning: Color,
    val focus: Color,
    val backdrop: Color,
)

internal val LightRageColors = RageColors(
    background = Cream,
    surface = Cream,
    surfaceElevated = SurfaceElevatedLight,
    surfaceSunken = SurfaceSunkenLight,
    tile = TileLight,
    fgPrimary = Charcoal,
    fgEmphasis = Black,
    fgSecondary = WarmGray,
    border = LightGray,
    divider = DividerLight,
    accent = BronzeLight,
    accentHover = Color(0xFF5A4A32),
    accentPress = Color(0xFF4A3B27),
    success = SageLight,
    info = SlateBlueLight,
    danger = ScarletLight,
    dangerStrong = DangerStrongLight,
    warning = AmberLight,
    focus = BronzeLight,
    backdrop = Color(0x66140C08),
)

internal val DarkRageColors = RageColors(
    background = DarkBase,
    surface = DarkSurface,
    surfaceElevated = DarkSurfaceElevated,
    surfaceSunken = DarkSurfaceSunken,
    tile = DarkSurfaceElevated,
    fgPrimary = Cream,
    fgEmphasis = Cream,
    fgSecondary = WarmGrayDark,
    border = DarkBorder,
    divider = DarkDivider,
    accent = BronzeDark,
    accentHover = Color(0xFFB8A07C),
    accentPress = Color(0xFFC8B08E),
    success = SageDark,
    info = SlateBlueDark,
    danger = ScarletDark,
    dangerStrong = DangerStrongDark,
    warning = AmberDark,
    focus = BronzeDark,
    backdrop = Color(0x8C000000),
)

internal val LightColorScheme: ColorScheme = lightColorScheme(
    primary = LightRageColors.accent,
    onPrimary = LightRageColors.background,
    secondary = LightRageColors.fgEmphasis,
    onSecondary = LightRageColors.background,
    background = LightRageColors.background,
    onBackground = LightRageColors.fgPrimary,
    surface = LightRageColors.surface,
    onSurface = LightRageColors.fgPrimary,
    surfaceVariant = LightRageColors.surfaceSunken,
    onSurfaceVariant = LightRageColors.fgSecondary,
    error = LightRageColors.dangerStrong,
    onError = LightRageColors.background,
    outline = LightRageColors.border,
)

internal val DarkColorScheme: ColorScheme = darkColorScheme(
    primary = DarkRageColors.accent,
    onPrimary = DarkRageColors.background,
    secondary = DarkRageColors.fgEmphasis,
    onSecondary = DarkRageColors.background,
    background = DarkRageColors.background,
    onBackground = DarkRageColors.fgPrimary,
    surface = DarkRageColors.surface,
    onSurface = DarkRageColors.fgPrimary,
    surfaceVariant = DarkRageColors.surfaceSunken,
    onSurfaceVariant = DarkRageColors.fgSecondary,
    error = DarkRageColors.dangerStrong,
    onError = DarkRageColors.background,
    outline = DarkRageColors.border,
)

val LocalRageColors = staticCompositionLocalOf { LightRageColors }

val rageColors: RageColors
    @Composable
    get() = LocalRageColors.current
