package com.example.ui.theme

import android.app.Activity
import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat

private val DarkColorScheme = darkColorScheme(
    primary = ForgeCyanDark,
    onPrimary = ForgeOnCyanDark,
    primaryContainer = ForgeCyanContainerDark,
    onPrimaryContainer = Color(0xFFB8F4FF),
    secondary = ForgeEmeraldDark,
    onSecondary = Color(0xFF002116),
    secondaryContainer = ForgeEmeraldContainerDark,
    onSecondaryContainer = Color(0xFFA7F3D0),
    tertiary = ForgeAmberDark,
    onTertiary = Color(0xFF281800),
    tertiaryContainer = ForgeAmberContainerDark,
    onTertiaryContainer = Color(0xFFFDE68A),
    error = ForgeErrorDark,
    background = ForgeBackgroundDark,
    onBackground = Color(0xFFE2E8F0),
    surface = ForgeSurfaceDark,
    onSurface = Color(0xFFF1F5F9),
    surfaceVariant = ForgeSurfaceVariantDark,
    onSurfaceVariant = Color(0xFF94A3B8)
)

private val LightColorScheme = lightColorScheme(
    primary = ForgeCyanLight,
    onPrimary = ForgeOnCyanLight,
    primaryContainer = ForgeCyanContainerLight,
    onPrimaryContainer = Color(0xFF001F24),
    secondary = ForgeEmeraldLight,
    onSecondary = Color.White,
    secondaryContainer = ForgeEmeraldContainerLight,
    onSecondaryContainer = Color(0xFF064E3B),
    tertiary = ForgeAmberLight,
    onTertiary = Color.White,
    tertiaryContainer = ForgeAmberContainerLight,
    onTertiaryContainer = Color(0xFF451A03),
    error = ForgeErrorLight,
    background = ForgeBackgroundLight,
    onBackground = Color(0xFF0F172A),
    surface = ForgeSurfaceLight,
    onSurface = Color(0xFF0F172A),
    surfaceVariant = ForgeSurfaceVariantLight,
    onSurfaceVariant = Color(0xFF475569)
)

@Composable
fun MyApplicationTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    dynamicColor: Boolean = false,
    content: @Composable () -> Unit
) {
    val colorScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val context = LocalContext.current
            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        }
        darkTheme -> DarkColorScheme
        else -> LightColorScheme
    }

    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as? Activity)?.window
            if (window != null) {
                @Suppress("DEPRECATION")
                window.statusBarColor = colorScheme.surface.toArgb()
                @Suppress("DEPRECATION")
                window.navigationBarColor = colorScheme.surface.toArgb()
                val insetsController = WindowCompat.getInsetsController(window, view)
                insetsController.isAppearanceLightStatusBars = !darkTheme
                insetsController.isAppearanceLightNavigationBars = !darkTheme
            }
        }
    }

    MaterialTheme(
        colorScheme = colorScheme,
        typography = Typography,
        content = content
    )
}
