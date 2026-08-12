package ragewarden.ragedroid.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.Schedule
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import ragewarden.ragedroid.ui.components.AppBar
import ragewarden.ragedroid.ui.components.IconBtn
import ragewarden.ragedroid.ui.components.RageButton
import ragewarden.ragedroid.ui.theme.RageTheme
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors

@Composable
fun TokenExpiredScreen(
    onSignIn: () -> Unit,
    onLater: () -> Unit,
) {
    val c = rageColors
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(c.background)
            .padding(horizontal = 18.dp),
    ) {
        AppBar(
            title = "",
            leading = {
                IconBtn(
                    icon = Icons.Outlined.Close,
                    contentDescription = "Close",
                    onClick = onLater,
                )
            },
        )
        Column(
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .padding(vertical = 24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            Box(
                modifier = Modifier
                    .size(72.dp)
                    .background(c.warning, CircleShape),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = Icons.Outlined.Schedule,
                    contentDescription = null,
                    tint = Color(0xFF1A140A),
                    modifier = Modifier.size(32.dp),
                )
            }
            Spacer(modifier = Modifier.height(20.dp))
            Text(
                text = "Session expired.",
                style = RageType.h1.copy(fontSize = 26.sp, lineHeight = 30.sp),
                color = c.fgEmphasis,
                textAlign = TextAlign.Center,
            )
            Spacer(modifier = Modifier.height(12.dp))
            Text(
                text = "Your sign-in token timed out. The vault is still encrypted on this " +
                    "device -- you can keep reading cached items, but new syncs need a fresh token.",
                style = RageType.body.copy(fontSize = 15.sp, lineHeight = 23.sp),
                color = c.fgSecondary,
                textAlign = TextAlign.Center,
            )
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = "No data left the device. No master password is required again.",
                style = RageType.body.copy(fontSize = 13.5.sp, lineHeight = 20.sp, fontStyle = FontStyle.Italic),
                color = c.fgSecondary,
                textAlign = TextAlign.Center,
            )
        }
        RageButton(
            label = "Re-authenticate",
            onClick = onSignIn,
            icon = Icons.Outlined.Key,
            fullWidth = true,
        )
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .clickable(onClick = onLater)
                .padding(vertical = 14.dp),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                text = "Keep working offline",
                style = RageType.sansBody.copy(fontSize = 13.sp),
                color = c.fgSecondary,
            )
        }
    }
}

@Preview(showBackground = true, name = "TokenExpiredScreen")
@Composable
private fun PreviewTokenExpired() {
    RageTheme {
        Box(modifier = Modifier.background(rageColors.background).fillMaxSize()) {
            TokenExpiredScreen(onSignIn = {}, onLater = {})
        }
    }
}
