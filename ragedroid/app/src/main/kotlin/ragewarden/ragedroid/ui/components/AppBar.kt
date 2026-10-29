package ragewarden.ragedroid.ui.components

import ragewarden.ragedroid.R
import androidx.compose.ui.res.stringResource
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.outlined.MoreVert
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import ragewarden.ragedroid.ui.theme.RageTheme
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors

@Composable
fun BackButton(onBack: () -> Unit) {
    IconBtn(icon = Icons.AutoMirrored.Outlined.ArrowBack, contentDescription = stringResource(R.string.back), onClick = onBack)
}

@Composable
fun AppBar(
    title: String,
    subtitle: String? = null,
    leading: (@Composable () -> Unit)? = null,
    trailing: (@Composable () -> Unit)? = null,
    large: Boolean = false,
) {
    val c = rageColors
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = if (large) 64.dp else 48.dp)
            .padding(
                horizontal = if (large) 18.dp else 12.dp,
                vertical = if (large) 14.dp else 10.dp,
            ),
        verticalAlignment = if (large) Alignment.Bottom else Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.weight(1f),
        ) {
            if (leading != null) {
                leading()
                Spacer(modifier = Modifier.width(4.dp))
            }
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = title,
                    style = if (large) RageType.h1 else RageType.rowTitle,
                    color = c.fgEmphasis,
                    maxLines = 1,
                )
                if (subtitle != null) {
                    Text(
                        text = subtitle,
                        style = RageType.meta,
                        color = c.fgSecondary,
                    )
                }
            }
        }
        if (trailing != null) {
            Row(
                horizontalArrangement = Arrangement.spacedBy(4.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                trailing()
            }
        } else {
            Box {}
        }
    }
}

