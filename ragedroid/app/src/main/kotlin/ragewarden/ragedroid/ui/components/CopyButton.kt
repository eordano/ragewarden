package ragewarden.ragedroid.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Check
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay
import ragewarden.ragedroid.ui.theme.RageTheme
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors

@Composable
fun CopyButton(
    onCopy: () -> Unit,
    modifier: Modifier = Modifier,
    label: String = "Copy",
    // compact now only trims padding; it can no longer shrink the button below
    // the 48dp touch floor enforced below. Kept because CardBody / NoteBody /
    // SshBody / IdentityBody / ItemDetailScreen still ask for it.
    compact: Boolean = false,
    countdownSeconds: Int = 30,
) {
    val c = rageColors
    var copied by remember { mutableStateOf(false) }
    var secs by remember { mutableStateOf(countdownSeconds) }

    LaunchedEffect(copied) {
        if (copied) {
            secs = countdownSeconds
            while (secs > 0) {
                delay(1000)
                secs -= 1
            }
            copied = false
        }
    }

    val bg = if (copied) c.success else c.tile
    val fg = if (copied) Color(0xFFFAF6EE) else c.fgPrimary
    val padding = if (compact) {
        PaddingValues(horizontal = 8.dp, vertical = 4.dp)
    } else {
        PaddingValues(horizontal = 10.dp, vertical = 6.dp)
    }
    Row(
        modifier = modifier
            // Android's minimum touch target is 48x48dp and Compose hands you
            // nothing of the sort on a bare clickable() -- the compact variant
            // was a ~21dp-tall tap target. Enforced in the primitive so every
            // call site inherits it instead of each body remembering to ask.
            .defaultMinSize(minWidth = 48.dp, minHeight = 48.dp)
            .background(bg, RoundedCornerShape(6.dp))
            .clickable {
                onCopy()
                copied = true
            }
            .padding(padding),
        verticalAlignment = Alignment.CenterVertically,
        // Centred so the label does not hug the left edge once the row is
        // stretched to the 48dp floor.
        horizontalArrangement = Arrangement.spacedBy(6.dp, Alignment.CenterHorizontally),
    ) {
        Icon(
            imageVector = if (copied) Icons.Outlined.Check else Icons.Outlined.ContentCopy,
            contentDescription = null,
            tint = fg,
            modifier = Modifier.size(13.dp),
        )
        Text(
            text = if (copied) "Cleared in ${secs}s" else label,
            style = RageType.button,
            color = fg,
        )
    }
}

@Preview(showBackground = true, name = "CopyButton - idle / compact")
@Composable
private fun PreviewCopyButton() {
    RageTheme {
        Row(
            modifier = Modifier
                .background(rageColors.background)
                .padding(16.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            CopyButton(onCopy = {})
            CopyButton(onCopy = {}, compact = true)
            CopyButton(onCopy = {}, label = "Copy URL", compact = true)
        }
    }
}
