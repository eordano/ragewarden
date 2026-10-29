package ragewarden.ragedroid.ui.components

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp

/**
 * A hand-built control that acts like [RageButton]: announced as a button and
 * never smaller than Android's 48 x 48 dp touch floor.
 */
fun Modifier.buttonTarget(enabled: Boolean = true, onClick: () -> Unit): Modifier =
    this
        .defaultMinSize(minWidth = 48.dp, minHeight = 48.dp)
        .clickable(enabled = enabled, role = Role.Button, onClick = onClick)
