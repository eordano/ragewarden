package ragewarden.ragedroid.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import ragewarden.ragedroid.R
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors

/**
 * Shown when RecipientStore could not decrypt this account's key list. Without
 * it the list read as empty: the phone looked like it had no keys, and the next
 * enrolment failed on the refusal to overwrite the unreadable copy.
 */
@Composable
fun UnreadableKeyListCard(onReset: () -> Unit, modifier: Modifier = Modifier) {
    val c = rageColors
    Column(
        modifier = modifier
            .fillMaxWidth()
            .testTag("key-list-unreadable")
            .background(c.danger.copy(alpha = 0.10f), RoundedCornerShape(10.dp))
            .border(1.dp, c.danger, RoundedCornerShape(10.dp))
            .padding(horizontal = 16.dp, vertical = 14.dp),
    ) {
        Text(text = stringResource(R.string.key_list_unreadable_title), style = RageType.rowTitle, color = c.fgEmphasis)
        Spacer(modifier = Modifier.height(6.dp))
        Text(text = stringResource(R.string.key_list_unreadable_body), style = RageType.caption, color = c.fgSecondary)
        Spacer(modifier = Modifier.height(10.dp))
        RageButton(
            label = stringResource(R.string.reset_key_list),
            onClick = onReset,
            variant = ButtonVariant.Danger,
            fullWidth = true,
        )
    }
}
