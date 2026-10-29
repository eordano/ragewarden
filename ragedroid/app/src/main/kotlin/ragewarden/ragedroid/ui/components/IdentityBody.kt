package ragewarden.ragedroid.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.collections.immutable.ImmutableList
import kotlinx.collections.immutable.persistentListOf
import ragewarden.ragedroid.R
import ragewarden.ragedroid.data.Clipboard
import ragewarden.ragedroid.model.VaultItem
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors

private data class IdentityField(
    val label: String,
    val value: String?,
    val multiline: Boolean,
    val sensitive: Boolean,
)

@Composable
fun IdentityBody(
    item: VaultItem,
    clipboard: Clipboard,
    showToast: (String) -> Unit,
) {
    val strings = androidx.compose.ui.platform.LocalContext.current
    val rows: ImmutableList<IdentityField> = persistentListOf(
        IdentityField(stringResource(R.string.full_name), item.fullName, multiline = false, sensitive = false),
        IdentityField(stringResource(R.string.date_of_birth), item.dob, multiline = false, sensitive = false),
        IdentityField(stringResource(R.string.address), item.address, multiline = true, sensitive = false),
        IdentityField(stringResource(R.string.phone), item.phone, multiline = false, sensitive = false),
        IdentityField(stringResource(R.string.email), item.email, multiline = false, sensitive = false),
        IdentityField(stringResource(R.string.national_id), item.nationalId, multiline = false, sensitive = true),
    )

    Column(modifier = Modifier.fillMaxWidth()) {
        rows.forEach { row ->
            IdentityRow(
                row = row,
                onCopy = {
                    val value = row.value ?: return@IdentityRow
                    val bytes = value.toByteArray(Charsets.UTF_8)
                    if (row.sensitive) {
                        clipboard.copySensitive(bytes, row.label.lowercase(), item = item.name)
                    } else {
                        clipboard.copyVisible(value, row.label.lowercase())
                    }
                    bytes.fill(0)
                    showToast(strings.getString(R.string.copied, row.label))
                },
            )
        }
        if (item.notes != null) {
            NotesField(text = item.notes)
        }
    }
}

@Composable
private fun IdentityRow(
    row: IdentityField,
    onCopy: () -> Unit,
) {
    val c = rageColors
    val isEmpty = row.value == null
    Field(label = row.label) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(c.surfaceSunken, RoundedCornerShape(8.dp))
                .border(1.dp, c.border, RoundedCornerShape(8.dp))
                .padding(horizontal = 12.dp, vertical = 10.dp),
            verticalAlignment = if (row.multiline) Alignment.Top else Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                text = row.value ?: stringResource(R.string.not_set),
                style = RageType.body.copy(
                    fontSize = 14.sp,
                    fontStyle = if (isEmpty) FontStyle.Italic else FontStyle.Normal,
                ),
                color = if (isEmpty) c.fgSecondary else c.fgPrimary,
                modifier = Modifier.weight(1f),
            )
            if (!isEmpty) {
                CopyButton(onCopy = onCopy, compact = true)
            }
        }
    }
}

