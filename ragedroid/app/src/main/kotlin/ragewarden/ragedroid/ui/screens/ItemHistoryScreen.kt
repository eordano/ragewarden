package ragewarden.ragedroid.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.collections.immutable.ImmutableList
import kotlinx.collections.immutable.persistentListOf
import ragewarden.ragedroid.R
import ragewarden.ragedroid.model.VaultItem
import ragewarden.ragedroid.ui.components.AppBar
import ragewarden.ragedroid.ui.components.BackButton
import ragewarden.ragedroid.ui.components.ButtonSize
import ragewarden.ragedroid.ui.components.ButtonVariant
import ragewarden.ragedroid.ui.components.Mono
import ragewarden.ragedroid.ui.components.RageButton
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors

@Immutable
data class HistoryChange(val field: String, val diff: String? = null)

@Immutable
data class HistoryRevision(
    val id: String,
    val when_: String,
    val by: String,
    val current: Boolean,
    val changes: ImmutableList<HistoryChange>,
)

@Composable
fun ItemHistoryScreen(
    item: VaultItem?,
    onBack: () -> Unit,
    entries: ImmutableList<HistoryRevision> = persistentListOf(),
    onRestore: (HistoryRevision) -> Unit = {},
    onViewDiff: (HistoryRevision) -> Unit = {},
) {
    val c = rageColors
    var selected by remember { mutableStateOf<String?>(null) }

    Column(modifier = Modifier.fillMaxSize().background(c.background)) {
        AppBar(
            title = stringResource(R.string.history_2),
            subtitle = item?.name,
            leading = { BackButton(onBack) },
        )

        LazyColumn(modifier = Modifier.fillMaxSize().padding(top = 8.dp)) {
            item("hint") {
                Text(
                    text = stringResource(R.string.past_values_are_stored_encrypted_under),
                    style = RageType.body.copy(fontSize = 13.5.sp, lineHeight = 20.sp, fontStyle = FontStyle.Italic),
                    color = c.fgSecondary,
                    modifier = Modifier.padding(start = 18.dp, end = 18.dp, bottom = 12.dp),
                )
            }
            itemsIndexed(entries, key = { _, rev -> rev.id }) { index, revision ->
                HistoryEntry(
                    revision = revision,
                    selected = selected == revision.id,
                    drawSpineTop = index > 0,
                    drawSpineBottom = index < entries.size - 1,
                    onSelect = { selected = if (selected == revision.id) null else revision.id },
                    onRestore = { onRestore(revision) },
                    onViewDiff = { onViewDiff(revision) },
                )
            }
            item("trail") {
                Spacer(modifier = Modifier.height(40.dp))
            }
        }
    }
}

@Composable
private fun HistoryEntry(
    revision: HistoryRevision,
    selected: Boolean,
    drawSpineTop: Boolean,
    drawSpineBottom: Boolean,
    onSelect: () -> Unit,
    onRestore: () -> Unit,
    onViewDiff: () -> Unit,
) {
    val c = rageColors
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 18.dp, vertical = 0.dp),
    ) {
        Column(
            modifier = Modifier.width(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Box(
                modifier = Modifier
                    .width(1.5.dp)
                    .height(16.dp)
                    .background(if (drawSpineTop) c.divider else androidx.compose.ui.graphics.Color.Transparent),
            )
            Box(
                modifier = Modifier
                    .size(12.dp)
                    .background(
                        if (revision.current) c.accent else c.surface,
                        CircleShape,
                    )
                    .border(
                        2.dp,
                        if (revision.current) c.accent else c.border,
                        CircleShape,
                    ),
            )
            Box(
                modifier = Modifier
                    .width(1.5.dp)
                    .weight(1f, fill = true)
                    .background(if (drawSpineBottom) c.divider else androidx.compose.ui.graphics.Color.Transparent),
            )
        }
        Spacer(modifier = Modifier.width(8.dp))
        Column(
            modifier = Modifier
                .weight(1f)
                .padding(top = 8.dp, bottom = 16.dp)
                .background(
                    if (selected) c.tile else c.surface,
                    RoundedCornerShape(10.dp),
                )
                .border(1.dp, c.border, RoundedCornerShape(10.dp))
                .clickable(onClick = onSelect)
                .padding(horizontal = 14.dp, vertical = 12.dp),
        ) {
            Row(
                verticalAlignment = Alignment.Top,
                horizontalArrangement = Arrangement.SpaceBetween,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    text = revision.when_,
                    style = RageType.rowTitle.copy(fontSize = 14.5.sp, lineHeight = 18.sp),
                    color = c.fgEmphasis,
                    modifier = Modifier.weight(1f),
                )
                if (revision.current) {
                    Text(
                        text = stringResource(R.string.current),
                        style = RageType.eyebrow.copy(fontSize = 10.sp, fontWeight = FontWeight.Bold),
                        color = c.accent,
                    )
                }
            }
            Mono(
                text = revision.by,
                size = 11,
                color = c.fgSecondary,
                modifier = Modifier.padding(top = 2.dp),
            )
            if (revision.changes.isNotEmpty()) {
                Spacer(modifier = Modifier.height(8.dp))
                Row(
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    revision.changes.forEach { change ->
                        Box(
                            modifier = Modifier
                                .background(c.tile, RoundedCornerShape(10.dp))
                                .padding(horizontal = 8.dp, vertical = 2.dp),
                        ) {
                            val text = if (change.diff != null) {
                                "${change.field} · ${change.diff}"
                            } else {
                                change.field
                            }
                            Text(
                                text = text,
                                style = RageType.sansBody.copy(fontSize = 11.5.sp, lineHeight = 15.sp),
                                color = c.fgPrimary,
                            )
                        }
                    }
                }
            }
            if (selected && !revision.current) {
                Spacer(modifier = Modifier.height(12.dp))
                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    RageButton(
                        label = stringResource(R.string.view_diff),
                        onClick = onViewDiff,
                        size = ButtonSize.Sm,
                        variant = ButtonVariant.Secondary,
                    )
                    RageButton(
                        label = stringResource(R.string.restore),
                        onClick = onRestore,
                        size = ButtonSize.Sm,
                        variant = ButtonVariant.Primary,
                    )
                }
            }
        }
    }
}
