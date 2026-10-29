package ragewarden.ragedroid.ui.components

import ragewarden.ragedroid.R
import androidx.compose.ui.res.stringResource
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Check
import androidx.compose.material.icons.outlined.Folder
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.collections.immutable.ImmutableList
import kotlinx.collections.immutable.toImmutableList
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors

data class FolderOption(
    val id: String?,
    val name: String,
    val color: Color?,
)

private val FolderRowTitle = RageType.rowTitle.copy(fontSize = 14.5.sp, lineHeight = 19.sp)

@Composable
fun MoveToFolderSheet(
    open: Boolean,
    onClose: () -> Unit,
    folders: ImmutableList<FolderOption>,
    currentId: String?,
    onPick: (FolderOption) -> Unit,
) {
    val c = rageColors
    val unfiled = stringResource(R.string.unfiled)
    val resolvedFolders: ImmutableList<FolderOption> = remember(folders, unfiled) {
        if (folders.any { it.id == null }) {
            folders
        } else {
            (listOf(FolderOption(id = null, name = unfiled, color = null)) + folders)
                .toImmutableList()
        }
    }
    Sheet(open = open, onDismiss = onClose, title = stringResource(R.string.move_to_folder)) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(start = 16.dp, end = 16.dp, bottom = 16.dp)
                .clip(RoundedCornerShape(10.dp))
                .background(c.surface, RoundedCornerShape(10.dp))
                .border(1.dp, c.border, RoundedCornerShape(10.dp)),
        ) {
            resolvedFolders.forEachIndexed { index, folder ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable {
                            onPick(folder)
                            onClose()
                        }
                        .padding(horizontal = 14.dp, vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Box(
                        modifier = Modifier
                            .size(32.dp)
                            .background(folder.color ?: c.tile, RoundedCornerShape(6.dp)),
                        contentAlignment = Alignment.Center,
                    ) {
                        Icon(
                            imageVector = Icons.Outlined.Folder,
                            contentDescription = null,
                            tint = if (folder.color != null) Color(0xFFFAF6EE) else c.fgSecondary,
                            modifier = Modifier.size(16.dp),
                        )
                    }
                    Text(
                        text = folder.name,
                        style = FolderRowTitle,
                        color = c.fgEmphasis,
                        modifier = Modifier.weight(1f),
                    )
                    if (currentId == folder.id) {
                        Icon(
                            imageVector = Icons.Outlined.Check,
                            contentDescription = null,
                            tint = c.accent,
                            modifier = Modifier.size(16.dp),
                        )
                    }
                }
                if (index < resolvedFolders.size - 1) {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(1.dp)
                            .background(c.divider),
                    )
                }
            }
        }
    }
}
