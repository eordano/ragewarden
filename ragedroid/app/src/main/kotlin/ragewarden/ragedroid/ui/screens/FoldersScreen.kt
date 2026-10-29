package ragewarden.ragedroid.ui.screens

import ragewarden.ragedroid.R
import androidx.compose.ui.res.stringResource
import androidx.compose.foundation.background
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.KeyboardArrowRight
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Folder
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
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.collections.immutable.ImmutableList
import kotlinx.collections.immutable.persistentListOf
import kotlinx.collections.immutable.toImmutableList
import ragewarden.ragedroid.data.Folder
import ragewarden.ragedroid.data.VaultBackend
import ragewarden.ragedroid.ui.components.AppBar
import ragewarden.ragedroid.ui.components.BackButton
import ragewarden.ragedroid.ui.components.IconBtn
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors

data class FolderEntry(
    val id: String,
    val name: String,
    val color: Color,
    val itemCount: Int,
)

private val FoldersIntroStyle = RageType.body.copy(
    fontSize = 13.5.sp,
    lineHeight = 20.sp,
    fontStyle = FontStyle.Italic,
)

private val FolderRowTitle = RageType.rowTitle.copy(fontSize = 15.sp, lineHeight = 19.sp)

private val FolderRowMeta = RageType.sansBody.copy(fontSize = 11.5.sp, lineHeight = 15.sp)

private val FolderPaletteColors: List<Color> = listOf(
    Color(0xFFC8552B),
    Color(0xFF6B8E5A),
    Color(0xFF3A6B8E),
    Color(0xFFB57A2A),
    Color(0xFF8C7B6B),
    Color(0xFF7C5A8E),
    Color(0xFFC99A3F),
    Color(0xFF5A8E8E),
)

private fun foldersToEntries(folders: ImmutableList<Folder>): ImmutableList<FolderEntry> =
    folders
        .mapIndexed { index, folder ->
            FolderEntry(
                id = folder.id,
                name = folder.name,
                color = FolderPaletteColors[index % FolderPaletteColors.size],
                itemCount = 0,
            )
        }
        .toImmutableList()

@Composable
fun FoldersScreen(
    folders: ImmutableList<FolderEntry> = persistentListOf(),
    repo: VaultBackend? = null,
    initialFolders: ImmutableList<Folder>? = null,
    onBack: () -> Unit,
    onEdit: (FolderEntry) -> Unit,
    onNew: () -> Unit,
) {
    val c = rageColors
    var loaded by remember { mutableStateOf(initialFolders) }
    var loadError by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(repo) {
        if (repo != null) {
            runCatching { repo.listFolders() }.fold(
                onSuccess = { loaded = it; loadError = null },
                onFailure = { loadError = it.message ?: it.javaClass.simpleName },
            )
        }
    }
    val resolved: ImmutableList<FolderEntry> = when {
        loaded != null -> foldersToEntries(loaded!!)
        else -> folders
    }
    Column(modifier = Modifier.fillMaxSize().background(c.background)) {
        AppBar(
            title = stringResource(R.string.folders),
            leading = { BackButton(onBack) },
            trailing = {
                IconBtn(
                    icon = Icons.Outlined.Add,
                    contentDescription = stringResource(R.string.new_folder),
                    onClick = onNew,
                )
            },
        )
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(top = 8.dp, bottom = 24.dp),
        ) {
            Text(
                text = stringResource(R.string.folders_are_decrypted_client_side_only),
                style = FoldersIntroStyle,
                color = c.fgSecondary,
                modifier = Modifier.padding(start = 18.dp, end = 18.dp, bottom = 12.dp),
            )
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(c.surface),
            ) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(1.dp)
                        .background(c.border),
                )
                resolved.forEachIndexed { index, folder ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { onEdit(folder) }
                            .padding(horizontal = 16.dp, vertical = 12.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        Box(
                            modifier = Modifier
                                .size(36.dp)
                                .background(folder.color, RoundedCornerShape(8.dp)),
                            contentAlignment = Alignment.Center,
                        ) {
                            Icon(
                                imageVector = Icons.Outlined.Folder,
                                contentDescription = null,
                                tint = Color(0xFFFAF6EE),
                                modifier = Modifier.size(18.dp),
                            )
                        }
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = folder.name,
                                style = FolderRowTitle,
                                color = c.fgEmphasis,
                            )
                            Spacer(modifier = Modifier.height(2.dp))
                            Text(
                                text = androidx.compose.ui.res.pluralStringResource(R.plurals.item_count, folder.itemCount, folder.itemCount),
                                style = FolderRowMeta,
                                color = c.fgSecondary,
                            )
                        }
                        Icon(
                            imageVector = Icons.AutoMirrored.Outlined.KeyboardArrowRight,
                            contentDescription = null,
                            tint = c.fgSecondary,
                            modifier = Modifier.size(14.dp),
                        )
                    }
                    if (index < resolved.size - 1) {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(1.dp)
                                .background(c.divider),
                        )
                    }
                }
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(1.dp)
                        .background(c.border),
                )
            }
        }
    }
}
