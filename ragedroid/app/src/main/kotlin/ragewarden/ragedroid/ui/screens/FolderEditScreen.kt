package ragewarden.ragedroid.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
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
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material.icons.outlined.Folder
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import android.widget.Toast
import kotlinx.collections.immutable.ImmutableList
import kotlinx.collections.immutable.persistentListOf
import kotlinx.coroutines.launch
import ragewarden.ragedroid.data.VaultBackend
import ragewarden.ragedroid.ui.components.AppBar
import ragewarden.ragedroid.ui.components.ButtonSize
import ragewarden.ragedroid.ui.components.ButtonVariant
import ragewarden.ragedroid.ui.components.Field
import ragewarden.ragedroid.ui.components.IconBtn
import ragewarden.ragedroid.ui.components.RageButton
import ragewarden.ragedroid.ui.components.TextInput
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors

private val FOLDER_PALETTE: ImmutableList<Color> = persistentListOf(
    Color(0xFFC8552B),
    Color(0xFF6B8E5A),
    Color(0xFF3A6B8E),
    Color(0xFFB57A2A),
    Color(0xFF8C7B6B),
    Color(0xFF7C5A8E),
    Color(0xFFC99A3F),
    Color(0xFF5A8E8E),
)

private val FolderFooterStyle = RageType.sansBody.copy(fontSize = 11.5.sp, lineHeight = 17.sp)

data class FolderDraft(
    val name: String,
    val color: Color,
)

@Composable
fun FolderEditScreen(
    existing: FolderEntry? = null,
    repo: VaultBackend? = null,
    onBack: () -> Unit,
    onSave: (FolderDraft) -> Unit,
    onDelete: ((FolderEntry) -> Unit)? = null,
) {
    val c = rageColors
    val isNew = existing == null
    val scope = rememberCoroutineScope()
    val ctx = LocalContext.current
    var name by remember(existing?.id) { mutableStateOf(existing?.name ?: "") }
    var color by remember(existing?.id) { mutableStateOf(existing?.color ?: FOLDER_PALETTE[0]) }
    fun toast(msg: String) {
        Toast.makeText(ctx, msg, Toast.LENGTH_SHORT).show()
    }

    Column(modifier = Modifier.fillMaxSize().background(c.background)) {
        AppBar(
            title = if (isNew) "New folder" else "Edit folder",
            leading = {
                IconBtn(
                    icon = Icons.AutoMirrored.Outlined.ArrowBack,
                    contentDescription = "Back",
                    onClick = onBack,
                )
            },
            trailing = {
                RageButton(
                    label = "Save",
                    onClick = {
                        if (repo != null && name.isNotBlank()) {
                            scope.launch {
                                val outcome = runCatching {
                                    if (existing != null) {
                                        repo.updateFolder(existing.id, name)
                                    } else {
                                        repo.createFolder(name)
                                    }
                                }
                                if (outcome.isSuccess) {
                                    toast(if (existing != null) "Folder updated" else "Folder created")
                                } else {
                                    toast("Save failed: ${outcome.exceptionOrNull()?.message ?: "unknown"}")
                                }
                                onSave(FolderDraft(name, color))
                            }
                        } else {
                            onSave(FolderDraft(name, color))
                        }
                    },
                    size = ButtonSize.Sm,
                )
            },
        )
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(start = 16.dp, end = 16.dp, top = 8.dp, bottom = 24.dp),
        ) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 20.dp, bottom = 24.dp),
                contentAlignment = Alignment.Center,
            ) {
                Box(
                    modifier = Modifier
                        .shadow(8.dp, RoundedCornerShape(18.dp))
                        .size(80.dp)
                        .background(color, RoundedCornerShape(18.dp)),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        imageVector = Icons.Outlined.Folder,
                        contentDescription = null,
                        tint = Color(0xFFFAF6EE),
                        modifier = Modifier.size(36.dp),
                    )
                }
            }

            Field(label = "Name") {
                TextInput(
                    value = name,
                    onValueChange = { name = it },
                    placeholder = "e.g. Infrastructure",
                )
            }

            Field(label = "Colour") {
                ColorSwatchGrid(
                    palette = FOLDER_PALETTE,
                    selected = color,
                    onPick = { color = it },
                )
            }

            if (existing != null && onDelete != null) {
                Spacer(modifier = Modifier.height(24.dp))
                RageButton(
                    label = "Delete folder",
                    onClick = {
                        if (repo != null) {
                            scope.launch {
                                val outcome = runCatching { repo.deleteFolder(existing.id) }
                                if (outcome.isSuccess) {
                                    toast("Folder deleted")
                                } else {
                                    toast("Delete failed: ${outcome.exceptionOrNull()?.message ?: "unknown"}")
                                }
                                onDelete(existing)
                            }
                        } else {
                            onDelete(existing)
                        }
                    },
                    icon = Icons.Outlined.Delete,
                    variant = ButtonVariant.Danger,
                    fullWidth = true,
                )
                Spacer(modifier = Modifier.height(8.dp))
                val countLabel = if (existing.itemCount == 1) "item" else "items"
                val footerText = buildAnnotatedString {
                    append("The ${existing.itemCount} $countLabel in this folder will move to ")
                    withStyle(
                        SpanStyle(
                            fontStyle = FontStyle.Italic,
                            fontWeight = FontWeight.SemiBold,
                        ),
                    ) {
                        append("Unfiled")
                    }
                    append(".")
                }
                Text(
                    text = footerText,
                    style = FolderFooterStyle.copy(textAlign = TextAlign.Center),
                    color = c.fgSecondary,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ColorSwatchGrid(
    palette: ImmutableList<Color>,
    selected: Color,
    onPick: (Color) -> Unit,
) {
    val c = rageColors
    FlowRow(
        horizontalArrangement = Arrangement.spacedBy(10.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        palette.forEach { swatch ->
            Box(
                modifier = Modifier
                    .size(36.dp)
                    .background(swatch, RoundedCornerShape(18.dp))
                    .border(
                        width = 3.dp,
                        color = if (selected == swatch) c.fgEmphasis else Color.Transparent,
                        shape = RoundedCornerShape(18.dp),
                    )
                    .clickable { onPick(swatch) },
            )
        }
    }
}
