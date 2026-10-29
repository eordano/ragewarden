package ragewarden.ragedroid.ui.screens

import androidx.compose.ui.platform.testTag
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.horizontalScroll
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
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.clickable
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.PersonAdd
import androidx.compose.material.icons.outlined.Search
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.material.icons.outlined.Close
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp
import kotlinx.collections.immutable.ImmutableList
import kotlinx.collections.immutable.toImmutableList
import ragewarden.ragedroid.R
import ragewarden.ragedroid.model.NO_FOLDER
import ragewarden.ragedroid.model.VaultItem
import ragewarden.ragedroid.ui.components.AppBar
import ragewarden.ragedroid.ui.components.ButtonVariant
import ragewarden.ragedroid.ui.components.EmptyVaultHero
import ragewarden.ragedroid.ui.components.FolderChip
import ragewarden.ragedroid.ui.components.IconBtn
import ragewarden.ragedroid.ui.components.RageButton
import ragewarden.ragedroid.ui.components.VaultRow
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors

@Composable
fun VaultListScreen(
    items: ImmutableList<VaultItem>,
    folders: ImmutableList<String>,
    onOpen: (VaultItem) -> Unit,
    onSettings: () -> Unit,
    onAdd: () -> Unit = {},
    onSearch: () -> Unit = {},
    hasAnyEnrolledRecipient: Boolean = true,
    onEnrollFirst: () -> Unit = onAdd,
    rotationStale: Boolean = false,
    onRotate: () -> Unit = {},
    keyListUnreadable: Boolean = false,
    onResetKeyList: () -> Unit = {},
) {
    val vaultListContext = androidx.compose.ui.platform.LocalContext.current
    val c = rageColors
    var query by remember { mutableStateOf("") }
    var folder by remember { mutableStateOf(NO_FOLDER) }

    val rageCount = items.count { it.rage }
    val filtered: ImmutableList<VaultItem> = remember(items, folder, query) {
        items.filter { it ->
            if (folder != NO_FOLDER && it.folder != folder) return@filter false
            if (query.isBlank()) return@filter true
            val q = query.trim().lowercase()
            it.name.lowercase().contains(q) ||
                it.username.lowercase().contains(q) ||
                it.site.lowercase().contains(q)
        }.toImmutableList()
    }

    Column(modifier = Modifier.fillMaxSize().background(c.background)) {
        AppBar(
            title = stringResource(R.string.vault),
            subtitle = stringResource(R.string.items_protected_2, items.size, rageCount),
            large = true,
            trailing = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    IconBtn(
                        icon = Icons.Outlined.Add,
                        contentDescription = stringResource(R.string.add_item),
                        onClick = onAdd,
                    )
                    IconBtn(
                        icon = Icons.Outlined.Settings,
                        contentDescription = stringResource(R.string.settings),
                        onClick = onSettings,
                    )
                }
            },
        )

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(start = 16.dp, end = 16.dp, top = 4.dp, bottom = 10.dp)
                .background(c.surfaceSunken, RoundedCornerShape(10.dp))
                .semantics { role = Role.Button }
                .clickable(onClick = onSearch)
                .padding(horizontal = 12.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Icon(
                imageVector = Icons.Outlined.Search,
                contentDescription = null,
                tint = c.fgSecondary,
                modifier = Modifier.size(16.dp),
            )
            Text(
                text = stringResource(R.string.search_vault_recipients_notes),
                style = RageType.sansBody,
                color = c.fgSecondary,
                modifier = Modifier.weight(1f),
            )
            Text(
                text = stringResource(R.string.filter),
                style = RageType.eyebrow.copy(
                    fontSize = 10.sp,
                    fontWeight = FontWeight.SemiBold,
                    letterSpacing = 0.06.em,
                ),
                color = c.fgSecondary.copy(alpha = 0.7f),
            )
        }

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState())
                .padding(start = 16.dp, end = 16.dp, bottom = 12.dp),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            folders.forEach { f ->
                FolderChip(name = if (f == NO_FOLDER) stringResource(R.string.all) else f, active = f == folder, onClick = { folder = f })
            }
        }

        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(1.dp)
                .background(c.divider),
        )

        if (keyListUnreadable) {
            ragewarden.ragedroid.ui.components.UnreadableKeyListCard(
                onReset = onResetKeyList,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 10.dp),
            )
        }
        var rotationBannerDismissed by androidx.compose.runtime.saveable.rememberSaveable { mutableStateOf(false) }
        if (rotationStale && items.any { it.rage } && !rotationBannerDismissed) {
            RotationBanner(onRotate = onRotate, onDismiss = { rotationBannerDismissed = true })
        }

        Box(modifier = Modifier.fillMaxSize().background(c.background)) {
            if (items.isEmpty()) {
                if (!hasAnyEnrolledRecipient) {
                    NoRecipientEmptyState(onEnrollFirst = onEnrollFirst)
                } else {
                    val host = ragewarden.ragedroid.data.VaultBridge.repository()
                        ?.serverUrl
                        ?.removePrefix("https://")
                        ?.removePrefix("http://")
                        ?.removeSuffix("/")
                        ?.removeSuffix("/api")
                        ?.takeIf { it.isNotBlank() }
                        ?: stringResource(R.string.your_bitwarden_server)
                    EmptyVaultHero(
                        syncHost = host,
                        onAdd = onAdd,
                        onAutofill = { ragewarden.ragedroid.ui.SystemSetup.openAutofillSettings(vaultListContext) },
                    )
                }
            } else if (filtered.isEmpty()) {
                Text(
                    text = stringResource(R.string.no_items_match),
                    style = RageType.body.copy(
                        textAlign = TextAlign.Center,
                        fontSize = 15.sp,
                        fontStyle = FontStyle.Italic,
                    ),
                    color = c.fgSecondary,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 40.dp, bottom = 40.dp, start = 24.dp, end = 24.dp),
                )
            } else {
                LazyColumn(modifier = Modifier.fillMaxSize().testTag("vault-list")) {
                    items(filtered, key = { it.id }) { item ->
                        VaultRow(item = item, onClick = { onOpen(item) })
                    }
                    item("footer") {
                        Text(
                            text = stringResource(R.string.vault_syncs_through_bitwarden_protected_items),
                            style = RageType.meta.copy(
                                textAlign = TextAlign.Center,
                                fontStyle = FontStyle.Italic,
                            ),
                            color = c.fgSecondary,
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(start = 24.dp, end = 24.dp, top = 24.dp, bottom = 32.dp),
                        )
                    }
                }
            }
        }
    }
}

@Composable
internal fun RotationBanner(onRotate: () -> Unit, onDismiss: () -> Unit) {
    val c = rageColors
    val tintBg = c.warning.copy(alpha = 0.14f)
    val tintBorder = c.warning.copy(alpha = 0.45f)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(tintBg)
            .border(width = 1.dp, color = tintBorder, shape = androidx.compose.ui.graphics.RectangleShape)
            .semantics { role = Role.Button }
            .clickable(onClick = onRotate)
            .padding(horizontal = 16.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = stringResource(R.string.recipients_changed_re_encrypt_items),
                style = RageType.rowTitle.copy(fontSize = 13.5.sp),
                color = c.fgEmphasis,
            )
            Text(
                text = stringResource(R.string.items_are_re_encrypted_to_the),
                style = RageType.meta.copy(fontSize = 12.sp),
                color = c.fgSecondary,
            )
        }
        Text(
            text = stringResource(R.string.re_encrypt),
            style = RageType.eyebrow.copy(
                fontSize = 11.sp,
                fontWeight = FontWeight.SemiBold,
                letterSpacing = 0.06.em,
            ),
            color = c.warning,
        )
        IconBtn(
            icon = Icons.Outlined.Close,
            contentDescription = stringResource(R.string.dismiss),
            onClick = onDismiss,
            iconSize = 18,
        )
    }
}

@Composable
private fun NoRecipientEmptyState(onEnrollFirst: () -> Unit) {
    val c = rageColors
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(c.background)
            .padding(horizontal = 24.dp, vertical = 40.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Text(
            text = stringResource(R.string.enrol_a_recipient_first),
            style = RageType.h1,
            color = c.fgEmphasis,
            textAlign = TextAlign.Center,
        )
        Spacer(modifier = Modifier.height(12.dp))
        Text(
            text = stringResource(R.string.ragewarden_encrypts_every_item_to_a),
            style = RageType.body,
            color = c.fgSecondary,
            textAlign = TextAlign.Center,
            modifier = Modifier.widthIn(max = 320.dp),
        )
        Spacer(modifier = Modifier.height(20.dp))
        Column(modifier = Modifier.widthIn(max = 280.dp).fillMaxWidth()) {
            RageButton(
                label = stringResource(R.string.add_recipient),
                icon = Icons.Outlined.PersonAdd,
                variant = ButtonVariant.Primary,
                fullWidth = true,
                onClick = onEnrollFirst,
            )
        }
    }
}
