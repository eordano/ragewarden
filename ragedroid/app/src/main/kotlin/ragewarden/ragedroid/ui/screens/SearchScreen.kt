package ragewarden.ragedroid.ui.screens

import ragewarden.ragedroid.R
import androidx.compose.ui.res.stringResource
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.Folder
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.Link
import androidx.compose.material.icons.outlined.Search
import androidx.compose.material.icons.outlined.Star
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
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import kotlinx.collections.immutable.ImmutableList
import kotlinx.collections.immutable.persistentListOf
import kotlinx.collections.immutable.toImmutableList
import ragewarden.ragedroid.model.VaultItem
import ragewarden.ragedroid.ui.components.IconBtn
import ragewarden.ragedroid.ui.components.RageChip
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors

private val PINNED_IDS: List<String> = listOf("github", "aws-root", "tailscale")

private enum class MatchField { Name, Username, Site, Notes, Folder }

private fun MatchField.label(): String = when (this) {
    MatchField.Name -> "name"
    MatchField.Username -> "username"
    MatchField.Site -> "site"
    MatchField.Notes -> "notes"
    MatchField.Folder -> "folder"
}

private data class SearchHit(val item: VaultItem, val match: MatchField?)

@Composable
fun SearchScreen(
    items: ImmutableList<VaultItem>,
    onBack: () -> Unit,
    onOpen: (VaultItem) -> Unit,
) {
    val c = rageColors
    var query by remember { mutableStateOf("") }
    var protectedOnly by remember { mutableStateOf(false) }
    var recipientId by remember { mutableStateOf<String?>(null) }
    var folder by remember { mutableStateOf<String?>(null) }
    var recents by remember { mutableStateOf<List<String>>(emptyList()) }

    val folders: List<String> = remember(items) {
        items.map { it.folder }.distinct().filter { it.isNotBlank() }
    }
    val liveRecipients = ragewarden.ragedroid.ui.LocalLiveRecipients.current
    // Only a recipient an age header can name is offerable as a filter: a
    // software or paper key's X25519 stanza carries nothing but the ephemeral
    // share (data/RecipientDescriptors.kt), so cycling onto one could only ever
    // produce an empty result list.
    val filterableRecipients = remember(liveRecipients) {
        liveRecipients.filter { it.descriptors.isNotEmpty() }
    }
    val recipientOrder: List<String?> = remember(filterableRecipients) {
        listOf<String?>(null) + filterableRecipients.map { it.id }
    }
    val selectedDescriptors: Set<String> = remember(recipientId, filterableRecipients) {
        filterableRecipients.firstOrNull { it.id == recipientId }?.descriptors?.toSet().orEmpty()
    }
    // A recipient can vanish out from under an active chip (revoked here, or
    // re-enrolled under a new id). The chip would keep its old id, match no
    // descriptors, and empty the result list while still reading as a live
    // filter -- so clear it instead of showing "no results" for a key that is
    // simply gone.
    LaunchedEffect(filterableRecipients) {
        if (recipientId != null && filterableRecipients.none { it.id == recipientId }) {
            recipientId = null
        }
    }

    val hits: ImmutableList<SearchHit> = remember(
        items, query, protectedOnly, recipientId, selectedDescriptors, folder,
    ) {
        items.map { item -> SearchHit(item, computeMatch(item, query)) }
            .filter { hit ->
                val it = hit.item
                if (protectedOnly && !it.rage) return@filter false
                // `it.recipients` holds stanza descriptors parsed from the item's
                // own age header ("piv-p256:<b64>"), not recipient ids -- see
                // data/RecipientDescriptors.kt. The chip carries a `Recipient.id`,
                // a UUID, so this used to test one namespace against another and
                // picking any recipient emptied the result list outright. Same fix
                // as ItemDetailScreen.kt:159 / MultiIdentityPickerSheet.kt:51.
                val rid = recipientId
                if (rid != null && it.recipients.none { d -> d in selectedDescriptors }) return@filter false
                val f = folder
                if (f != null && it.folder != f) return@filter false
                if (query.isNotBlank() && hit.match == null) return@filter false
                true
            }
            .toImmutableList()
    }

    val activeFilters = listOf(
        protectedOnly,
        recipientId != null,
        folder != null,
    ).count { it }
    val hasQuery = query.isNotEmpty()

    val recentItems: List<VaultItem> = remember(recents, items) {
        recents.mapNotNull { id -> items.firstOrNull { it.id == id } }
    }
    val pinnedItems: List<VaultItem> = remember(items) {
        PINNED_IDS.mapNotNull { id -> items.firstOrNull { it.id == id } }
    }

    val record: (VaultItem) -> Unit = { item ->
        recents = (listOf(item.id) + recents.filter { it != item.id }).take(5)
        onOpen(item)
    }

    Column(modifier = Modifier.fillMaxSize().background(c.background)) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(start = 12.dp, end = 12.dp, top = 10.dp, bottom = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            IconBtn(
                icon = Icons.AutoMirrored.Outlined.ArrowBack,
                contentDescription = stringResource(R.string.back),
                onClick = onBack,
            )
            Row(
                modifier = Modifier
                    .weight(1f)
                    .background(c.surfaceSunken, RoundedCornerShape(10.dp))
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
                BasicTextField(
                    value = query,
                    onValueChange = { query = it },
                    textStyle = RageType.sansBody.copy(color = c.fgPrimary),
                    cursorBrush = SolidColor(c.accent),
                    singleLine = true,
                    modifier = Modifier.weight(1f),
                    decorationBox = { inner ->
                        if (query.isEmpty()) {
                            Text(
                                text = stringResource(R.string.search_vault_recipients_notes),
                                style = RageType.sansBody,
                                color = c.fgSecondary,
                            )
                        }
                        inner()
                    },
                )
                if (query.isNotEmpty()) {
                    IconBtn(
                        icon = Icons.Outlined.Close,
                        contentDescription = stringResource(R.string.clear_search),
                        onClick = { query = "" },
                        iconSize = 16,
                    )
                }
            }
        }

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState())
                .padding(start = 14.dp, end = 14.dp, top = 4.dp, bottom = 10.dp),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            FilterChip(
                label = stringResource(R.string.protected_only),
                icon = Icons.Outlined.Link,
                active = protectedOnly,
                onClick = { protectedOnly = !protectedOnly },
            )
            // Hidden when nothing is filterable rather than left as a chip that
            // cycles `[null]` and never lights up: with only software or paper
            // keys enrolled there is no recipient an age header can name.
            if (filterableRecipients.isNotEmpty()) {
                FilterChip(
                    label = recipientId
                        ?.let { rid -> filterableRecipients.firstOrNull { it.id == rid }?.name ?: stringResource(R.string.recipient) }
                        ?: stringResource(R.string.recipient),
                    icon = Icons.Outlined.Key,
                    active = recipientId != null,
                    onClick = {
                        val current = recipientOrder.indexOf(recipientId).let { if (it < 0) 0 else it }
                        recipientId = recipientOrder[(current + 1) % recipientOrder.size]
                    },
                )
            }
            FilterChip(
                label = folder ?: stringResource(R.string.folder),
                icon = Icons.Outlined.Folder,
                active = folder != null,
                onClick = {
                    val order: List<String?> = listOf<String?>(null) + folders
                    val current = order.indexOf(folder).let { if (it < 0) 0 else it }
                    folder = order[(current + 1) % order.size]
                },
            )
            if (activeFilters > 0) {
                Box(
                    modifier = Modifier
                        .clickable {
                            protectedOnly = false
                            recipientId = null
                            folder = null
                        }
                        .padding(horizontal = 8.dp, vertical = 5.dp),
                ) {
                    Text(
                        text = stringResource(R.string.clear),
                        style = RageType.button.copy(fontWeight = FontWeight.SemiBold),
                        color = c.fgSecondary,
                    )
                }
            }
        }

        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(1.dp)
                .background(c.divider),
        )

        if (!hasQuery && activeFilters == 0) {
            EmptySearchState(
                recents = recentItems,
                pinned = pinnedItems,
                onOpen = record,
            )
        } else {
            Text(
                text = androidx.compose.ui.res.pluralStringResource(R.plurals.result_count, hits.size, hits.size),
                style = RageType.eyebrow,
                color = c.fgSecondary,
                modifier = Modifier.padding(start = 18.dp, end = 18.dp, top = 10.dp, bottom = 6.dp),
            )
            if (hits.isEmpty()) {
                EmptyHint(message = stringResource(R.string.nothing_matches_that_search))
            } else {
                LazyColumn(modifier = Modifier.fillMaxSize()) {
                    items(hits, key = { it.item.id }) { hit ->
                        SearchResultRowPlus(
                            item = hit.item,
                            query = query,
                            match = hit.match,
                            onClick = { record(hit.item) },
                        )
                    }
                }
            }
        }
    }
}

private fun computeMatch(item: VaultItem, q: String): MatchField? {
    if (q.isBlank()) return null
    val ql = q.lowercase()
    if (item.name.lowercase().contains(ql)) return MatchField.Name
    if (item.username.lowercase().contains(ql)) return MatchField.Username
    if (item.site.lowercase().contains(ql)) return MatchField.Site
    if (item.notes?.lowercase()?.contains(ql) == true) return MatchField.Notes
    if (item.folder.lowercase().contains(ql)) return MatchField.Folder
    return null
}

@Composable
private fun EmptySearchState(
    recents: List<VaultItem>,
    pinned: List<VaultItem>,
    onOpen: (VaultItem) -> Unit,
) {
    val c = rageColors
    if (recents.isEmpty() && pinned.isEmpty()) {
        EmptyHint(message = stringResource(R.string.type_to_search_or_pick_a))
        return
    }
    LazyColumn(modifier = Modifier.fillMaxSize()) {
        if (recents.isNotEmpty()) {
            item("recent-label") { SearchSection(label = stringResource(R.string.recent)) }
            items(recents, key = { "rc-${it.id}" }) { item ->
                PlainResultRow(item = item, hint = stringResource(R.string.recent), hintIcon = null, onClick = { onOpen(item) })
            }
        }
        if (pinned.isNotEmpty()) {
            item("pinned-label") { SearchSection(label = stringResource(R.string.pinned)) }
            items(pinned, key = { "pn-${it.id}" }) { item ->
                PlainResultRow(
                    item = item,
                    hint = stringResource(R.string.pinned),
                    hintIcon = Icons.Outlined.Star,
                    onClick = { onOpen(item) },
                )
            }
        }
        item("trail") { Spacer(modifier = Modifier.height(40.dp)) }
    }
}

@Composable
private fun EmptyHint(message: String) {
    val c = rageColors
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 60.dp, start = 24.dp, end = 24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Box(
            modifier = Modifier
                .size(48.dp)
                .background(c.tile, RoundedCornerShape(24.dp)),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                imageVector = Icons.Outlined.Search,
                contentDescription = null,
                tint = c.fgSecondary,
                modifier = Modifier.size(22.dp),
            )
        }
        Spacer(modifier = Modifier.height(14.dp))
        Text(
            text = message,
            style = RageType.body.copy(fontStyle = FontStyle.Italic, textAlign = TextAlign.Center),
            color = c.fgSecondary,
        )
    }
}

@Composable
internal fun SearchSection(label: String) {
    val c = rageColors
    Text(
        text = label.uppercase(),
        style = RageType.eyebrow,
        color = c.fgSecondary,
        modifier = Modifier.padding(start = 18.dp, end = 18.dp, top = 14.dp, bottom = 6.dp),
    )
}

@Composable
internal fun FilterChip(
    label: String,
    icon: ImageVector,
    active: Boolean,
    onClick: () -> Unit,
) {
    val c = rageColors
    val bg = if (active) c.fgEmphasis else c.surfaceSunken
    val fg = if (active) c.background else c.fgPrimary
    val border = if (active) c.fgEmphasis else c.border
    Row(
        modifier = Modifier
            .background(bg, RoundedCornerShape(999.dp))
            .border(1.dp, border, RoundedCornerShape(999.dp))
            .clickable(onClick = onClick)
            .padding(horizontal = 10.dp, vertical = 5.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(5.dp),
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = fg,
            modifier = Modifier.size(11.dp),
        )
        Text(
            text = label,
            style = RageType.button.copy(fontWeight = FontWeight.SemiBold),
            color = fg,
            maxLines = 1,
        )
    }
}

@Composable
private fun SearchResultRowPlus(
    item: VaultItem,
    query: String,
    match: MatchField?,
    onClick: () -> Unit,
) {
    val c = rageColors
    val initials = item.name.filter { it.isLetter() }.take(2).uppercase().ifEmpty { "··" }

    Column(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable(onClick = onClick)
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Box(
                modifier = Modifier
                    .size(36.dp)
                    .background(
                        if (item.rage) c.tile else c.surfaceElevated,
                        RoundedCornerShape(8.dp),
                    )
                    .border(1.dp, c.border, RoundedCornerShape(8.dp)),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    text = initials,
                    style = RageType.rowTitle,
                    color = if (item.rage) c.accent else c.fgSecondary,
                )
            }
            Column(modifier = Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = item.name,
                        style = RageType.rowTitle,
                        color = c.fgEmphasis,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f, fill = false),
                    )
                    if (match != null && match != MatchField.Name) {
                        Spacer(modifier = Modifier.size(8.dp))
                        Box(
                            modifier = Modifier
                                .background(c.tile, RoundedCornerShape(999.dp))
                                .padding(horizontal = 7.dp, vertical = 1.dp),
                        ) {
                            Text(
                                text = stringResource(R.string.matched, match.label().uppercase()),
                                style = RageType.eyebrow,
                                color = c.accent,
                            )
                        }
                    }
                }
                val sub = when (match) {
                    MatchField.Notes -> snippet(item.notes.orEmpty(), query)
                    MatchField.Folder -> stringResource(R.string.in_, item.folder)
                    else -> {
                        val site = item.site.takeIf { it.isNotBlank() }
                        if (site != null) "${item.username} · $site" else item.username
                    }
                }
                Text(
                    text = sub,
                    style = if (match == MatchField.Notes) {
                        RageType.caption.copy(fontStyle = FontStyle.Italic)
                    } else {
                        RageType.caption
                    },
                    color = c.fgSecondary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            if (item.rage) {
                RageChip(recipientCount = item.recipients.size)
            }
        }
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(1.dp)
                .background(c.divider),
        )
    }
}

@Composable
internal fun PlainResultRow(
    item: VaultItem,
    hint: String,
    hintIcon: ImageVector?,
    onClick: () -> Unit,
) {
    val c = rageColors
    val initials = item.name.filter { it.isLetter() }.take(2).uppercase().ifEmpty { "··" }
    Column(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable(onClick = onClick)
                .padding(horizontal = 16.dp, vertical = 11.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Box(
                modifier = Modifier
                    .size(32.dp)
                    .background(
                        if (item.rage) c.tile else c.surfaceElevated,
                        RoundedCornerShape(8.dp),
                    )
                    .border(1.dp, c.border, RoundedCornerShape(8.dp)),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    text = initials,
                    style = RageType.button.copy(fontWeight = FontWeight.Bold),
                    color = if (item.rage) c.accent else c.fgSecondary,
                )
            }
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = item.name,
                    style = RageType.rowTitle,
                    color = c.fgEmphasis,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                val sub = if (item.site.isNotBlank()) {
                    "${item.username} · ${item.site}"
                } else {
                    item.username
                }
                Text(
                    text = sub,
                    style = RageType.caption,
                    color = c.fgSecondary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                if (hintIcon != null) {
                    Icon(
                        imageVector = hintIcon,
                        contentDescription = null,
                        tint = c.fgSecondary,
                        modifier = Modifier.size(10.dp),
                    )
                }
                Text(
                    text = hint.uppercase(),
                    style = RageType.eyebrow,
                    color = c.fgSecondary,
                )
            }
        }
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(1.dp)
                .background(c.divider),
        )
    }
}

private fun snippet(notes: String, q: String): String {
    if (q.isBlank()) return notes.take(60)
    val i = notes.lowercase().indexOf(q.lowercase())
    if (i < 0) return notes.take(60)
    val start = (i - 12).coerceAtLeast(0)
    val end = (i + q.length + 30).coerceAtMost(notes.length)
    val prefix = if (start > 0) "..." else ""
    val suffix = if (end < notes.length) "..." else ""
    return prefix + notes.substring(start, end) + suffix
}

@Suppress("unused")
private val previewItems: ImmutableList<VaultItem> = persistentListOf()
