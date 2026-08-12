package ragewarden.ragedroid.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Bolt
import androidx.compose.material.icons.outlined.Check
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.DeleteOutline
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material.icons.outlined.Schedule
import androidx.compose.material.icons.outlined.Visibility
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp
import kotlinx.collections.immutable.ImmutableList
import ragewarden.ragedroid.data.audit.AuditAction
import ragewarden.ragedroid.data.audit.AuditEntry
import ragewarden.ragedroid.ui.components.AppBar
import ragewarden.ragedroid.ui.components.IconBtn
import ragewarden.ragedroid.ui.components.RecipientPip
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors

private enum class AuditFilter(val id: String, val label: String) {
    All("all", "All"),
    Unlocks("unlocks", "Unlocks"),
    Failures("failures", "Failures"),
    Admin("admin", "Enrol & rotate"),
}

@Composable
fun AuditLogScreen(
    onBack: () -> Unit,
    entries: ImmutableList<AuditEntry> = kotlinx.collections.immutable.persistentListOf(),
    onClear: () -> Unit = {},
    onToast: (String) -> Unit = {},
) {
    val c = rageColors
    var filter by remember { mutableStateOf(AuditFilter.All) }

    val filtered = remember(filter, entries) {
        entries.filter { e ->
            when (filter) {
                AuditFilter.All -> true
                AuditFilter.Unlocks -> e.action in setOf(
                    AuditAction.Autofill,
                    AuditAction.Copy,
                    AuditAction.Reveal,
                    AuditAction.Totp,
                )
                AuditFilter.Failures -> e.action == AuditAction.Failed
                AuditFilter.Admin -> e.action in setOf(
                    AuditAction.Enroll,
                    AuditAction.Rotate,
                    AuditAction.Delete,
                )
            }
        }
    }

    val groups = remember(filtered) {
        val out = mutableListOf<Pair<String, MutableList<AuditEntry>>>()
        var current: String? = null
        filtered.forEach { e ->
            if (e.bucket != current) {
                out.add(e.bucket to mutableListOf())
                current = e.bucket
            }
            out.last().second.add(e)
        }
        out
    }

    Column(modifier = Modifier.fillMaxSize().background(c.background)) {
        AppBar(
            title = "Activity",
            subtitle = "Local · this device",
            leading = {
                IconBtn(
                    icon = Icons.AutoMirrored.Outlined.ArrowBack,
                    contentDescription = "Back",
                    onClick = onBack,
                )
            },
            trailing = if (entries.isNotEmpty()) {
                {
                    IconBtn(
                        icon = Icons.Outlined.Close,
                        contentDescription = "Clear activity",
                        onClick = onClear,
                    )
                }
            } else null,
        )

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState())
                .padding(start = 14.dp, end = 14.dp, bottom = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            AuditFilter.entries.forEach { f ->
                val active = filter == f
                Box(
                    modifier = Modifier
                        .background(
                            if (active) c.fgEmphasis else c.surfaceSunken,
                            RoundedCornerShape(999.dp),
                        )
                        .border(
                            1.dp,
                            if (active) c.fgEmphasis else c.border,
                            RoundedCornerShape(999.dp),
                        )
                        .clickable { filter = f }
                        .padding(horizontal = 12.dp, vertical = 5.dp),
                ) {
                    Text(
                        text = f.label,
                        style = RageType.button.copy(fontSize = 12.sp),
                        color = if (active) c.background else c.fgPrimary,
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

        if (groups.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(horizontal = 24.dp, vertical = 60.dp),
                contentAlignment = Alignment.TopCenter,
            ) {
                Text(
                    text = "No matching activity.",
                    style = RageType.body.copy(
                        fontSize = 14.sp,
                        fontStyle = FontStyle.Italic,
                    ),
                    color = c.fgSecondary,
                    textAlign = TextAlign.Center,
                )
            }
        } else {
            LazyColumn(modifier = Modifier.fillMaxSize()) {
                groups.forEach { (label, list) ->
                    item(key = "h-$label") {
                        Text(
                            text = label.uppercase(),
                            style = RageType.eyebrow.copy(fontSize = 11.sp, letterSpacing = 0.08.em),
                            color = c.fgSecondary,
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(c.background)
                                .padding(start = 18.dp, end = 18.dp, top = 12.dp, bottom = 6.dp),
                        )
                    }
                    items(list, key = { it.id }) { entry ->
                        AuditRow(entry = entry)
                    }
                }
                item("trail") {
                    Text(
                        text = "Activity is stored on this device only. Nothing leaves the phone.",
                        style = RageType.caption.copy(
                            fontSize = 11.sp,
                            fontStyle = FontStyle.Italic,
                            lineHeight = 17.sp,
                        ),
                        color = c.fgSecondary,
                        textAlign = TextAlign.Center,
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 24.dp, vertical = 20.dp),
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                }
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun AuditRow(entry: AuditEntry) {
    val c = rageColors
    val liveRecipients = ragewarden.ragedroid.ui.LocalLiveRecipients.current
    val recipient = remember(entry.recipient, liveRecipients) {
        liveRecipients.firstOrNull { it.id == entry.recipient }
    }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 18.dp, vertical = 12.dp),
        verticalAlignment = Alignment.Top,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        ActionIcon(action = entry.action)
        Column(modifier = Modifier.weight(1f)) {
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(2.dp),
            ) {
                Text(
                    text = actionLabel(entry.action),
                    style = RageType.rowTitle.copy(fontSize = 14.sp),
                    color = c.fgEmphasis,
                )
                if (entry.cleared) {
                    Text(
                        text = "· cleared".uppercase(),
                        style = RageType.eyebrow.copy(fontSize = 10.sp, letterSpacing = 0.06.em),
                        color = c.fgSecondary,
                    )
                }
            }
            Text(
                text = entry.item,
                style = RageType.body.copy(fontSize = 13.5.sp),
                color = c.fgPrimary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.padding(top = 2.dp),
            )
            if (entry.reason != null) {
                Text(
                    text = entry.reason,
                    style = RageType.caption.copy(fontSize = 11.5.sp),
                    color = if (entry.action == AuditAction.Failed) c.danger else c.fgSecondary,
                    modifier = Modifier.padding(top = 2.dp),
                )
            }
            Row(
                modifier = Modifier.padding(top = 4.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                Text(
                    text = entry.timestamp,
                    style = RageType.caption.copy(fontSize = 11.sp),
                    color = c.fgSecondary,
                )
                if (recipient != null) {
                    Text(text = "·", style = RageType.caption, color = c.fgSecondary)
                    Box(modifier = Modifier.size(14.dp), contentAlignment = Alignment.Center) {
                        RecipientPip(kind = recipient.kind)
                    }
                    Text(
                        text = recipient.name,
                        style = RageType.caption.copy(fontSize = 11.sp),
                        color = c.fgSecondary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
                if (entry.site != null) {
                    Text(text = "·", style = RageType.caption, color = c.fgSecondary)
                    Text(
                        text = entry.site,
                        style = RageType.caption.copy(fontSize = 11.sp),
                        color = c.fgSecondary,
                    )
                }
            }
        }
    }
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(1.dp)
            .background(c.divider),
    )
}

@Composable
private fun ActionIcon(action: AuditAction) {
    val c = rageColors
    val (icon, tint) = actionIconAndTint(action)
    Box(
        modifier = Modifier
            .size(28.dp)
            .background(c.tile, RoundedCornerShape(6.dp)),
        contentAlignment = Alignment.Center,
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = tint(c),
            modifier = Modifier.size(14.dp),
        )
    }
}

private fun actionLabel(action: AuditAction): String = when (action) {
    AuditAction.Autofill -> "Autofilled"
    AuditAction.Copy -> "Copied"
    AuditAction.Reveal -> "Revealed"
    AuditAction.Totp -> "TOTP read"
    AuditAction.Failed -> "Failed"
    AuditAction.Enroll -> "Enrolled"
    AuditAction.Rotate -> "Rotated"
    AuditAction.Delete -> "Deleted"
}

private fun actionIconAndTint(action: AuditAction): Pair<ImageVector, (ragewarden.ragedroid.ui.theme.RageColors) -> androidx.compose.ui.graphics.Color> {
    return when (action) {
        AuditAction.Autofill -> Icons.Outlined.Bolt to { c -> c.accent }
        AuditAction.Copy -> Icons.Outlined.ContentCopy to { c -> c.accent }
        AuditAction.Reveal -> Icons.Outlined.Visibility to { c -> c.accent }
        AuditAction.Totp -> Icons.Outlined.Schedule to { c -> c.accent }
        AuditAction.Failed -> Icons.Outlined.Close to { c -> c.dangerStrong }
        AuditAction.Enroll -> Icons.Outlined.Add to { c -> c.success }
        AuditAction.Rotate -> Icons.Outlined.Refresh to { c -> c.success }
        AuditAction.Delete -> Icons.Outlined.DeleteOutline to { c -> c.dangerStrong }
    }
}
