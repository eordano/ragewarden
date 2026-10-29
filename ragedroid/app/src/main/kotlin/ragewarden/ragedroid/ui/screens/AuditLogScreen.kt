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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Bolt
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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp
import kotlinx.collections.immutable.ImmutableList
import ragewarden.ragedroid.R
import ragewarden.ragedroid.data.audit.AuditAction
import ragewarden.ragedroid.data.audit.AuditEntry
import ragewarden.ragedroid.ui.components.AppBar
import ragewarden.ragedroid.ui.components.BackButton
import ragewarden.ragedroid.ui.components.IconBtn
import ragewarden.ragedroid.ui.components.RecipientPip
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors
import ragewarden.ragedroid.ui.uiString

private enum class AuditFilter(val id: String, @androidx.annotation.StringRes val label: Int) {
    All("all", R.string.all),
    Unlocks("unlocks", R.string.unlocks),
    Failures("failures", R.string.failures),
    Admin("admin", R.string.enrol_rotate),
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
                    AuditAction.Exec,
                    AuditAction.AgentAdd,
                )
                AuditFilter.Failures -> e.result != ragewarden.ragedroid.data.audit.AuditResult.Ok
                AuditFilter.Admin -> e.action !in setOf(
                    AuditAction.Autofill,
                    AuditAction.Copy,
                    AuditAction.Reveal,
                    AuditAction.Totp,
                    AuditAction.Exec,
                    AuditAction.AgentAdd,
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

    var confirmClear by remember { mutableStateOf(false) }
    if (confirmClear) {
        androidx.compose.material3.AlertDialog(
            onDismissRequest = { confirmClear = false },
            title = { Text(stringResource(R.string.clear_activity)) },
            text = { Text(stringResource(R.string.this_deletes_the_activity_history_kept)) },
            confirmButton = {
                androidx.compose.material3.TextButton(onClick = {
                    confirmClear = false
                    onClear()
                }) { Text(stringResource(R.string.clear)) }
            },
            dismissButton = {
                androidx.compose.material3.TextButton(onClick = { confirmClear = false }) { Text(stringResource(R.string.cancel)) }
            },
        )
    }
    Column(modifier = Modifier.fillMaxSize().background(c.background)) {
        AppBar(
            title = stringResource(R.string.activity),
            subtitle = stringResource(R.string.local_this_device),
            leading = { BackButton(onBack) },
            trailing = if (entries.isNotEmpty()) {
                {
                    IconBtn(
                        icon = Icons.Outlined.DeleteOutline,
                        contentDescription = stringResource(R.string.clear_activity_2),
                        onClick = { confirmClear = true },
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
                        text = stringResource(f.label),
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
                    text = stringResource(R.string.no_matching_activity),
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
                        text = stringResource(R.string.activity_is_stored_on_this_device),
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
                    text = entryLabel(entry),
                    style = RageType.rowTitle.copy(fontSize = 14.sp),
                    color = c.fgEmphasis,
                )
                if (entry.cleared) {
                    Text(
                        text = stringResource(R.string.cleared).uppercase(),
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
                    color = if (entry.result != ragewarden.ragedroid.data.audit.AuditResult.Ok) c.danger else c.fgSecondary,
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
    AuditAction.Autofill -> uiString(R.string.audit_autofilled)
    AuditAction.Copy -> uiString(R.string.audit_copied)
    AuditAction.Reveal -> uiString(R.string.audit_revealed)
    AuditAction.Totp -> uiString(R.string.totp_read)
    AuditAction.Set -> uiString(R.string.audit_created)
    AuditAction.Update -> uiString(R.string.audit_edited)
    AuditAction.Rotate -> uiString(R.string.audit_re_encrypted)
    AuditAction.Delete -> uiString(R.string.audit_deleted)
    AuditAction.EnrollIdentity -> uiString(R.string.key_added)
    AuditAction.RemoveRecipient -> uiString(R.string.key_removed)
    AuditAction.Login -> uiString(R.string.signed_in)
    AuditAction.Logout -> uiString(R.string.signed_out)
    AuditAction.Sync -> uiString(R.string.audit_synced)
    AuditAction.CreateFolder -> uiString(R.string.folder_created)
    AuditAction.RenameFolder -> uiString(R.string.folder_renamed)
    AuditAction.DeleteFolder -> uiString(R.string.folder_deleted)
    AuditAction.Recover -> uiString(R.string.audit_recovered)
    AuditAction.BulkProtect -> uiString(R.string.audit_protected)
    AuditAction.Exec -> uiString(R.string.audit_passed_to_a_command)
    AuditAction.AgentAdd -> uiString(R.string.audit_loaded_into_ssh_agent)
}

private fun entryLabel(entry: AuditEntry): String = when (entry.result) {
    ragewarden.ragedroid.data.audit.AuditResult.Ok -> actionLabel(entry.action)
    ragewarden.ragedroid.data.audit.AuditResult.Declined -> uiString(R.string.declined, actionLabel(entry.action))
    ragewarden.ragedroid.data.audit.AuditResult.Failed -> uiString(R.string.failed_2, actionLabel(entry.action))
}

private fun actionIconAndTint(action: AuditAction): Pair<ImageVector, (ragewarden.ragedroid.ui.theme.RageColors) -> androidx.compose.ui.graphics.Color> {
    return when (action) {
        AuditAction.Autofill -> Icons.Outlined.Bolt to { c -> c.accent }
        AuditAction.Copy -> Icons.Outlined.ContentCopy to { c -> c.accent }
        AuditAction.Reveal -> Icons.Outlined.Visibility to { c -> c.accent }
        AuditAction.Totp -> Icons.Outlined.Schedule to { c -> c.accent }
        AuditAction.Exec, AuditAction.AgentAdd -> Icons.Outlined.Bolt to { c -> c.accent }
        AuditAction.EnrollIdentity, AuditAction.Set, AuditAction.CreateFolder, AuditAction.Login ->
            Icons.Outlined.Add to { c -> c.success }
        AuditAction.Rotate, AuditAction.Update, AuditAction.RenameFolder, AuditAction.Sync,
        AuditAction.Recover, AuditAction.BulkProtect -> Icons.Outlined.Refresh to { c -> c.success }
        AuditAction.Delete, AuditAction.RemoveRecipient, AuditAction.DeleteFolder, AuditAction.Logout ->
            Icons.Outlined.DeleteOutline to { c -> c.dangerStrong }
    }
}
