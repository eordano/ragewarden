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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.outlined.Check
import androidx.compose.material.icons.outlined.CheckBox
import androidx.compose.material.icons.outlined.CheckBoxOutlineBlank
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.HourglassEmpty
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material.icons.outlined.WarningAmber
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import ragewarden.ragedroid.R
import ragewarden.ragedroid.data.VaultBridge
import ragewarden.ragedroid.data.toUiRecipient
import ragewarden.ragedroid.di.appEntryPoint
import ragewarden.ragedroid.model.Recipient
import ragewarden.ragedroid.model.VaultItem
import ragewarden.ragedroid.model.VaultItemKind
import ragewarden.ragedroid.ui.components.SelectionBox
import ragewarden.ragedroid.ui.components.AppBar
import ragewarden.ragedroid.ui.components.IconBtn
import ragewarden.ragedroid.ui.components.Mono
import ragewarden.ragedroid.ui.components.RageButton
import ragewarden.ragedroid.ui.components.RecipientPip
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors
import ragewarden.ragedroid.ui.uiQuantity
import ragewarden.ragedroid.ui.uiString

private enum class BulkStep { SelectItems, PickRecipients, Progress }

private enum class ItemProtectStatus { Pending, Encrypting, Done, Failed }

private data class ProtectRow(
    val item: VaultItem,
    var status: ItemProtectStatus = ItemProtectStatus.Pending,
    var error: String? = null,
)

@Composable
fun BulkProtectScreen(
    onBack: () -> Unit,
    onComplete: () -> Unit,
    onToast: (String) -> Unit = {},
) {
    val c = rageColors
    val context = androidx.compose.ui.platform.LocalContext.current.applicationContext
    val scope = rememberCoroutineScope()

    val backend = remember(context) { VaultBridge.ensureBackend(context) }
    val accountId = remember(context) { VaultBridge.repository()?.accountId.orEmpty() }
    val allItems = remember(context) { backend.snapshot() }
    val unprotectedItems = remember(allItems) { allItems.filter { !it.rage } }
    val allRecipients: List<Recipient> = remember(context, accountId) {
        if (accountId.isBlank()) emptyList()
        else context.appEntryPoint().recipientStore().forAccount(accountId)
            .map { it.toUiRecipient() }
    }

    var step by remember { mutableStateOf(BulkStep.SelectItems) }
    val selectedIds = remember { mutableStateListOf<String>() }
    val selectedRecipientIds = remember { mutableStateListOf<String>() }

    val progressRows = remember { mutableStateListOf<ProtectRow>() }
    var processed by remember { mutableStateOf(0) }
    var running by remember { mutableStateOf(false) }
    var complete by remember { mutableStateOf(false) }

    LaunchedEffect(unprotectedItems) {
        if (selectedIds.isEmpty()) {
            selectedIds.addAll(unprotectedItems.map { it.id })
        }
    }

    LaunchedEffect(allRecipients) {
        if (selectedRecipientIds.isEmpty()) {
            selectedRecipientIds.addAll(allRecipients.map { it.id })
        }
    }

    Column(modifier = Modifier.fillMaxSize().background(c.background)) {
        AppBar(
            title = when (step) {
                BulkStep.SelectItems -> stringResource(R.string.protect_unprotected_items)
                BulkStep.PickRecipients -> stringResource(R.string.pick_recipients)
                BulkStep.Progress -> if (complete) stringResource(R.string.done) else stringResource(R.string.protecting)
            },
            leading = {
                IconBtn(
                    icon = Icons.AutoMirrored.Outlined.ArrowBack,
                    contentDescription = stringResource(R.string.back),
                    onClick = {
                        when {
                            running -> Unit
                            step == BulkStep.PickRecipients -> step = BulkStep.SelectItems
                            step == BulkStep.Progress && complete -> onComplete()
                            else -> onBack()
                        }
                    },
                )
            },
        )

        when (step) {
            BulkStep.SelectItems -> SelectItemsStep(
                items = unprotectedItems,
                selectedIds = selectedIds,
                onToggle = { id ->
                    if (id in selectedIds) selectedIds.remove(id) else selectedIds.add(id)
                },
                onToggleAll = {
                    if (selectedIds.size == unprotectedItems.size) {
                        selectedIds.clear()
                    } else {
                        selectedIds.clear()
                        selectedIds.addAll(unprotectedItems.map { it.id })
                    }
                },
                onNext = {
                    if (selectedIds.isNotEmpty()) {
                        step = BulkStep.PickRecipients
                    }
                },
            )

            BulkStep.PickRecipients -> PickRecipientsStep(
                recipients = allRecipients,
                selectedIds = selectedRecipientIds,
                onToggle = { id ->
                    if (id in selectedRecipientIds) selectedRecipientIds.remove(id) else selectedRecipientIds.add(id)
                },
                selectedItemCount = selectedIds.size,
                onBegin = {
                    if (selectedRecipientIds.isEmpty()) return@PickRecipientsStep
                    val selected = unprotectedItems.filter { it.id in selectedIds }
                    progressRows.clear()
                    progressRows.addAll(selected.map { ProtectRow(it) })
                    processed = 0
                    running = true
                    complete = false
                    step = BulkStep.Progress

                    scope.launch {
                        for (i in progressRows.indices) {
                            progressRows[i] = progressRows[i].copy(status = ItemProtectStatus.Encrypting)
                            val result = withContext(Dispatchers.IO) {
                                runCatching {
                                    val item = progressRows[i].item
                                    val pt = backend.decrypt(item.id, emptyList(), null)
                                    backend.update(item.copy(rage = true), pt)
                                }
                            }
                            progressRows[i] = if (result.isSuccess) {
                                progressRows[i].copy(status = ItemProtectStatus.Done)
                            } else {
                                progressRows[i].copy(
                                    status = ItemProtectStatus.Failed,
                                    error = result.exceptionOrNull()?.message ?: uiString(R.string.unknown_error),
                                )
                            }
                            processed = i + 1
                        }
                        running = false
                        complete = true
                    }
                },
            )

            BulkStep.Progress -> ProgressStep(
                rows = progressRows,
                processed = processed,
                total = progressRows.size,
                complete = complete,
                onDone = {
                    val failed = progressRows.count { it.status == ItemProtectStatus.Failed }
                    val succeeded = progressRows.size - failed
                    if (failed == 0) {
                        onToast(uiQuantity(R.plurals.protected_items, succeeded, succeeded))
                    } else {
                        onToast(uiString(R.string.protected_failed, succeeded, failed))
                    }
                    onComplete()
                },
            )
        }
    }
}

@Composable
private fun SelectItemsStep(
    items: List<VaultItem>,
    selectedIds: List<String>,
    onToggle: (String) -> Unit,
    onToggleAll: () -> Unit,
    onNext: () -> Unit,
) {
    val c = rageColors
    val allSelected = selectedIds.size == items.size && items.isNotEmpty()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(start = 16.dp, end = 16.dp, top = 6.dp, bottom = 16.dp),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(bottom = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Row(
                modifier = Modifier
                    .clickable(onClick = onToggleAll)
                    .padding(vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                Icon(
                    imageVector = if (allSelected) Icons.Outlined.CheckBox else Icons.Outlined.CheckBoxOutlineBlank,
                    contentDescription = null,
                    tint = c.accent,
                    modifier = Modifier.size(18.dp),
                )
                Text(
                    text = if (allSelected) stringResource(R.string.deselect_all) else stringResource(R.string.select_all),
                    style = RageType.button,
                    color = c.accent,
                )
            }
            Box(
                modifier = Modifier
                    .background(c.tile, RoundedCornerShape(12.dp))
                    .padding(horizontal = 10.dp, vertical = 4.dp),
            ) {
                Text(
                    text = stringResource(R.string.of_selected, selectedIds.size, items.size),
                    style = RageType.caption.copy(fontSize = 12.sp),
                    color = c.fgEmphasis,
                )
            }
        }

        if (items.isEmpty()) {
            Spacer(modifier = Modifier.weight(1f))
            Text(
                text = stringResource(R.string.all_items_are_already_rage_protected),
                style = RageType.body.copy(fontSize = 15.sp),
                color = c.fgSecondary,
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(modifier = Modifier.weight(1f))
        } else {
            LazyColumn(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(2.dp),
            ) {
                items(items, key = { it.id }) { item ->
                    val selected = item.id in selectedIds
                    ItemSelectRow(
                        item = item,
                        selected = selected,
                        onToggle = { onToggle(item.id) },
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(12.dp))
        RageButton(
            label = stringResource(R.string.next),
            onClick = onNext,
            icon = Icons.Outlined.Shield,
            fullWidth = true,
            enabled = selectedIds.isNotEmpty(),
        )
    }
}

@Composable
private fun ItemSelectRow(
    item: VaultItem,
    selected: Boolean,
    onToggle: () -> Unit,
) {
    val c = rageColors
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(
                if (selected) c.tile else androidx.compose.ui.graphics.Color.Transparent,
                RoundedCornerShape(8.dp),
            )
            .clickable(onClick = onToggle)
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        SelectionBox(on = selected)
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = item.name,
                style = RageType.rowTitle.copy(fontSize = 14.sp),
                color = c.fgEmphasis,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            val subtitle = when (item.kind) {
                VaultItemKind.Login -> item.username.ifBlank { stringResource(R.string.login) }
                VaultItemKind.Card -> stringResource(R.string.card)
                VaultItemKind.Note -> stringResource(R.string.secure_note)
                VaultItemKind.Identity -> stringResource(R.string.identity)
                VaultItemKind.SshKey -> stringResource(R.string.ssh_key)
            }
            Text(
                text = subtitle,
                style = RageType.caption.copy(fontSize = 11.5.sp),
                color = c.fgSecondary,
            )
        }
    }
}

@Composable
private fun PickRecipientsStep(
    recipients: List<Recipient>,
    selectedIds: List<String>,
    onToggle: (String) -> Unit,
    selectedItemCount: Int,
    onBegin: () -> Unit,
) {
    val c = rageColors

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(start = 16.dp, end = 16.dp, top = 6.dp, bottom = 16.dp),
    ) {
        Text(
            text = androidx.compose.ui.res.pluralStringResource(R.plurals.encrypt_items_to_selected_recipients, selectedItemCount, selectedItemCount),
            style = RageType.body.copy(fontSize = 15.sp, lineHeight = 22.sp),
            color = c.fgPrimary,
            modifier = Modifier.padding(bottom = 12.dp),
        )

        if (selectedIds.size < 2) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(c.tile, RoundedCornerShape(8.dp))
                    .border(1.dp, c.warning, RoundedCornerShape(8.dp))
                    .padding(horizontal = 12.dp, vertical = 10.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.Top,
            ) {
                Icon(
                    imageVector = Icons.Outlined.WarningAmber,
                    contentDescription = null,
                    tint = c.warning,
                    modifier = Modifier
                        .size(16.dp)
                        .padding(top = 2.dp),
                )
                Text(
                    text = stringResource(R.string.at_least_two_recipients_recommended_with),
                    style = RageType.body.copy(fontSize = 13.sp, lineHeight = 18.sp),
                    color = c.fgPrimary,
                )
            }
            Spacer(modifier = Modifier.height(12.dp))
        }

        LazyColumn(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            items(recipients, key = { it.id }) { recipient ->
                val selected = recipient.id in selectedIds
                RecipientSelectRow(
                    recipient = recipient,
                    selected = selected,
                    onToggle = { onToggle(recipient.id) },
                )
            }
        }

        Spacer(modifier = Modifier.height(12.dp))
        RageButton(
            label = androidx.compose.ui.res.pluralStringResource(R.plurals.begin_with_recipients, selectedIds.size, selectedIds.size),
            onClick = onBegin,
            icon = Icons.Outlined.Lock,
            fullWidth = true,
            enabled = selectedIds.isNotEmpty(),
        )
    }
}

@Composable
private fun RecipientSelectRow(
    recipient: Recipient,
    selected: Boolean,
    onToggle: () -> Unit,
) {
    val c = rageColors
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(
                if (selected) c.tile else androidx.compose.ui.graphics.Color.Transparent,
                RoundedCornerShape(8.dp),
            )
            .clickable(onClick = onToggle)
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        SelectionBox(on = selected)
        RecipientPip(kind = recipient.kind)
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = recipient.name,
                style = RageType.rowTitle.copy(fontSize = 14.sp),
                color = c.fgEmphasis,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Mono(
                text = recipient.fingerprint,
                size = 11,
                color = c.fgSecondary,
            )
        }
    }
}

@Composable
private fun ProgressStep(
    rows: List<ProtectRow>,
    processed: Int,
    total: Int,
    complete: Boolean,
    onDone: () -> Unit,
) {
    val c = rageColors
    val progress = if (total == 0) 0f else processed.toFloat() / total.toFloat()
    val failedCount = rows.count { it.status == ItemProtectStatus.Failed }
    val succeededCount = rows.count { it.status == ItemProtectStatus.Done }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(start = 16.dp, end = 16.dp, top = 6.dp, bottom = 16.dp),
    ) {
        LinearProgressIndicator(
            progress = { progress },
            color = c.accent,
            trackColor = c.surfaceSunken,
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = if (complete) {
                if (failedCount == 0) {
                    stringResource(R.string.of_protected, succeededCount, total)
                } else {
                    stringResource(R.string.protected_failed_2, succeededCount, failedCount)
                }
            } else {
                stringResource(R.string.of_protected, processed, total)
            },
            style = RageType.caption.copy(fontSize = 13.sp),
            color = c.fgSecondary,
        )
        Spacer(modifier = Modifier.height(12.dp))

        LazyColumn(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            items(rows, key = { it.item.id }) { row ->
                ProtectProgressRow(row = row)
            }
        }

        if (complete) {
            Spacer(modifier = Modifier.height(12.dp))

            if (failedCount == 0) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(c.surfaceElevated, RoundedCornerShape(10.dp))
                        .border(1.dp, c.border, RoundedCornerShape(10.dp))
                        .padding(horizontal = 14.dp, vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    Icon(
                        imageVector = Icons.Outlined.Check,
                        contentDescription = null,
                        tint = c.success,
                        modifier = Modifier.size(20.dp),
                    )
                    Text(
                        text = stringResource(R.string.all_items_are_now_rage_protected),
                        style = RageType.body.copy(fontSize = 14.sp),
                        color = c.fgEmphasis,
                    )
                }
            }

            Spacer(modifier = Modifier.height(12.dp))
            RageButton(
                label = stringResource(R.string.done),
                onClick = onDone,
                icon = Icons.Outlined.Check,
                fullWidth = true,
            )
        }
    }
}

@Composable
private fun ProtectProgressRow(row: ProtectRow) {
    val c = rageColors
    val (statusIcon, statusTint) = when (row.status) {
        ItemProtectStatus.Pending -> Icons.Outlined.HourglassEmpty to c.fgSecondary
        ItemProtectStatus.Encrypting -> Icons.Outlined.Lock to c.accent
        ItemProtectStatus.Done -> Icons.Outlined.Check to c.success
        ItemProtectStatus.Failed -> Icons.Outlined.Close to c.danger
    }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(c.surface, RoundedCornerShape(8.dp))
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Icon(
            imageVector = statusIcon,
            contentDescription = null,
            tint = statusTint,
            modifier = Modifier.size(16.dp),
        )
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = row.item.name,
                style = RageType.rowTitle.copy(fontSize = 14.sp),
                color = c.fgEmphasis,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            if (row.status == ItemProtectStatus.Failed && row.error != null) {
                Text(
                    text = row.error!!,
                    style = RageType.caption.copy(fontSize = 11.sp),
                    color = c.danger,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
        Text(
            text = when (row.status) {
                ItemProtectStatus.Pending -> "pending"
                ItemProtectStatus.Encrypting -> "encrypting..."
                ItemProtectStatus.Done -> "done"
                ItemProtectStatus.Failed -> "failed"
            },
            style = RageType.caption.copy(fontSize = 11.sp),
            color = statusTint,
        )
    }
}
