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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.DeleteOutline
import androidx.compose.material.icons.outlined.East
import androidx.compose.material.icons.outlined.Devices
import androidx.compose.material.icons.outlined.Edit
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.automirrored.outlined.KeyboardArrowRight
import androidx.compose.material.icons.outlined.MoreVert
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material.icons.outlined.Visibility
import androidx.compose.material.icons.outlined.VisibilityOff
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.tracing.trace
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import ragewarden.ragedroid.data.BitwardenVaultRepository
import ragewarden.ragedroid.data.Clipboard
import ragewarden.ragedroid.model.Recipient
import ragewarden.ragedroid.model.VaultItem
import ragewarden.ragedroid.jni.generateTotp
import ragewarden.ragedroid.ui.components.AppBar
import ragewarden.ragedroid.ui.components.ButtonVariant
import ragewarden.ragedroid.ui.components.CopyButton
import ragewarden.ragedroid.ui.components.Field
import ragewarden.ragedroid.ui.components.IconBtn
import ragewarden.ragedroid.ui.components.InlineTapReveal
import ragewarden.ragedroid.ui.components.MasterPasswordConfirm
import ragewarden.ragedroid.ui.components.Mono
import ragewarden.ragedroid.ui.components.MultiIdentityPickerSheet
import ragewarden.ragedroid.ui.components.RageButton
import ragewarden.ragedroid.ui.components.RecipientPip
import ragewarden.ragedroid.ui.components.Sheet
import ragewarden.ragedroid.ui.components.TapAction
import ragewarden.ragedroid.ui.components.TapPresentation
import ragewarden.ragedroid.ui.components.TextInput
import ragewarden.ragedroid.identities.HardwareTapCancelledException
import ragewarden.ragedroid.identities.HardwareTapTimeoutException
import ragewarden.ragedroid.identities.HardwareTapUnavailableException
import ragewarden.ragedroid.identities.NoUsableIdentityException
import ragewarden.ragedroid.identities.PinRequest
import ragewarden.ragedroid.identities.StanzaTags
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors

private const val REVEAL_AUTO_CLEAR_SECS = 8

/**
 * Maps a ceremony failure onto the existing [TapFailureKind] full-screen states.
 * Uses the typed exceptions from `HardwareTapErrors.kt` first and only falls
 * back to substring-sniffing the message for errors that came up through the
 * JNI/age layer untyped.
 */
private fun classifyTapFailure(err: Throwable): TapFailureKind = when (err) {
    is HardwareTapTimeoutException -> TapFailureKind.Timeout
    is HardwareTapCancelledException -> TapFailureKind.Cancelled
    is NoUsableIdentityException -> TapFailureKind.NoMatch
    is kotlinx.coroutines.TimeoutCancellationException -> TapFailureKind.Timeout
    else -> {
        val msg = err.message.orEmpty()
        when {
            msg.contains("cancel", ignoreCase = true) -> TapFailureKind.Cancelled
            msg.contains("match", ignoreCase = true) ||
                msg.contains("no identities", ignoreCase = true) -> TapFailureKind.NoMatch
            else -> TapFailureKind.WrongKey
        }
    }
}

@Composable
fun ItemDetailScreen(
    item: VaultItem,
    /**
     * Performs the whole authorized use: gate, hardware ceremony, decrypt.
     * `onlyRecipientIds` narrows it to the key the user picked in
     * [MultiIdentityPickerSheet] -- picking a key used to print a toast and then
     * decrypt with every identity on the device anyway.
     *
     * It must **throw** on refusal. Returning a fallback plaintext, or an empty
     * array, is how a hardware requirement turns into a suggestion.
     */
    decryptPassword: suspend (itemId: String, onlyRecipientIds: Set<String>?) -> ByteArray,
    clipboard: Clipboard,
    showToast: (String) -> Unit,
    onBack: () -> Unit,
    onEdit: (() -> Unit)? = null,
    onHistory: (() -> Unit)? = null,
    onTapFailure: ((TapFailureKind) -> Unit)? = null,
    onRotate: (suspend (ByteArray) -> Unit)? = null,
    onDelete: (suspend () -> Unit)? = null,
    repository: BitwardenVaultRepository? = null,
    autoOpenIdentityPicker: Boolean = false,
    onIdentityPickerOpened: () -> Unit = {},
    onSetUpDevice: (() -> Unit)? = null,
    /** What the prompt is allowed to claim about the key. Derived from a real IdentitySet. */
    tapPresentation: TapPresentation = TapPresentation.softwareOnly("this device"),
    /** Pending PIV PIN request from the tap coordinator, if any. */
    pinRequest: PinRequest? = null,
) {
    val c = rageColors

    var tapMode by remember { mutableStateOf<TapMode>(TapMode.Idle) }
    var selectedRecipientIds by remember { mutableStateOf<Set<String>?>(null) }
    var revealedPlaintext by remember { mutableStateOf<ByteArray?>(null) }
    var revealSecsLeft by remember { mutableStateOf(REVEAL_AUTO_CLEAR_SECS) }
    var showSheet by remember { mutableStateOf(false) }
    var identityPickerOpen by remember { mutableStateOf(false) }
    var pendingTapAction by remember { mutableStateOf<TapAction?>(null) }
    var deleteConfirmOpen by remember { mutableStateOf(false) }
    var deletePwOpen by remember { mutableStateOf(false) }
    var deleting by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val uriHandler = LocalUriHandler.current

    val liveRecipients = ragewarden.ragedroid.ui.LocalLiveRecipients.current
    // `item.recipients` carries stanza descriptors parsed from the blob's own age
    // header, not recipient ids -- see data/RecipientDescriptors.kt. Matching by
    // descriptor is what makes this list non-empty for real protected items; it
    // used to be matched against the literal id "software-demo" and was
    // therefore always empty, which routed every protected item to the
    // "Set up this device" card instead of the reveal controls.
    val recipients: List<Recipient> = remember(item.id, item.recipients, liveRecipients) {
        val descriptorSet = item.recipients.toSet()
        liveRecipients.filter { r -> r.descriptors.any { it in descriptorSet } }
    }
    /** X25519/scrypt stanzas: real recipients the header cannot name. */
    val anonymousRecipientCount = remember(item.recipients) {
        item.recipients.count { it == StanzaTags.X25519 || it == StanzaTags.SCRYPT }
    }

    LaunchedEffect(item.id, autoOpenIdentityPicker) {
        if (autoOpenIdentityPicker && item.rage && recipients.size > 1) {
            identityPickerOpen = true
            onIdentityPickerOpened()
        }
    }

    LaunchedEffect(revealedPlaintext) {
        val pt = revealedPlaintext ?: return@LaunchedEffect
        revealSecsLeft = REVEAL_AUTO_CLEAR_SECS
        while (revealSecsLeft > 0) {
            delay(1000)
            revealSecsLeft -= 1
        }
        pt.fill(0)
        revealedPlaintext = null
        tapMode = TapMode.Idle
        showToast("Password cleared from screen")
    }

    DisposableEffect(item.id) {
        onDispose {
            revealedPlaintext?.fill(0)
        }
    }

    // NOTE: the prompt's label now comes from `tapPresentation`, which is built
    // from the live IdentitySet, not from whatever happens to be first in this
    // display list (and certainly not from the string "Software identity",
    // which two of three call sites used to hardcode).

    Column(modifier = Modifier.fillMaxSize().background(c.background)) {
        AppBar(
            title = item.name,
            subtitle = item.site.ifBlank { null },
            leading = {
                IconBtn(
                    icon = Icons.AutoMirrored.Outlined.ArrowBack,
                    contentDescription = "Back",
                    onClick = onBack,
                )
            },
            trailing = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    if (onEdit != null) {
                        IconBtn(
                            icon = Icons.Outlined.Edit,
                            contentDescription = "Edit",
                            onClick = onEdit,
                        )
                    }
                    IconBtn(
                        icon = Icons.Outlined.MoreVert,
                        contentDescription = "More actions",
                        onClick = { showSheet = true },
                    )
                }
            },
        )

        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 16.dp, vertical = 12.dp),
        ) {
            item("username") {
                Field(label = "Username") {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(c.surfaceSunken, RoundedCornerShape(8.dp))
                            .border(1.dp, c.border, RoundedCornerShape(8.dp))
                            .padding(horizontal = 12.dp, vertical = 10.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Text(
                            text = item.username,
                            style = RageType.sansBody,
                            color = c.fgPrimary,
                            modifier = Modifier.weight(1f),
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                        CopyButton(
                            onCopy = {
                                clipboard.copyVisible(item.username, "username")
                                showToast("Username copied")
                            },
                            compact = true,
                        )
                    }
                }
            }

            item("password") {
                Field(
                    label = "Password",
                    hint = if (!item.rage) "This item is not protected by Ragewarden." else null,
                ) {
                    when {
                        revealedPlaintext != null -> {
                            RevealedPasswordCard(
                                plaintext = String(revealedPlaintext!!, Charsets.UTF_8),
                                secsLeft = revealSecsLeft,
                                onHide = {
                                    revealedPlaintext?.fill(0)
                                    revealedPlaintext = null
                                    tapMode = TapMode.Idle
                                },
                            )
                        }
                        tapMode is TapMode.Rotating -> {
                            InlineTapReveal(
                                itemName = item.name,
                                itemSite = item.site.ifBlank { null },
                                presentation = tapPresentation,
                                initialAction = TapAction.Reveal,
                                pinRequest = pinRequest,
                                // Suspends for the whole ceremony. Any throw lands
                                // in InlineTapReveal's Failed phase with a named
                                // reason instead of a toast the user can miss.
                                onAuthorize = {
                                    val plaintext = withContext(Dispatchers.IO) {
                                        trace("ragewarden.decrypt") {
                                            decryptPassword(item.id, selectedRecipientIds)
                                        }
                                    }
                                    val rotateFn = onRotate
                                    if (rotateFn == null) {
                                        plaintext.fill(0)
                                        tapMode = TapMode.Idle
                                    } else {
                                        try {
                                            rotateFn(plaintext)
                                        } finally {
                                            plaintext.fill(0)
                                        }
                                        // Only on success. Leaving tapMode alone on
                                        // failure keeps InlineTapReveal composed so
                                        // its Failed phase can render -- clearing it
                                        // here would unmount the component and
                                        // cancel the effect that reports the error.
                                        showToast("Rotated to current recipients")
                                        tapMode = TapMode.Idle
                                    }
                                },
                                onCancel = { tapMode = TapMode.Idle },
                            )
                        }
                        tapMode is TapMode.Active -> {
                            InlineTapReveal(
                                itemName = item.name,
                                itemSite = item.site.ifBlank { null },
                                presentation = tapPresentation,
                                initialAction = (tapMode as TapMode.Active).preselected,
                                pinRequest = pinRequest,
                                onAuthorize = { action ->
                                    val plaintext = try {
                                        withContext(Dispatchers.IO) {
                                            trace("ragewarden.decrypt") {
                                                decryptPassword(item.id, selectedRecipientIds)
                                            }
                                        }
                                    } catch (err: Throwable) {
                                        // "Nothing here can open this" carries
                                        // per-recipient detail the full-screen
                                        // failure states cannot show, so keep it
                                        // inline. Everything else goes to the
                                        // existing TapFailure screen.
                                        val inlineOnly = err is NoUsableIdentityException ||
                                            err is HardwareTapUnavailableException
                                        if (onTapFailure != null && !inlineOnly) {
                                            tapMode = TapMode.Idle
                                            onTapFailure(classifyTapFailure(err))
                                        }
                                        throw err
                                    }
                                    when (action) {
                                        TapAction.Autofill -> {
                                            clipboard.copySensitive(plaintext, "password")
                                            plaintext.fill(0)
                                            tapMode = TapMode.Idle
                                            showToast(
                                                "Copied · paste into ${item.site.ifBlank { item.name }}. " +
                                                    "Tap the Ragewarden chip on the field for direct autofill.",
                                            )
                                        }
                                        TapAction.Copy -> {
                                            clipboard.copySensitive(plaintext, "password")
                                            plaintext.fill(0)
                                            tapMode = TapMode.Idle
                                            showToast("Copied · clears in 30s")
                                        }
                                        TapAction.Reveal -> {
                                            revealedPlaintext = plaintext
                                            tapMode = TapMode.Idle
                                        }
                                    }
                                },
                                onCancel = { tapMode = TapMode.Idle },
                            )
                        }
                        item.rage && recipients.isEmpty() && onSetUpDevice != null -> {
                            NeedsSetupCard(
                                firstDevice = liveRecipients.isEmpty(),
                                onSetUpDevice = onSetUpDevice,
                            )
                        }
                        else -> {
                            IdlePasswordCard(
                                onChooseAction = { action ->
                                    if (item.rage) {
                                        if (recipients.size > 1) {
                                            pendingTapAction = action
                                            identityPickerOpen = true
                                        } else {
                                            tapMode = TapMode.Active(preselected = action)
                                        }
                                    } else {
                                        when (action) {
                                            TapAction.Autofill -> {
                                                val pw = item.password.toByteArray(Charsets.UTF_8)
                                                clipboard.copySensitive(pw, "password")
                                                pw.fill(0)
                                                showToast(
                                                    "Copied · paste into ${item.site.ifBlank { item.name }}. " +
                                                        "Tap the Ragewarden chip on the field for direct autofill.",
                                                )
                                            }
                                            TapAction.Copy -> {
                                                val pw = item.password.toByteArray(Charsets.UTF_8)
                                                clipboard.copySensitive(pw, "password")
                                                pw.fill(0)
                                                showToast("Copied · clears in 30s")
                                            }
                                            TapAction.Reveal -> {
                                                revealedPlaintext = item.password.toByteArray(Charsets.UTF_8)
                                            }
                                        }
                                    }
                                },
                            )
                        }
                    }
                }
            }

            if (item.totpSeed != null) {
                item("totp") {
                    Field(label = "TOTP", hint = "Code refreshes every 30s.") {
                        TotpCard(
                            seed = item.totpSeed,
                            onCopy = { code ->
                                val bytes = code.toByteArray(Charsets.UTF_8)
                                clipboard.copySensitive(bytes, "totp")
                                bytes.fill(0)
                                showToast("TOTP copied · clears in 30s")
                            },
                        )
                    }
                }
            }

            if (item.notes != null) {
                item("notes") {
                    Field(label = "Notes") {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(c.surfaceSunken, RoundedCornerShape(8.dp))
                                .border(1.dp, c.border, RoundedCornerShape(8.dp))
                                .padding(horizontal = 12.dp, vertical = 10.dp),
                        ) {
                            Text(
                                text = item.notes,
                                style = RageType.body,
                                color = c.fgPrimary,
                            )
                        }
                    }
                }
            }

            if (item.rage && (recipients.isNotEmpty() || anonymousRecipientCount > 0)) {
                item("recipients") {
                    Field(
                        label = "Unlock recipients",
                        hint = if (anonymousRecipientCount > 0) {
                            "Any one of these can decrypt this secret. " +
                                "$anonymousRecipientCount software or paper recipient(s) are also " +
                                "wrapped in -- age headers do not name those, so they cannot be listed."
                        } else {
                            "Any one of these can decrypt this secret."
                        },
                    ) {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(c.surface, RoundedCornerShape(8.dp))
                                .border(1.dp, c.border, RoundedCornerShape(8.dp)),
                        ) {
                            recipients.forEachIndexed { index, recipient ->
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(horizontal = 12.dp, vertical = 10.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                                ) {
                                    RecipientPip(kind = recipient.kind)
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(
                                            text = recipient.name,
                                            style = RageType.sansBody,
                                            color = c.fgPrimary,
                                        )
                                        Mono(
                                            text = recipient.fingerprint,
                                            size = 11,
                                            color = c.fgSecondary,
                                        )
                                    }
                                }
                                if (index < recipients.size - 1) {
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
            }

            item("meta") {
                Spacer(modifier = Modifier.height(4.dp))
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(c.surfaceSunken, RoundedCornerShape(8.dp))
                        .padding(horizontal = 14.dp, vertical = 12.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "LAST USED",
                            style = RageType.eyebrow,
                            color = c.fgSecondary,
                        )
                        Text(
                            text = item.lastUsed,
                            style = RageType.sansBody,
                            color = c.fgPrimary,
                        )
                    }
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "HISTORY",
                            style = RageType.eyebrow,
                            color = c.fgSecondary,
                        )
                        Text(
                            text = "${item.history} versions",
                            style = RageType.sansBody,
                            color = c.fgPrimary,
                        )
                    }
                }
                Spacer(modifier = Modifier.height(40.dp))
            }
        }
    }

    Sheet(open = showSheet, onDismiss = { showSheet = false }, title = "More actions") {
        SheetActions(
            includeLaunchWebsite = item.site.isNotBlank(),
            includeRotate = item.rage && onRotate != null,
            includeHistory = onHistory != null,
            // No repository means no master-password gate can be built, so the
            // delete affordance is withheld rather than shown ungated.
            includeDelete = onDelete != null && repository != null,
            onAction = { label ->
                showSheet = false
                when (label) {
                    "Launch website" -> {
                        val raw = item.site.trim()
                        val target = if (raw.contains("://")) raw else "https://$raw"
                        runCatching { uriHandler.openUri(target) }
                            .onFailure { e -> showToast("Couldn't open $target: ${e.message}") }
                    }
                    "Rotate to current recipients" -> {
                        if (recipients.size > 1) {
                            pendingTapAction = null
                            identityPickerOpen = true
                            tapMode = TapMode.Rotating
                        } else {
                            tapMode = TapMode.Rotating
                        }
                    }
                    "View history" -> onHistory?.invoke()
                    "Edit recipients" -> identityPickerOpen = true
                    "Delete item" -> deleteConfirmOpen = true
                }
            },
        )
    }

    DeleteConfirmSheet(
        open = deleteConfirmOpen,
        item = item,
        onClose = { deleteConfirmOpen = false },
        onConfirm = {
            deleteConfirmOpen = false
            deletePwOpen = true
        },
    )

    if (repository != null) {
        MasterPasswordConfirm(
            open = deletePwOpen,
            onClose = { deletePwOpen = false },
            title = "Delete \"${item.name}\"?",
            body = if (item.rage) {
                "RageDroid-protected items are removed for good. Confirm with your master password to continue."
            } else {
                "The server keeps a 30-day soft-delete window. Confirm with your master password to continue."
            },
            action = if (item.rage) "Delete permanently" else "Delete",
            danger = true,
            repository = repository,
            onConfirm = {
                val handler = onDelete ?: return@MasterPasswordConfirm
                if (deleting) return@MasterPasswordConfirm
                deleting = true
                scope.launch {
                    runCatching { handler() }
                        .onSuccess { showToast("Deleted \"${item.name}\"") }
                        .onFailure { e -> showToast("Delete failed: ${e.message}") }
                    deleting = false
                }
            },
        )
    }

    MultiIdentityPickerSheet(
        open = identityPickerOpen,
        item = item,
        onPick = { recipient ->
            identityPickerOpen = false
            val action = pendingTapAction
            pendingTapAction = null
            // Actually restrict the decrypt to the chosen key. Previously this
            // only showed "Using <name>" and then handed every identity on the
            // device to age, so the pick was cosmetic.
            selectedRecipientIds = setOf(recipient.id)
            showToast("Using ${recipient.name}")
            if (action != null) {
                tapMode = TapMode.Active(preselected = action)
            }
        },
        onClose = {
            identityPickerOpen = false
            pendingTapAction = null
            selectedRecipientIds = null
            if (tapMode is TapMode.Rotating) {
                tapMode = TapMode.Idle
            }
        },
    )
}

@Composable
private fun SheetActions(
    includeLaunchWebsite: Boolean = false,
    includeRotate: Boolean = false,
    includeHistory: Boolean = false,
    includeDelete: Boolean = false,
    onAction: (String) -> Unit,
) {
    val c = rageColors
    data class ActionRow(val label: String, val icon: ImageVector, val danger: Boolean = false)
    val rows = buildList {
        if (includeLaunchWebsite) {
            add(ActionRow("Launch website", Icons.Outlined.East))
        }
        add(ActionRow("Edit recipients", Icons.Outlined.MoreVert))
        if (includeRotate) {
            add(ActionRow("Rotate to current recipients", Icons.Outlined.Refresh))
        }
        if (includeHistory) {
            add(ActionRow("View history", Icons.Outlined.MoreVert))
        }
        if (includeDelete) {
            add(ActionRow("Delete item", Icons.Outlined.DeleteOutline, danger = true))
        }
    }
    Column(modifier = Modifier.fillMaxWidth()) {
        rows.forEachIndexed { i, row ->
            val tint = if (row.danger) c.dangerStrong else c.fgPrimary
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { onAction(row.label) }
                    .padding(vertical = 12.dp, horizontal = 4.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Icon(
                    imageVector = row.icon,
                    contentDescription = null,
                    tint = tint,
                    modifier = Modifier.size(18.dp),
                )
                Text(text = row.label, style = RageType.sansBody, color = tint)
            }
            if (i < rows.size - 1) {
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

@Composable
private fun DeleteConfirmSheet(
    open: Boolean,
    item: VaultItem,
    onClose: () -> Unit,
    onConfirm: () -> Unit,
) {
    val c = rageColors
    var typed by remember(open) { mutableStateOf("") }
    val protectedItem = item.rage
    val expected = item.name
    val ok = !protectedItem || typed.trim().equals(expected.trim(), ignoreCase = true)

    Sheet(open = open, onDismiss = onClose, title = "Delete this item?") {
        Column(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(c.surface, RoundedCornerShape(10.dp))
                    .border(1.dp, c.border, RoundedCornerShape(10.dp))
                    .padding(horizontal = 14.dp, vertical = 14.dp),
            ) {
                Text(
                    text = item.name,
                    style = RageType.rowTitle,
                    color = c.fgEmphasis,
                )
                Spacer(modifier = Modifier.height(2.dp))
                Text(
                    text = item.username.ifBlank { item.site.ifBlank { "--" } },
                    style = RageType.caption,
                    color = c.fgSecondary,
                )
            }
            Spacer(modifier = Modifier.height(14.dp))
            Text(
                text = if (protectedItem) {
                    "This item is RageDroid-protected. Deleting it removes every encrypted version from the server. There is no undo."
                } else {
                    "The server keeps a 30-day soft-delete. You can restore it from the trash within that window."
                },
                style = RageType.body,
                color = c.fgPrimary,
            )
            Spacer(modifier = Modifier.height(14.dp))
            if (protectedItem) {
                Field(label = "Type \"$expected\" to confirm") {
                    TextInput(
                        value = typed,
                        onValueChange = { typed = it },
                        placeholder = expected,
                    )
                }
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                RageButton(
                    label = "Cancel",
                    onClick = onClose,
                    variant = ButtonVariant.Secondary,
                )
                RageButton(
                    label = if (protectedItem) "Delete permanently" else "Delete",
                    onClick = { if (ok) onConfirm() },
                    variant = ButtonVariant.Danger,
                    enabled = ok,
                    icon = Icons.Outlined.DeleteOutline,
                    modifier = Modifier.weight(1f),
                    fullWidth = true,
                )
            }
        }
    }
}

private sealed interface TapMode {
    data object Idle : TapMode
    data class Active(val preselected: TapAction) : TapMode

    data object Rotating : TapMode
}

@Composable
private fun NeedsSetupCard(
    firstDevice: Boolean,
    onSetUpDevice: () -> Unit,
) {
    val c = rageColors
    val title = if (firstDevice) {
        "Set up this device"
    } else {
        "This item was protected on another device"
    }
    val body = if (firstDevice) {
        "You haven't enrolled any keys on this device yet. Set this device up -- ideally " +
            "from one that already has access to your vault -- and protected items will open here."
    } else {
        "None of the keys on this device are recipients for this item. Add one of this " +
            "device's keys to the recipient set from a device that already has access; " +
            "the next sync re-encrypts to include it."
    }
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(c.surfaceSunken, RoundedCornerShape(8.dp))
            .border(1.dp, c.border, RoundedCornerShape(8.dp))
            .padding(horizontal = 14.dp, vertical = 14.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Icon(
                imageVector = Icons.Outlined.Devices,
                contentDescription = null,
                tint = c.accent,
                modifier = Modifier.size(20.dp),
            )
            Text(
                text = title,
                style = RageType.rowTitle,
                color = c.fgEmphasis,
            )
        }
        Text(
            text = body,
            style = RageType.body,
            color = c.fgSecondary,
        )
        RageButton(
            label = "Set up this device",
            onClick = onSetUpDevice,
            icon = Icons.Outlined.Key,
            fullWidth = true,
            variant = ButtonVariant.Primary,
        )
    }
}

@Composable
private fun IdlePasswordCard(
    onChooseAction: (TapAction) -> Unit,
) {
    val c = rageColors
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(c.surfaceSunken, RoundedCornerShape(8.dp))
            .border(1.dp, c.border, RoundedCornerShape(8.dp))
            .padding(horizontal = 12.dp, vertical = 10.dp),
    ) {
        Mono(
            text = "••••••••••••",
            color = c.fgSecondary,
            size = 16,
        )
        Spacer(modifier = Modifier.height(10.dp))
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            ActionButton(
                action = TapAction.Autofill,
                accent = true,
                modifier = Modifier.weight(1f),
                onClick = { onChooseAction(TapAction.Autofill) },
            )
            ActionButton(
                action = TapAction.Copy,
                accent = false,
                modifier = Modifier.weight(1f),
                onClick = { onChooseAction(TapAction.Copy) },
            )
            ActionButton(
                action = TapAction.Reveal,
                accent = false,
                modifier = Modifier.weight(1f),
                onClick = { onChooseAction(TapAction.Reveal) },
            )
        }
    }
}

@Composable
private fun ActionButton(
    action: TapAction,
    accent: Boolean,
    modifier: Modifier,
    onClick: () -> Unit,
) {
    val c = rageColors
    val bg = if (accent) c.accent else c.surfaceElevated
    val fg = if (accent) c.background else c.fgPrimary
    val borderColor = if (accent) c.accent else c.border
    val (icon, label) = actionMetadata(action)
    Column(
        modifier = modifier
            .background(bg, RoundedCornerShape(8.dp))
            .border(1.dp, borderColor, RoundedCornerShape(8.dp))
            .clickable(onClick = onClick)
            .padding(horizontal = 6.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Icon(imageVector = icon, contentDescription = null, tint = fg, modifier = Modifier.size(16.dp))
        Text(text = label, style = RageType.button, color = fg)
    }
}

private fun actionMetadata(action: TapAction): Pair<ImageVector, String> = when (action) {
    TapAction.Autofill -> Icons.Outlined.East to "Autofill"
    TapAction.Copy -> Icons.Outlined.ContentCopy to "Copy"
    TapAction.Reveal -> Icons.Outlined.Visibility to "Reveal"
}

@Composable
private fun RevealedPasswordCard(
    plaintext: String,
    secsLeft: Int,
    onHide: () -> Unit,
) {
    val c = rageColors
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(c.surfaceElevated, RoundedCornerShape(10.dp))
            .border(1.dp, c.success, RoundedCornerShape(10.dp))
            .padding(horizontal = 14.dp, vertical = 12.dp),
    ) {
        Mono(
            text = plaintext,
            size = 14,
            color = c.fgEmphasis,
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(modifier = Modifier.height(8.dp))
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(1.dp)
                .background(c.divider),
        )
        Spacer(modifier = Modifier.height(8.dp))
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                Box(
                    modifier = Modifier
                        .size(6.dp)
                        .background(c.success, RoundedCornerShape(50)),
                )
                Text(
                    text = "Auto-clear in ${secsLeft}s",
                    style = RageType.meta,
                    color = c.fgSecondary,
                )
            }
            Row(
                modifier = Modifier
                    .background(c.surface, RoundedCornerShape(6.dp))
                    .border(1.dp, c.border, RoundedCornerShape(6.dp))
                    .clickable(onClick = onHide)
                    .padding(horizontal = 8.dp, vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Icon(
                    imageVector = Icons.Outlined.VisibilityOff,
                    contentDescription = null,
                    tint = c.fgPrimary,
                    modifier = Modifier.size(13.dp),
                )
                Text(text = "Hide", style = RageType.caption, color = c.fgPrimary)
            }
        }
    }
}

@Composable
private fun TotpCard(
    seed: String,
    onCopy: (String) -> Unit,
) {
    val c = rageColors
    var code by remember { mutableStateOf("------") }
    var secsLeft by remember { mutableStateOf(30) }
    var period by remember { mutableStateOf(30) }

    LaunchedEffect(seed) {
        while (true) {
            val tc = withContext(Dispatchers.Default) {
                runCatching { trace("ragewarden.totp") { generateTotp(seed) } }.getOrNull()
            }
            if (tc == null) {
                code = "ERROR"
                secsLeft = 0
                break
            }
            code = tc.code
            secsLeft = tc.secondsRemaining
            period = tc.period
            delay(1000)
        }
    }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(c.surfaceSunken, RoundedCornerShape(8.dp))
            .border(1.dp, c.border, RoundedCornerShape(8.dp))
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Mono(text = code, size = 18, color = c.fgEmphasis)
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                text = "${secsLeft}s",
                style = RageType.meta,
                color = c.fgSecondary,
            )
            Box(
                modifier = Modifier
                    .background(c.surface, RoundedCornerShape(6.dp))
                    .border(1.dp, c.border, RoundedCornerShape(6.dp))
                    .clickable { onCopy(code) }
                    .padding(horizontal = 8.dp, vertical = 4.dp),
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    Icon(
                        imageVector = Icons.Outlined.ContentCopy,
                        contentDescription = null,
                        tint = c.fgPrimary,
                        modifier = Modifier.size(13.dp),
                    )
                    Text(text = "Copy", style = RageType.caption, color = c.fgPrimary)
                }
            }
        }
    }
}
