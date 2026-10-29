package ragewarden.ragedroid.ui.screens

import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import kotlinx.collections.immutable.toImmutableList
import ragewarden.ragedroid.R
import ragewarden.ragedroid.data.VaultBridge
import ragewarden.ragedroid.di.appEntryPoint
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
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.DeleteOutline
import androidx.compose.material.icons.outlined.East
import androidx.compose.material.icons.outlined.Devices
import androidx.compose.material.icons.outlined.Edit
import androidx.compose.material.icons.outlined.Key
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
import ragewarden.ragedroid.ui.components.BackButton
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
import ragewarden.ragedroid.ui.uiString

private const val REVEAL_AUTO_CLEAR_SECS = 8

/**
 * Maps a ceremony failure onto the existing [TapFailureKind] full-screen states.
 * Uses the typed exceptions from `HardwareTapErrors.kt` first and only falls
 * back to substring-sniffing the message for errors that came up through the
 * JNI/age layer untyped.
 */
internal fun classifyTapFailure(err: Throwable): TapFailureKind = when (err) {
    is HardwareTapTimeoutException -> TapFailureKind.Timeout
    is HardwareTapCancelledException -> TapFailureKind.Cancelled
    is ragewarden.ragedroid.identities.HardwareTapWrongKeyException -> TapFailureKind.WrongKey
    is NoUsableIdentityException -> TapFailureKind.NoMatch
    is kotlinx.coroutines.TimeoutCancellationException -> TapFailureKind.Timeout
    else -> {
        val msg = err.message.orEmpty()
        when {
            msg.contains("cancel", ignoreCase = true) -> TapFailureKind.Cancelled
            msg.contains("no matching identity", ignoreCase = true) -> TapFailureKind.NoMatch
            msg.contains("wrong key", ignoreCase = true) ||
                msg.contains("not a recipient", ignoreCase = true) ||
                msg.contains("unwrap", ignoreCase = true) -> TapFailureKind.WrongKey
            else -> TapFailureKind.Unknown
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
    decryptPassword: suspend (itemId: String, onlyRecipientIds: Set<String>?, purpose: String, use: ragewarden.ragedroid.data.audit.AuditAction?) -> ByteArray,
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
    tapPresentation: TapPresentation = TapPresentation.softwareOnly(uiString(R.string.this_device_2)),
    /** Pending PIV PIN request from the tap coordinator, if any. */
    pinRequest: PinRequest? = null,
    /** One protected field other than the password (a TOTP seed, notes), behind its own tap. */
    decryptField: (suspend (field: String) -> ByteArray)? = null,
) {
    val strings = androidx.compose.ui.platform.LocalContext.current
    val c = rageColors

    var tapMode by remember { mutableStateOf<TapMode>(TapMode.Idle) }
    var selectedRecipientIds by remember { mutableStateOf<Set<String>?>(null) }
    var revealedPlaintext by remember { mutableStateOf<ByteArray?>(null) }
    // Protected login fields other than the password (another client may have
    // protected the TOTP seed or the notes), opened one at a time.
    val protectedFields = remember(item.id, item.protectedFields, item.rage) {
        ragewarden.ragedroid.data.ItemFields.protectedFields(item).filter { it == "totp" || it == "notes" }.toSet()
    }
    val openedFields = androidx.compose.runtime.remember(item.id) { androidx.compose.runtime.mutableStateMapOf<String, String>() }
    val fieldScope = androidx.compose.runtime.rememberCoroutineScope()
    val fieldContext = androidx.compose.ui.platform.LocalContext.current
    val openField: (String) -> Unit = { field ->
        val decrypt = decryptField
        if (decrypt != null) {
            fieldScope.launch {
                runCatching { decrypt(field) }
                    .onSuccess { b ->
                        openedFields[field] = String(b, Charsets.UTF_8)
                        b.fill(0)
                    }
                    .onFailure { e -> showToast(fieldContext.getString(R.string.not_opened, e.message ?: "")) }
            }
        }
    }
    // Text on screen needs a String; this is the one made per reveal.
    val revealedText = remember(revealedPlaintext) { revealedPlaintext?.let { String(it, Charsets.UTF_8) } }
    var revealSecsLeft by remember { mutableStateOf(REVEAL_AUTO_CLEAR_SECS) }
    var showSheet by remember { mutableStateOf(false) }
    val liveRecipientsForWraps = ragewarden.ragedroid.ui.LocalLiveRecipients.current
    val legacyWraps = remember(item.id, item.recipients, liveRecipientsForWraps) {
        if (item.rage) {
            (repository?.legacyPrfWraps(item.id) ?: 0) +
                ragewarden.ragedroid.data.RecipientDescriptors.movedPasskeyWraps(item.recipients, liveRecipientsForWraps)
        } else {
            0
        }
    }
    var folderChoices by remember { mutableStateOf<kotlinx.collections.immutable.ImmutableList<ragewarden.ragedroid.ui.components.FolderOption>?>(null) }
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
        showToast(strings.getString(R.string.password_cleared_from_screen))
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
            leading = { BackButton(onBack) },
            trailing = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    if (onEdit != null) {
                        IconBtn(
                            icon = Icons.Outlined.Edit,
                            contentDescription = stringResource(R.string.edit),
                            onClick = onEdit,
                        )
                    }
                    IconBtn(
                        icon = Icons.Outlined.MoreVert,
                        contentDescription = stringResource(R.string.more_actions),
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
                Field(label = stringResource(R.string.username)) {
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
                                showToast(strings.getString(R.string.username_copied))
                            },
                            compact = true,
                        )
                    }
                }
            }

            item("password") {
                Field(
                    label = stringResource(R.string.password),
                    hint = if (!item.rage) stringResource(R.string.this_item_is_not_protected_by) else null,
                ) {
                    when {
                        revealedPlaintext != null -> {
                            RevealedPasswordCard(
                                plaintext = revealedText.orEmpty(),
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
                                            decryptPassword(item.id, selectedRecipientIds, uiString(R.string.re_encrypt_to_the_current_keys, item.name), null)
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
                                        showToast(strings.getString(R.string.rotated_to_current_recipients))
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
                                copiesForAutofill = true,
                                onAuthorize = { action ->
                                    val plaintext = try {
                                        withContext(Dispatchers.IO) {
                                            trace("ragewarden.decrypt") {
                                                decryptPassword(item.id, selectedRecipientIds, tapPurpose(action, item.name), if (action == TapAction.Reveal) ragewarden.ragedroid.data.audit.AuditAction.Reveal else ragewarden.ragedroid.data.audit.AuditAction.Copy)
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
                                            clipboard.copySensitive(plaintext, "password", audit = null)
                                            plaintext.fill(0)
                                            tapMode = TapMode.Idle
                                            showToast(
                                                uiString(R.string.copied_paste_into_tap_the_ragewarden, item.site.ifBlank { item.name }),
                                            )
                                        }
                                        TapAction.Copy -> {
                                            clipboard.copySensitive(plaintext, "password", audit = null)
                                            plaintext.fill(0)
                                            tapMode = TapMode.Idle
                                            showToast(strings.getString(R.string.copied_clears_in_30s))
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
                                                clipboard.copySensitive(pw, "password", item = item.name)
                                                pw.fill(0)
                                                showToast(
                                                    uiString(R.string.copied_paste_into_tap_the_ragewarden, item.site.ifBlank { item.name }),
                                                )
                                            }
                                            TapAction.Copy -> {
                                                val pw = item.password.toByteArray(Charsets.UTF_8)
                                                clipboard.copySensitive(pw, "password", item = item.name)
                                                pw.fill(0)
                                                showToast(strings.getString(R.string.copied_clears_in_30s))
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

            if (item.totpSeed != null || "totp" in protectedFields) {
                item("totp") {
                    Field(label = stringResource(R.string.totp), hint = stringResource(R.string.code_refreshes_every_30s)) {
                        val seed = item.totpSeed ?: openedFields["totp"]
                        if (seed == null) {
                            OpenProtectedFieldButton(
                                label = stringResource(R.string.show_totp_codes),
                                enabled = decryptField != null,
                                onOpen = { openField("totp") },
                            )
                            return@Field
                        }
                        TotpCard(
                            seed = seed,
                            onCopy = { code ->
                                val bytes = code.toByteArray(Charsets.UTF_8)
                                clipboard.copySensitive(bytes, "totp", audit = ragewarden.ragedroid.data.audit.AuditAction.Totp, item = item.name)
                                bytes.fill(0)
                                showToast(strings.getString(R.string.totp_copied_clears_in_30s))
                            },
                        )
                    }
                }
            }

            if (item.notes != null || "notes" in protectedFields) {
                item("notes") {
                    Field(label = stringResource(R.string.notes)) {
                        val noteText = item.notes ?: openedFields["notes"]
                        if (noteText == null) {
                            OpenProtectedFieldButton(
                                label = stringResource(R.string.open_note),
                                enabled = decryptField != null,
                                onOpen = { openField("notes") },
                            )
                            return@Field
                        }
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(c.surfaceSunken, RoundedCornerShape(8.dp))
                                .border(1.dp, c.border, RoundedCornerShape(8.dp))
                                .padding(horizontal = 12.dp, vertical = 10.dp),
                        ) {
                            Text(
                                text = noteText,
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
                        label = stringResource(R.string.unlock_recipients),
                        hint = if (anonymousRecipientCount > 0) {
                            stringResource(R.string.any_one_of_these_can_open_2, anonymousRecipientCount)
                        } else {
                            stringResource(R.string.any_one_of_these_can_decrypt_3)
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
                val metaContext = androidx.compose.ui.platform.LocalContext.current
                val (lastUsedText, historyCount) = remember(item.id, item.name) {
                    val entry = runCatching { metaContext.appEntryPoint() }.getOrNull()
                    val account = VaultBridge.repository()?.accountId.orEmpty()
                    val last = entry?.let { e ->
                        runCatching { e.auditFeed().list().firstOrNull { it.item == item.name } }.getOrNull()
                    }?.let { "${it.bucket} ${it.timestamp}".trim() }
                    val revisions = entry?.takeIf { account.isNotBlank() }?.let { e ->
                        runCatching { e.historyStore().forItem(account, item.id).size }.getOrNull()
                    }
                    last to revisions
                }
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
                            text = stringResource(R.string.last_used),
                            style = RageType.eyebrow,
                            color = c.fgSecondary,
                        )
                        Text(
                            text = lastUsedText ?: stringResource(R.string.not_used_on_this_phone),
                            style = RageType.sansBody,
                            color = c.fgPrimary,
                        )
                    }
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = stringResource(R.string.history),
                            style = RageType.eyebrow,
                            color = c.fgSecondary,
                        )
                        Text(
                            text = when (historyCount) {
                                null -> stringResource(R.string.no_local_history)
                                else -> androidx.compose.ui.res.pluralStringResource(R.plurals.version_count, historyCount, historyCount)
                            },
                            style = RageType.sansBody,
                            color = c.fgPrimary,
                        )
                    }
                }
                Spacer(modifier = Modifier.height(40.dp))
            }
        }
    }

    Sheet(open = showSheet, onDismiss = { showSheet = false }, title = stringResource(R.string.more_actions)) {
        SheetActions(
            includeLaunchWebsite = item.site.isNotBlank(),
            includeRotate = item.rage && onRotate != null,
            rotateLabel = if (legacyWraps > 0) androidx.compose.ui.res.pluralStringResource(R.plurals.re_encrypt_renews_passkey_wraps, legacyWraps, legacyWraps) else stringResource(R.string.re_encrypt_to_current_keys),
            includeHistory = onHistory != null,
            // No repository means no master-password gate can be built, so the
            // delete affordance is withheld rather than shown ungated.
            includeDelete = onDelete != null && repository != null,
            includeChooseKey = recipients.size > 1,
            includeMove = repository != null,
            onAction = { action ->
                showSheet = false
                when (action) {
                    ItemSheetAction.LaunchWebsite -> {
                        val raw = item.site.trim()
                        val target = if (raw.contains("://")) raw else "https://$raw"
                        runCatching { uriHandler.openUri(target) }
                            .onFailure { e -> showToast(strings.getString(R.string.couldn_t_open, target, e.message ?: strings.getString(R.string.unknown_error))) }
                    }
                    ItemSheetAction.Rotate -> {
                        if (recipients.size > 1) {
                            pendingTapAction = null
                            identityPickerOpen = true
                            tapMode = TapMode.Rotating
                        } else {
                            tapMode = TapMode.Rotating
                        }
                    }
                    ItemSheetAction.History -> onHistory?.invoke()
                    ItemSheetAction.Move -> scope.launch {
                        folderChoices = repository?.listFolders()?.getOrNull()
                            ?.map { ragewarden.ragedroid.ui.components.FolderOption(it.id, it.name, null) }
                            ?.let { listOf(ragewarden.ragedroid.ui.components.FolderOption(null, uiString(R.string.no_folder), null)) + it }
                            ?.toImmutableList()
                        if (folderChoices == null) showToast(strings.getString(R.string.couldn_t_load_folders))
                    }
                    ItemSheetAction.ChooseKey -> identityPickerOpen = true
                    ItemSheetAction.Delete -> deleteConfirmOpen = true
                }
            },
        )
    }

    folderChoices?.let { choices ->
        ragewarden.ragedroid.ui.components.MoveToFolderSheet(
            open = true,
            onClose = { folderChoices = null },
            folders = choices,
            currentId = item.folderId,
            onPick = { picked ->
                folderChoices = null
                scope.launch {
                    repository?.moveToFolder(item.id, picked.id)
                        ?.onSuccess { showToast(strings.getString(R.string.moved_to, picked.name)) }
                        ?.onFailure { e -> showToast(strings.getString(R.string.not_moved, e.message ?: strings.getString(R.string.unknown_error))) }
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
            title = stringResource(R.string.delete, item.name),
            body = if (item.rage) {
                stringResource(R.string.ragedroid_protected_items_are_removed_for)
            } else {
                stringResource(R.string.the_server_keeps_a_30_day_2)
            },
            action = if (item.rage) stringResource(R.string.delete_permanently) else stringResource(R.string.delete_2),
            danger = true,
            repository = repository,
            onConfirm = {
                val handler = onDelete ?: return@MasterPasswordConfirm
                if (deleting) return@MasterPasswordConfirm
                deleting = true
                scope.launch {
                    runCatching { handler() }
                        .onSuccess { showToast(strings.getString(R.string.deleted, item.name)) }
                        .onFailure { e -> showToast(strings.getString(R.string.delete_failed, e.message ?: strings.getString(R.string.unknown_error))) }
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
            showToast(strings.getString(R.string.using, recipient.name))
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
    includeChooseKey: Boolean = false,
    includeMove: Boolean = false,
    rotateLabel: String = uiString(R.string.re_encrypt_to_current_keys),
    onAction: (ItemSheetAction) -> Unit,
) {
    val c = rageColors
    data class ActionRow(val action: ItemSheetAction, val label: String, val icon: ImageVector, val danger: Boolean = false)
    val rows = buildList {
        if (includeLaunchWebsite) {
            add(ActionRow(ItemSheetAction.LaunchWebsite, stringResource(R.string.launch_website), Icons.Outlined.East))
        }
        if (includeChooseKey) {
            add(ActionRow(ItemSheetAction.ChooseKey, stringResource(R.string.choose_which_key_to_use), Icons.Outlined.MoreVert))
        }
        if (includeMove) {
            add(ActionRow(ItemSheetAction.Move, stringResource(R.string.move_to_folder), Icons.Outlined.MoreVert))
        }
        if (includeRotate) {
            add(ActionRow(ItemSheetAction.Rotate, rotateLabel, Icons.Outlined.Refresh))
        }
        if (includeHistory) {
            add(ActionRow(ItemSheetAction.History, stringResource(R.string.view_history), Icons.Outlined.MoreVert))
        }
        if (includeDelete) {
            add(ActionRow(ItemSheetAction.Delete, stringResource(R.string.delete_item), Icons.Outlined.DeleteOutline, danger = true))
        }
    }
    Column(modifier = Modifier.fillMaxWidth()) {
        rows.forEachIndexed { i, row ->
            val tint = if (row.danger) c.dangerStrong else c.fgPrimary
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { onAction(row.action) }
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

    Sheet(open = open, onDismiss = onClose, title = stringResource(R.string.delete_this_item)) {
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
                    stringResource(R.string.this_item_is_ragedroid_protected_deleting)
                } else {
                    stringResource(R.string.the_server_keeps_a_30_day)
                },
                style = RageType.body,
                color = c.fgPrimary,
            )
            Spacer(modifier = Modifier.height(14.dp))
            if (protectedItem) {
                Field(label = stringResource(R.string.type_to_confirm, expected)) {
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
                    label = stringResource(R.string.cancel),
                    onClick = onClose,
                    variant = ButtonVariant.Secondary,
                )
                RageButton(
                    label = if (protectedItem) stringResource(R.string.delete_permanently) else stringResource(R.string.delete_2),
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
        stringResource(R.string.set_up_this_device)
    } else {
        stringResource(R.string.this_item_was_protected_on_another_2)
    }
    val body = if (firstDevice) {
        stringResource(R.string.you_haven_t_enrolled_any_keys)
    } else {
        stringResource(R.string.none_of_the_keys_on_this)
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
            label = stringResource(R.string.set_up_this_device),
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
            .testTag("action-${action.name.lowercase()}")
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
    TapAction.Autofill -> Icons.Outlined.East to uiString(R.string.copy_for_autofill)
    TapAction.Copy -> Icons.Outlined.ContentCopy to uiString(R.string.copy)
    TapAction.Reveal -> Icons.Outlined.Visibility to uiString(R.string.reveal)
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
                    text = stringResource(R.string.auto_clear_in_s, secsLeft),
                    style = RageType.meta,
                    color = c.fgSecondary,
                )
            }
            Row(
                modifier = Modifier
                    .background(c.surface, RoundedCornerShape(6.dp))
                    .border(1.dp, c.border, RoundedCornerShape(6.dp))
                    .testTag("password-hide")
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
                Text(text = stringResource(R.string.hide), style = RageType.caption, color = c.fgPrimary)
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
                text = stringResource(R.string.seconds_short, secsLeft),
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
                    Text(text = stringResource(R.string.copy), style = RageType.caption, color = c.fgPrimary)
                }
            }
        }
    }
}

internal fun tapPurpose(action: TapAction, itemName: String): String = when (action) {
    TapAction.Autofill -> uiString(R.string.copy_password_for_autofill, itemName)
    TapAction.Copy -> uiString(R.string.copy_password_to_the_clipboard, itemName)
    TapAction.Reveal -> uiString(R.string.show_password_on_screen_for_8, itemName)
}

internal enum class ItemSheetAction { LaunchWebsite, ChooseKey, Move, Rotate, History, Delete }

@Composable
private fun OpenProtectedFieldButton(label: String, enabled: Boolean, onOpen: () -> Unit) {
    ragewarden.ragedroid.ui.components.RageButton(
        label = label,
        onClick = onOpen,
        variant = ragewarden.ragedroid.ui.components.ButtonVariant.Secondary,
        fullWidth = true,
        enabled = enabled,
    )
}
