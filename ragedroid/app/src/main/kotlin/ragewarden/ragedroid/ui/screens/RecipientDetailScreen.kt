package ragewarden.ragedroid.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
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
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Check
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material.icons.outlined.Fingerprint
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Memory
import androidx.compose.material.icons.outlined.Nfc
import androidx.compose.material.icons.outlined.Shield
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
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch
import ragewarden.ragedroid.R
import ragewarden.ragedroid.data.VaultBridge
import ragewarden.ragedroid.di.appEntryPoint
import ragewarden.ragedroid.model.Recipient
import ragewarden.ragedroid.model.RecipientKind
import ragewarden.ragedroid.ui.components.AppBar
import ragewarden.ragedroid.ui.components.BackButton
import ragewarden.ragedroid.ui.components.ButtonVariant
import ragewarden.ragedroid.ui.components.MasterPasswordConfirm
import ragewarden.ragedroid.ui.components.Mono
import ragewarden.ragedroid.ui.components.RageButton
import ragewarden.ragedroid.ui.components.RageChip
import ragewarden.ragedroid.ui.components.Sheet
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors
import ragewarden.ragedroid.ui.uiString

@Composable
fun RecipientDetailScreen(
    recipient: Recipient,
    onBack: () -> Unit,
    onRename: (String) -> Unit = {},
    onRemove: () -> Unit = {},
    onToast: (String) -> Unit = {},
    onRewrapStale: () -> Unit = {},
) {
    val c = rageColors
    var revokeOpen by remember { mutableStateOf(false) }
    var pwOpen by remember { mutableStateOf(false) }
    var revoking by remember { mutableStateOf(false) }

    val context = androidx.compose.ui.platform.LocalContext.current
    val scope = rememberCoroutineScope()
    val recipientStore = remember(context) { context.appEntryPoint().recipientStore() }
    val repo = VaultBridge.repository()
    val accountId = repo?.accountId.orEmpty()
    val vaultItems = remember(context) {
        ragewarden.ragedroid.data.VaultBridge.ensureBackend(context.applicationContext).snapshot()
    }
    // `item.recipients` holds the stanza descriptors the JNI layer parses out of
    // each blob's own age header ("piv-p256:<b64>"), not recipient ids -- see
    // data/RecipientDescriptors.kt. `recipient.id` is a UUID, so the two
    // namespaces never intersect and this filter, the coverage meter below and
    // the "CAN UNLOCK" list were all permanently empty. Same fix as
    // ItemDetailScreen.kt:159, MultiIdentityPickerSheet.kt:51 and
    // TapFailureScreen.kt:74.
    val descriptors = remember(recipient.descriptors) { recipient.descriptors.toSet() }
    val items = remember(descriptors, vaultItems) {
        if (descriptors.isEmpty()) emptyList()
        else vaultItems.filter { item -> item.rage && item.recipients.any { it in descriptors } }
    }
    val totalProtected = remember(vaultItems) { vaultItems.count { it.rage } }
    val coverage = items.size
    // An age X25519 stanza's only argument is the ephemeral share, so software
    // and paper recipients cannot be named from a header at all
    // (data/RecipientDescriptors.kt) and have no descriptors. Their coverage is
    // not zero, it is unknowable from here -- and saying "0 of N" about a paper
    // key that opens everything is the same class of lie as the id/descriptor
    // mismatch above.
    val coverageKnowable = descriptors.isNotEmpty()
    /** Revoke copy must not quote a count we could not compute. */
    val wrappedItemsPhrase = if (coverageKnowable) {
        androidx.compose.ui.res.pluralStringResource(R.plurals.items_already_protected_with_it, coverage, coverage)
    } else {
        stringResource(R.string.items_already_protected_with_it)
    }

    val subtitle = when (recipient.kind) {
        RecipientKind.YubiKey -> stringResource(R.string.yubikey_piv_x25519)
        RecipientKind.Fido2 -> stringResource(R.string.passkey_fido2_hmac_secret_older_format)
        RecipientKind.PasskeyPrf -> stringResource(R.string.passkey_webauthn_prf)
        RecipientKind.StrongBox -> stringResource(R.string.android_strongbox)
        RecipientKind.Recovery -> stringResource(R.string.paper_recovery_phrase)
        RecipientKind.Software -> stringResource(R.string.software_identity)
    }

    Column(modifier = Modifier.fillMaxSize().background(c.background)) {
        AppBar(
            title = stringResource(R.string.recipient),
            leading = { BackButton(onBack) },
        )

        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState()),
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(start = 18.dp, end = 18.dp, top = 4.dp, bottom = 18.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(14.dp),
            ) {
                Box(
                    modifier = Modifier
                        .size(56.dp)
                        .background(c.tile, RoundedCornerShape(12.dp)),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        imageVector = recipientKindIcon(recipient.kind),
                        contentDescription = null,
                        tint = c.accent,
                        modifier = Modifier.size(26.dp),
                    )
                }
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = recipient.name,
                        style = RageType.h2.copy(
                            fontSize = 22.sp,
                            lineHeight = 24.sp,
                            letterSpacing = (-0.01).em,
                        ),
                        color = c.fgEmphasis,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = subtitle.uppercase(),
                        style = RageType.eyebrow.copy(fontSize = 11.sp),
                        color = c.fgSecondary,
                    )
                }
            }

            Box(modifier = Modifier.padding(start = 18.dp, end = 18.dp, bottom = 18.dp)) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(c.surfaceElevated, RoundedCornerShape(12.dp))
                        .border(1.dp, c.border, RoundedCornerShape(12.dp))
                        .padding(horizontal = 16.dp, vertical = 14.dp),
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.Bottom,
                    ) {
                        Text(
                            text = stringResource(R.string.coverage),
                            style = RageType.eyebrow.copy(fontSize = 11.sp),
                            color = c.fgSecondary,
                        )
                        Row(verticalAlignment = Alignment.Bottom) {
                            Text(
                                text = if (coverageKnowable) "$coverage" else "--",
                                style = RageType.h2.copy(fontSize = 16.sp, fontWeight = FontWeight.Bold),
                                color = c.fgEmphasis,
                            )
                            Text(
                                text = stringResource(R.string.of_protected_items, totalProtected),
                                style = RageType.body.copy(fontSize = 13.5.sp),
                                color = c.fgSecondary,
                            )
                        }
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(4.dp)
                            .background(c.surfaceSunken, RoundedCornerShape(2.dp)),
                    ) {
                        val frac = if (totalProtected == 0 || !coverageKnowable) {
                            0f
                        } else {
                            coverage.toFloat() / totalProtected
                        }
                        Box(
                            modifier = Modifier
                                .fillMaxWidth(frac)
                                .height(4.dp)
                                .background(c.accent, RoundedCornerShape(2.dp)),
                        )
                    }
                    if (coverageKnowable && coverage == totalProtected && totalProtected > 0) {
                        Spacer(modifier = Modifier.height(10.dp))
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                imageVector = Icons.Outlined.Check,
                                contentDescription = null,
                                tint = c.success,
                                modifier = Modifier.size(12.dp),
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = stringResource(R.string.this_recipient_can_decrypt_every_protected),
                                style = RageType.caption.copy(fontSize = 11.5.sp),
                                color = c.success,
                            )
                        }
                    }
                    if (!coverageKnowable || coverage == 0) {
                        Spacer(modifier = Modifier.height(10.dp))
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                imageVector = Icons.Outlined.Info,
                                contentDescription = null,
                                tint = c.warning,
                                modifier = Modifier.size(12.dp),
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = if (coverageKnowable) {
                                    stringResource(R.string.no_item_is_protected_for_this)
                                } else {
                                    stringResource(R.string.items_do_not_record_this_kind)
                                },
                                style = RageType.caption.copy(fontSize = 11.5.sp),
                                color = c.warning,
                            )
                        }
                    }
                }
            }

            SectionLabel(label = stringResource(R.string.identity))
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
                val rows = buildList {
                    add(IdentityRow(stringResource(R.string.serial), recipient.serial, mono = false))
                    add(IdentityRow(stringResource(R.string.public_key), recipient.fingerprint, mono = true))
                    add(IdentityRow(stringResource(R.string.enrolled), recipient.enrolled, mono = false))
                    add(IdentityRow(stringResource(R.string.last_used_2), recipient.lastUsed, mono = false))
                }
                rows.forEachIndexed { idx, row ->
                    IdentityRowView(row = row, isLast = idx == rows.lastIndex)
                }
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(1.dp)
                        .background(c.border),
                )
            }

            Column(
                modifier = Modifier.padding(start = 18.dp, end = 18.dp, top = 20.dp, bottom = 8.dp),
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.Bottom,
                ) {
                    Text(
                        text = stringResource(R.string.can_unlock),
                        style = RageType.eyebrow.copy(fontSize = 11.sp, letterSpacing = 0.08.em),
                        color = c.fgSecondary,
                    )
                    if (items.size > 6) {
                        Text(
                            text = stringResource(R.string.items, items.size),
                            style = RageType.caption.copy(fontSize = 11.5.sp),
                            color = c.fgSecondary,
                        )
                    }
                }
            }

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
                if (items.isEmpty()) {
                    Text(
                        text = if (coverageKnowable) {
                            stringResource(R.string.no_items_use_this_key_yet)
                        } else {
                            stringResource(R.string.items_protected_with_this_key_can)
                        },
                        style = RageType.body.copy(
                            fontSize = 13.5.sp,
                            fontStyle = FontStyle.Italic,
                        ),
                        color = c.fgSecondary,
                        modifier = Modifier.padding(horizontal = 18.dp, vertical = 18.dp),
                    )
                } else {
                    val visible = items.take(6)
                    visible.forEachIndexed { idx, item ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 18.dp, vertical = 10.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            RageChip()
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = item.name,
                                    style = RageType.rowTitle.copy(fontSize = 14.sp),
                                    color = c.fgEmphasis,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                )
                                Text(
                                    text = stringResource(R.string.recipients, item.folder, item.recipients.size),
                                    style = RageType.caption.copy(fontSize = 11.5.sp),
                                    color = c.fgSecondary,
                                )
                            }
                            // SOLE means "rotating this item away from this
                            // recipient makes it unopenable", i.e. the header
                            // carries exactly one stanza and it is this key's.
                            // Comparing `recipients.firstOrNull()` -- a stanza
                            // descriptor -- to `recipient.id`, a UUID, never
                            // matched, so the badge never appeared.
                            if (item.recipients.size == 1 && item.recipients.first() in descriptors) {
                                Box(
                                    modifier = Modifier
                                        .border(1.dp, c.warning, RoundedCornerShape(3.dp))
                                        .padding(horizontal = 5.dp, vertical = 1.dp),
                                ) {
                                    Text(
                                        text = stringResource(R.string.sole),
                                        style = RageType.eyebrow.copy(
                                            fontSize = 9.5.sp,
                                            letterSpacing = 0.06.em,
                                        ),
                                        color = c.warning,
                                    )
                                }
                            }
                        }
                        if (idx < visible.lastIndex) {
                            Box(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(1.dp)
                                    .background(c.divider),
                            )
                        }
                    }
                    if (items.size > 6) {
                        Text(
                            text = stringResource(R.string.more, items.size - 6),
                            style = RageType.caption.copy(fontSize = 12.sp),
                            color = c.fgSecondary,
                            textAlign = TextAlign.Center,
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 18.dp, vertical = 10.dp),
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

            Column(
                modifier = Modifier.padding(start = 18.dp, end = 18.dp, top = 24.dp, bottom = 32.dp),
            ) {
                if (recipient.kind == ragewarden.ragedroid.model.RecipientKind.Fido2) {
                    val stored = remember(recipient.id, accountId) {
                        recipientStore.forAccount(accountId).firstOrNull { it.id == recipient.id }
                    }
                    if (stored != null) {
                        Text(text = stringResource(R.string.passkey_move_title), style = RageType.eyebrow, color = c.fgSecondary)
                        Spacer(modifier = Modifier.height(6.dp))
                        Text(text = stringResource(R.string.passkey_move_body), style = RageType.caption, color = c.fgSecondary)
                        Spacer(modifier = Modifier.height(10.dp))
                        val moved = stringResource(R.string.passkey_moved)
                        val failed = stringResource(R.string.passkey_move_failed)
                        RageButton(
                            label = stringResource(R.string.passkey_move_button),
                            onClick = {
                                scope.launch {
                                    runCatching {
                                        recipientStore.add(accountId, stored.migratedToPasskeyPrf())
                                        repo?.pushRecipientRegistry()?.getOrThrow()
                                    }.onSuccess { onToast(moved); onBack() }
                                        .onFailure { e -> onToast(failed.format(e.message ?: "")) }
                                }
                            },
                            variant = ButtonVariant.Secondary,
                            fullWidth = true,
                        )
                        Spacer(modifier = Modifier.height(24.dp))
                    }
                }
                Text(
                    text = stringResource(R.string.danger_zone),
                    style = RageType.eyebrow.copy(fontSize = 11.sp, letterSpacing = 0.08.em),
                    color = c.dangerStrong,
                )
                Spacer(modifier = Modifier.height(10.dp))
                RageButton(
                    label = stringResource(R.string.revoke_this_recipient),
                    onClick = { revokeOpen = true },
                    variant = ButtonVariant.Secondary,
                    fullWidth = true,
                )
                Spacer(modifier = Modifier.height(10.dp))
                // unpublishRecipient() rewrites the registry and syncs; the items
                // themselves are re-encrypted afterwards by the backfill wizard.
                Text(
                    text = stringResource(R.string.drops_this_recipient_from_the_published),
                    style = RageType.caption.copy(fontSize = 11.5.sp, lineHeight = 17.sp),
                    color = c.fgSecondary,
                )
            }
        }
    }

    Sheet(open = revokeOpen, onDismiss = { revokeOpen = false }, title = stringResource(R.string.revoke, recipient.name)) {
        Column(modifier = Modifier.fillMaxWidth()) {
            Text(
                text = stringResource(R.string.stops_being_encrypted_to_from_now, recipient.name, wrappedItemsPhrase),
                style = RageType.body.copy(fontSize = 14.5.sp, lineHeight = 22.sp),
                color = c.fgPrimary,
                modifier = Modifier.padding(bottom = 12.dp),
            )
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                // Keep/Revoke sit 8dp apart and the right one is irreversible.
                // The 48dp touch floor that keeps a thumb miss off it lives in
                // RageButton itself, so neither call site restates it.
                RageButton(
                    label = stringResource(R.string.keep),
                    onClick = { revokeOpen = false },
                    variant = ButtonVariant.Ghost,
                    fullWidth = true,
                    modifier = Modifier.weight(1f),
                )
                RageButton(
                    label = stringResource(R.string.revoke_2),
                    onClick = {
                        revokeOpen = false
                        // No repository means no master-password gate exists to
                        // put in front of this, so refuse instead of revoking
                        // ungated.
                        if (repo == null || accountId.isBlank()) {
                            onToast(uiString(R.string.no_active_account))
                        } else {
                            pwOpen = true
                        }
                    },
                    variant = ButtonVariant.Danger,
                    fullWidth = true,
                    modifier = Modifier.weight(1f),
                    rejectObscured = true,
                )
            }
        }
    }

    // Gated only when a repository exists to verify the master password against.
    // This sheet used to omit `repository`, which selected a branch that slept
    // 150ms and then confirmed whatever was typed -- one arbitrary character
    // revoked a recipient. The parameter is non-null now, so the omission is no
    // longer expressible; the Revoke button refuses above when repo is null.
    if (repo != null && accountId.isNotBlank()) {
        MasterPasswordConfirm(
            open = pwOpen,
            onClose = { if (!revoking) pwOpen = false },
            title = stringResource(R.string.revoke, recipient.name),
            body = stringResource(R.string.stops_being_encrypted_to_stay_readable, recipient.name, wrappedItemsPhrase),
            action = if (revoking) stringResource(R.string.revoking) else stringResource(R.string.revoke_recipient),
            repository = repo,
            onConfirm = {
                if (revoking) return@MasterPasswordConfirm
                revoking = true
                scope.launch {
                    val unpublish = repo.unpublishRecipient(recipient.id)
                    unpublish.onSuccess {
                        runCatching { recipientStore.remove(accountId, recipient.id) }
                        pwOpen = false
                        revoking = false
                        onToast(context.getString(R.string.recipient_revoked))
                        onRemove()
                        // Items already wrapped to it stay readable by it until they
                        // are re-encrypted; the wizard does that, one tap each.
                        if (items.isNotEmpty()) onRewrapStale() else onBack()
                    }.onFailure { e ->
                        revoking = false
                        onToast(uiString(R.string.revoke_failed, e.message ?: uiString(R.string.unknown_error)))
                    }
                }
            },
        )
    }
}

private data class IdentityRow(val label: String, val value: String, val mono: Boolean)

@Composable
private fun IdentityRowView(row: IdentityRow, isLast: Boolean) {
    val c = rageColors
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 18.dp, vertical = 11.dp),
    ) {
        if (row.mono) {
            Text(
                text = row.label.uppercase(),
                style = RageType.eyebrow.copy(fontSize = 12.5.sp, letterSpacing = 0.04.em),
                color = c.fgSecondary,
            )
            Spacer(modifier = Modifier.height(4.dp))
            Mono(text = row.value, size = 11, color = c.fgPrimary)
        } else {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(
                    text = row.label.uppercase(),
                    style = RageType.eyebrow.copy(fontSize = 12.5.sp, letterSpacing = 0.04.em),
                    color = c.fgSecondary,
                )
                Spacer(modifier = Modifier.width(12.dp))
                Text(
                    text = row.value,
                    style = RageType.sansBody.copy(fontSize = 13.5.sp),
                    color = c.fgPrimary,
                    textAlign = TextAlign.End,
                )
            }
        }
    }
    if (!isLast) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(1.dp)
                .background(c.divider),
        )
    }
}

@Composable
private fun SectionLabel(label: String) {
    Text(
        text = label.uppercase(),
        style = RageType.eyebrow.copy(fontSize = 11.sp, letterSpacing = 0.08.em),
        color = rageColors.fgSecondary,
        modifier = Modifier.padding(start = 18.dp, end = 18.dp, top = 4.dp, bottom = 8.dp),
    )
}

private fun recipientKindIcon(kind: RecipientKind): ImageVector = when (kind) {
    RecipientKind.YubiKey -> Icons.Outlined.Nfc
    RecipientKind.Fido2 -> Icons.Outlined.Fingerprint
    RecipientKind.PasskeyPrf -> Icons.Outlined.Fingerprint
    RecipientKind.StrongBox -> Icons.Outlined.Memory
    RecipientKind.Recovery -> Icons.Outlined.Description
    RecipientKind.Software -> Icons.Outlined.Shield
}
