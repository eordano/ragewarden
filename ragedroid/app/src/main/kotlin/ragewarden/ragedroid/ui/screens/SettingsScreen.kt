package ragewarden.ragedroid.ui.screens

import androidx.compose.ui.res.stringResource
import kotlinx.coroutines.launch
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.platform.LocalContext
import android.content.pm.ApplicationInfo
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Bolt
import androidx.compose.material.icons.outlined.BugReport
import androidx.compose.material.icons.outlined.Fingerprint
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.Memory
import androidx.compose.material.icons.outlined.Usb
import androidx.compose.material.icons.outlined.ChevronRight
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material.icons.outlined.Folder
import androidx.compose.material.icons.outlined.History
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Keyboard
import androidx.compose.material.icons.outlined.Language
import androidx.compose.material.icons.outlined.LockReset
import androidx.compose.material.icons.outlined.Preview
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material.icons.outlined.Upgrade
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
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp
import kotlinx.collections.immutable.ImmutableList
import kotlinx.collections.immutable.persistentListOf
import kotlinx.collections.immutable.toImmutableList
import ragewarden.ragedroid.R
import ragewarden.ragedroid.data.VaultBridge
import ragewarden.ragedroid.data.toUiRecipient
import ragewarden.ragedroid.di.appEntryPoint
import ragewarden.ragedroid.model.Recipient
import ragewarden.ragedroid.model.RecipientKind
import ragewarden.ragedroid.model.VaultItem
import ragewarden.ragedroid.ui.components.AppBar
import ragewarden.ragedroid.ui.components.BackButton
import ragewarden.ragedroid.ui.components.Mono
import ragewarden.ragedroid.ui.components.RecipientPickerSheet
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors
import ragewarden.ragedroid.ui.uiString

@Composable
fun SettingsScreen(
    items: ImmutableList<VaultItem> = persistentListOf(),
    recipients: ImmutableList<Recipient>? = null,
    email: String = VaultBridge.repository()?.email.orEmpty(),
    server: String = VaultBridge.repository()?.serverUrl.orEmpty(),
    activityCount: Int = 0,
    folderCount: Int = 0,
    initialDefaultRecipientIds: ImmutableList<String> = persistentListOf(),
    autofillOn: Boolean = true,
    imeOn: Boolean = false,
    onBack: () -> Unit,
    onAccount: () -> Unit,
    onAddRecipient: () -> Unit,
    onOpenRecipient: (Recipient) -> Unit,
    onRecovery: () -> Unit,
    onRecoverFromPhrase: () -> Unit = {},
    onListRecipients: () -> Unit = {},
    onFolders: () -> Unit,
    onOpenAuditLog: () -> Unit,
    onAutofillToggle: (Boolean) -> Unit = {},
    onImeToggle: (Boolean) -> Unit = {},
    onLockNow: () -> Unit = {},
    onBackfill: () -> Unit = {},
    onBulkProtect: () -> Unit = {},
    onAutofillPreview: () -> Unit = {},
    onImePreview: () -> Unit = {},
    onDebugTokenExpired: (() -> Unit)? = null,
    onSignOut: () -> Unit,
    onToast: (String) -> Unit = {},
) {
    val c = rageColors
    val context = androidx.compose.ui.platform.LocalContext.current
    val accountId = remember(context) { VaultBridge.repository()?.accountId.orEmpty() }
    // Same signal RageApp uses to decide whether to hand us onDebugTokenExpired.
    // Recomputed here rather than taken from the caller so a demo surface can
    // never reach a release build because someone forgot to gate the argument.
    val isDebuggable = remember(context) {
        (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
    }
    val resolvedRecipients: ImmutableList<Recipient> = remember(recipients, context, accountId) {
        if (recipients != null) recipients
        else if (accountId.isBlank()) persistentListOf()
        else context.appEntryPoint().recipientStore().forAccount(accountId)
            .map { it.toUiRecipient() }
            .toImmutableList()
    }

    val setupContext = LocalContext.current
    val sourceUriHandler = androidx.compose.ui.platform.LocalUriHandler.current
    var autofill by remember { mutableStateOf(ragewarden.ragedroid.ui.SystemSetup.autofillEnabled(setupContext)) }
    var ime by remember { mutableStateOf(ragewarden.ragedroid.ui.SystemSetup.keyboardEnabled(setupContext)) }
    val setupLifecycle = androidx.lifecycle.compose.LocalLifecycleOwner.current
    androidx.compose.runtime.DisposableEffect(setupLifecycle) {
        val observer = androidx.lifecycle.LifecycleEventObserver { _, event ->
            if (event == androidx.lifecycle.Lifecycle.Event.ON_RESUME) {
                autofill = ragewarden.ragedroid.ui.SystemSetup.autofillEnabled(setupContext)
                ime = ragewarden.ragedroid.ui.SystemSetup.keyboardEnabled(setupContext)
            }
        }
        setupLifecycle.lifecycle.addObserver(observer)
        onDispose { setupLifecycle.lifecycle.removeObserver(observer) }
    }
    var defaultsPickerOpen by remember { mutableStateOf(false) }
    val settingsContext = LocalContext.current
    val recipientStoreForDefaults = remember(settingsContext) {
        runCatching { settingsContext.appEntryPoint().recipientStore() }.getOrNull()
    }
    val accountForDefaults = VaultBridge.repository()?.accountId.orEmpty()
    var defaultRecipientIds by remember(accountForDefaults) {
        mutableStateOf(
            recipientStoreForDefaults?.takeIf { accountForDefaults.isNotBlank() }
                ?.forAccount(accountForDefaults)?.filter { it.defaultEncrypt }?.map { it.id }?.toImmutableList()
                ?: initialDefaultRecipientIds,
        )
    }
    val defaultsScope = rememberCoroutineScope()

    val itemCount = items.size
    val protectedItems = items.count { it.rage }

    val defaultRecipients = remember(defaultRecipientIds, resolvedRecipients) {
        defaultRecipientIds.mapNotNull { id -> resolvedRecipients.firstOrNull { it.id == id } }
    }

    Column(modifier = Modifier.fillMaxSize().background(c.background)) {
        AppBar(
            title = stringResource(R.string.settings),
            leading = { BackButton(onBack) },
        )

        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(bottom = 32.dp),
        ) {
            AccountHero(
                email = email,
                server = server,
                itemCount = itemCount,
                protectedItems = protectedItems,
                onClick = onAccount,
            )

            SettingsSectionLabel(
                label = stringResource(R.string.identities),
                action = {
                    Row(
                        modifier = Modifier
                            .clickable(onClick = onAddRecipient)
                            .padding(horizontal = 4.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        Icon(
                            imageVector = Icons.Outlined.Add,
                            contentDescription = null,
                            tint = c.accent,
                            modifier = Modifier.size(13.dp),
                        )
                        Text(
                            text = stringResource(R.string.add),
                            style = RageType.button.copy(fontSize = 12.5.sp),
                            color = c.accent,
                        )
                    }
                },
            )
            Card {
                if (resolvedRecipients.isEmpty()) {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 16.dp, vertical = 14.dp),
                    ) {
                        Text(
                            text = stringResource(R.string.no_identities_enrolled_yet_tap_add),
                            style = RageType.body.copy(fontSize = 13.sp, lineHeight = 18.sp),
                            color = c.fgSecondary,
                        )
                    }
                } else {
                    resolvedRecipients.forEachIndexed { index, recipient ->
                        RecipientRow(recipient = recipient, onClick = { onOpenRecipient(recipient) })
                        if (index < resolvedRecipients.size - 1) Divider()
                    }
                }
            }

            Spacer(modifier = Modifier.height(8.dp))
            Card {
                DefaultRecipientsRow(
                    selected = defaultRecipients.toImmutableList(),
                    onClick = { defaultsPickerOpen = true },
                )
                Divider()
                SettingsRow(
                    icon = Icons.Outlined.Shield,
                    title = stringResource(R.string.manage_recipients),
                    subtitle = stringResource(R.string.every_key_that_can_open_your),
                    onClick = onListRecipients,
                )
            }

            SettingsSectionLabel(label = stringResource(R.string.vault))
            Card {
                SettingsRow(
                    icon = Icons.Outlined.Folder,
                    title = stringResource(R.string.folders),
                    subtitle = when (folderCount) {
                        0 -> stringResource(R.string.no_custom_folders_yet)
                        else -> androidx.compose.ui.res.pluralStringResource(R.plurals.folder_count, folderCount, folderCount)
                    },
                    onClick = onFolders,
                )
                Divider()
                SettingsRow(
                    icon = Icons.Outlined.Description,
                    title = stringResource(R.string.create_a_new_recovery_phrase),
                    subtitle = stringResource(R.string.earlier_phrases_keep_working_until_you),
                    onClick = onRecovery,
                )
                Divider()
                SettingsRow(
                    icon = Icons.Outlined.Key,
                    title = stringResource(R.string.test_my_paper_backup),
                    subtitle = stringResource(R.string.type_your_phrase_and_open_one),
                    onClick = onRecoverFromPhrase,
                )
                Divider()
                SettingsRow(
                    icon = Icons.Outlined.History,
                    title = stringResource(R.string.activity),
                    subtitle = stringResource(R.string.entries_stored_on_this_device, activityCount),
                    onClick = onOpenAuditLog,
                )
                Divider()
                SettingsRow(
                    icon = Icons.Outlined.Upgrade,
                    title = stringResource(R.string.protect_existing_items),
                    subtitle = stringResource(R.string.protect_items_that_are_not_protected),
                    onClick = onBackfill,
                )
                Divider()
                SettingsRow(
                    icon = Icons.Outlined.Shield,
                    title = stringResource(R.string.bulk_protect_wizard),
                    subtitle = stringResource(R.string.select_items_pick_recipients_and_protect),
                    onClick = onBulkProtect,
                )
            }

            SettingsSectionLabel(label = stringResource(R.string.system_integration))
            Card {
                SettingsSwitchRow(
                    icon = Icons.Outlined.Bolt,
                    title = stringResource(R.string.autofill),
                    subtitle = if (autofill) {
                        stringResource(R.string.ragedroid_is_the_active_autofill_provider)
                    } else {
                        stringResource(R.string.tap_to_make_ragedroid_the_active)
                    },
                    on = autofill,
                    onChange = {
                        onAutofillToggle(it)
                        ragewarden.ragedroid.ui.SystemSetup.openAutofillSettings(settingsContext)
                    },
                )
                Divider()
                SettingsSwitchRow(
                    icon = Icons.Outlined.Keyboard,
                    title = stringResource(R.string.quick_fill_keyboard),
                    subtitle = if (ime) {
                        stringResource(R.string.a_ragedroid_keyboard_suggests_credentials_inside)
                    } else {
                        stringResource(R.string.suggests_credentials_inline_above_the_keys)
                    },
                    on = ime,
                    onChange = {
                        onImeToggle(it)
                        ragewarden.ragedroid.ui.SystemSetup.openKeyboardSettings(settingsContext)
                    },
                )
                // Demo surfaces: they render mock credentials rather than doing
                // anything to the vault, so they belong with the other
                // debug-only entries and not in a shipped build.
                if (isDebuggable) {
                    Divider()
                    SettingsRow(
                        icon = Icons.Outlined.Preview,
                        title = stringResource(R.string.preview_autofill_picker),
                        subtitle = stringResource(R.string.debug_only_what_ragedroid_shows_when),
                        onClick = onAutofillPreview,
                    )
                    Divider()
                    SettingsRow(
                        icon = Icons.Outlined.Preview,
                        title = stringResource(R.string.preview_keyboard),
                        subtitle = stringResource(R.string.debug_only_the_quick_fill_keyboard),
                        onClick = onImePreview,
                    )
                }
            }

            SettingsSectionLabel(label = stringResource(R.string.security))
            Card {
                SettingsRow(
                    icon = Icons.Outlined.LockReset,
                    title = stringResource(R.string.lock_now),
                    subtitle = stringResource(R.string.require_biometric_or_master_password_to),
                    onClick = onLockNow,
                )
            }

            SettingsSectionLabel(label = stringResource(R.string.about))
            Card {
                SettingsRow(
                    icon = Icons.Outlined.Info,
                    title = stringResource(R.string.version),
                    value = "${ragewarden.ragedroid.BuildConfig.VERSION_NAME} · build ${ragewarden.ragedroid.BuildConfig.VERSION_CODE}",
                    onClick = null,
                )
                Divider()
                // Plain text, not a link: nothing here launches a browser, and
                // a chevron that only toasts "Opens browser" is a lie.
                SettingsRow(
                    icon = Icons.Outlined.Language,
                    title = stringResource(R.string.source_code),
                    subtitle = stringResource(R.string.github_com_eordano_ragewarden),
                    onClick = { sourceUriHandler.openUri("https://github.com/eordano/ragewarden") },
                )
                Divider()
                SettingsRow(
                    icon = Icons.Outlined.Close,
                    title = stringResource(R.string.sign_out_2),
                    subtitle = stringResource(R.string.removes_the_session_offline_vault_copy),
                    danger = true,
                    onClick = onSignOut,
                )
                if (onDebugTokenExpired != null) {
                    Divider()
                    SettingsRow(
                        icon = Icons.Outlined.BugReport,
                        title = stringResource(R.string.simulate_token_expiry),
                        subtitle = stringResource(R.string.debug_only_jumps_to_the_re),
                        onClick = onDebugTokenExpired,
                    )
                }
            }

            Spacer(modifier = Modifier.height(24.dp))
            Text(
                text = stringResource(R.string.ragedroid_yubikit_android, ragewarden.ragedroid.BuildConfig.VERSION_NAME, ragewarden.ragedroid.BuildConfig.YUBIKIT_VERSION),
                style = RageType.body.copy(
                    fontSize = 13.sp,
                    lineHeight = 19.5.sp,
                    fontStyle = androidx.compose.ui.text.font.FontStyle.Italic,
                    textAlign = TextAlign.Center,
                ),
                color = c.fgSecondary,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 18.dp),
            )
            Spacer(modifier = Modifier.height(12.dp))
        }
    }

    RecipientPickerSheet(
        open = defaultsPickerOpen,
        onDismiss = { defaultsPickerOpen = false },
        recipients = resolvedRecipients,
        selected = defaultRecipientIds,
        onChange = { next ->
            val store = recipientStoreForDefaults
            if (store == null || accountForDefaults.isBlank()) {
                onToast(uiString(R.string.not_saved_sign_in_first_2))
                return@RecipientPickerSheet
            }
            val before = defaultRecipientIds.toSet()
            defaultsScope.launch {
                val result = runCatching {
                    store.forAccount(accountForDefaults).forEach { r ->
                        val want = r.id in next
                        if (want != (r.id in before) || want != r.defaultEncrypt) {
                            store.setDefaultEncrypt(accountForDefaults, r.id, want)
                        }
                    }
                    VaultBridge.repository()?.pushRecipientRegistry()
                }
                if (result.isSuccess) {
                    defaultRecipientIds = next
                    onToast(uiString(R.string.default_recipients_updated_selected, next.size))
                } else {
                    onToast(uiString(R.string.not_saved, result.exceptionOrNull()?.message ?: uiString(R.string.unknown_error)))
                }
            }
        },
        allowEmpty = false,
        onToast = onToast,
    )
}

@Composable
private fun AccountHero(
    email: String,
    server: String,
    itemCount: Int,
    protectedItems: Int,
    onClick: () -> Unit,
) {
    val c = rageColors
    val initial = email.firstOrNull()?.uppercaseChar()?.toString() ?: "?"
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .padding(start = 16.dp, end = 16.dp, top = 8.dp),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(c.surfaceElevated, RoundedCornerShape(12.dp))
                .border(1.dp, c.border, RoundedCornerShape(12.dp))
                .clickable(onClick = onClick)
                .padding(14.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Box(
                modifier = Modifier
                    .size(44.dp)
                    .background(c.accent, RoundedCornerShape(22.dp)),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    text = initial,
                    style = RageType.h2.copy(fontSize = 18.sp),
                    color = c.background,
                )
            }
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = email,
                    style = RageType.h2.copy(fontSize = 16.sp),
                    color = c.fgEmphasis,
                )
                Mono(
                    text = stringResource(R.string.items_protected, server, itemCount, protectedItems),
                    size = 11,
                    color = c.fgSecondary,
                    modifier = Modifier.padding(top = 2.dp),
                )
            }
            Icon(
                imageVector = Icons.Outlined.ChevronRight,
                contentDescription = null,
                tint = c.fgSecondary,
                modifier = Modifier.size(16.dp),
            )
        }
    }
}

@Composable
private fun SettingsSectionLabel(
    label: String,
    action: (@Composable () -> Unit)? = null,
) {
    val c = rageColors
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(start = 18.dp, end = 18.dp, top = 20.dp, bottom = 8.dp),
        verticalAlignment = Alignment.Bottom,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(
            text = label.uppercase(),
            style = RageType.eyebrow.copy(letterSpacing = 0.08.em),
            color = c.fgSecondary,
        )
        if (action != null) action()
    }
}

@Composable
internal fun SettingsRow(
    icon: ImageVector? = null,
    title: String,
    subtitle: String? = null,
    value: String? = null,
    danger: Boolean = false,
    onClick: (() -> Unit)?,
) {
    val c = rageColors
    val rowMod = if (onClick != null) Modifier.clickable(onClick = onClick) else Modifier
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .then(rowMod)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (icon != null) {
            Box(
                modifier = Modifier
                    .size(32.dp)
                    .background(c.tile, RoundedCornerShape(8.dp)),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = if (danger) c.dangerStrong else c.accent,
                    modifier = Modifier.size(16.dp),
                )
            }
        }
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                style = RageType.rowTitle.copy(fontSize = 14.5.sp),
                color = if (danger) c.dangerStrong else c.fgEmphasis,
            )
            if (subtitle != null) {
                Text(
                    text = subtitle,
                    style = RageType.caption.copy(fontSize = 11.5.sp),
                    color = c.fgSecondary,
                    modifier = Modifier.padding(top = 2.dp),
                )
            }
        }
        if (value != null) {
            Text(
                text = value,
                style = RageType.caption.copy(fontSize = 12.5.sp),
                color = c.fgSecondary,
            )
        }
        if (onClick != null) {
            Icon(
                imageVector = Icons.Outlined.ChevronRight,
                contentDescription = null,
                tint = c.fgSecondary,
                modifier = Modifier.size(14.dp),
            )
        }
    }
}

@Composable
private fun SettingsSwitchRow(
    icon: ImageVector?,
    title: String,
    subtitle: String?,
    on: Boolean,
    onChange: (Boolean) -> Unit,
) {
    val c = rageColors
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onChange(!on) }
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (icon != null) {
            Box(
                modifier = Modifier
                    .size(32.dp)
                    .background(c.tile, RoundedCornerShape(8.dp)),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = c.accent,
                    modifier = Modifier.size(16.dp),
                )
            }
        }
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                style = RageType.rowTitle.copy(fontSize = 14.5.sp),
                color = c.fgEmphasis,
            )
            if (subtitle != null) {
                Text(
                    text = subtitle,
                    style = RageType.caption.copy(fontSize = 11.5.sp),
                    color = c.fgSecondary,
                    modifier = Modifier.padding(top = 2.dp),
                )
            }
        }
        ToggleSwitch(on = on, onChange = onChange)
    }
}

@Composable
private fun RecipientRow(recipient: Recipient, onClick: () -> Unit) {
    val c = rageColors
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
                .size(32.dp)
                .background(c.tile, RoundedCornerShape(8.dp)),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                imageVector = recipientKindIcon(recipient.kind),
                contentDescription = null,
                tint = c.accent,
                modifier = Modifier.size(16.dp),
            )
        }
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = recipient.name,
                style = RageType.rowTitle.copy(fontSize = 14.5.sp),
                color = c.fgEmphasis,
            )
            val subtitle = if (recipient.lastUsed.isBlank()) {
                recipientKindLabel(recipient.kind)
            } else {
                "${recipientKindLabel(recipient.kind)} · ${recipient.lastUsed}"
            }
            Text(
                text = subtitle,
                style = RageType.caption.copy(fontSize = 11.5.sp),
                color = c.fgSecondary,
                modifier = Modifier.padding(top = 2.dp),
            )
        }
        Icon(
            imageVector = Icons.Outlined.ChevronRight,
            contentDescription = null,
            tint = c.fgSecondary,
            modifier = Modifier.size(14.dp),
        )
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun DefaultRecipientsRow(
    selected: ImmutableList<Recipient>,
    onClick: () -> Unit,
) {
    val c = rageColors
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.Top,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Box(
            modifier = Modifier
                .size(32.dp)
                .background(c.tile, RoundedCornerShape(8.dp)),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                imageVector = Icons.Outlined.Shield,
                contentDescription = null,
                tint = c.accent,
                modifier = Modifier.size(16.dp),
            )
        }
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = stringResource(R.string.default_recipients),
                style = RageType.rowTitle.copy(fontSize = 14.5.sp),
                color = c.fgEmphasis,
            )
            Text(
                text = stringResource(R.string.every_new_item_is_encrypted_to),
                style = RageType.caption.copy(fontSize = 11.5.sp),
                color = c.fgSecondary,
                modifier = Modifier.padding(top = 2.dp),
            )
            Spacer(modifier = Modifier.height(8.dp))
            if (selected.isEmpty()) {
                Text(
                    text = stringResource(R.string.none_new_items_will_be_unprotected),
                    style = RageType.caption.copy(
                        fontSize = 12.sp,
                        fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold,
                    ),
                    color = c.dangerStrong,
                )
            } else {
                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    selected.forEach { recipient ->
                        Row(
                            modifier = Modifier
                                .background(c.tile, RoundedCornerShape(12.dp))
                                .border(1.dp, c.border, RoundedCornerShape(12.dp))
                                .padding(horizontal = 8.dp, vertical = 3.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(5.dp),
                        ) {
                            Icon(
                                imageVector = recipientKindIcon(recipient.kind),
                                contentDescription = null,
                                tint = c.accent,
                                modifier = Modifier.size(11.dp),
                            )
                            Text(
                                text = recipient.name,
                                style = RageType.caption.copy(fontSize = 11.5.sp),
                                color = c.fgEmphasis,
                            )
                        }
                    }
                }
            }
        }
        Icon(
            imageVector = Icons.Outlined.ChevronRight,
            contentDescription = null,
            tint = c.fgSecondary,
            modifier = Modifier
                .padding(top = 10.dp)
                .size(14.dp),
        )
    }
}

private fun recipientKindIcon(kind: RecipientKind): ImageVector = when (kind) {
    RecipientKind.YubiKey -> Icons.Outlined.Usb
    RecipientKind.Fido2 -> Icons.Outlined.Fingerprint
    RecipientKind.PasskeyPrf -> Icons.Outlined.Fingerprint
    RecipientKind.StrongBox -> Icons.Outlined.Memory
    RecipientKind.Recovery -> Icons.Outlined.Description
    RecipientKind.Software -> Icons.Outlined.Key
}

private fun recipientKindLabel(kind: RecipientKind): String = when (kind) {
    RecipientKind.YubiKey -> uiString(R.string.yubikey_piv)
    RecipientKind.Fido2 -> uiString(R.string.fido2_hmac_secret)
    RecipientKind.PasskeyPrf -> uiString(R.string.passkey_webauthn_prf)
    RecipientKind.StrongBox -> uiString(R.string.android_strongbox)
    RecipientKind.Recovery -> uiString(R.string.paper_recovery)
    RecipientKind.Software -> uiString(R.string.software_identity)
}
