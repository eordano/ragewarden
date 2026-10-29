package ragewarden.ragedroid.ui.screens

import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.selection.toggleable
import androidx.compose.animation.core.animateDpAsState
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
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.automirrored.outlined.KeyboardArrowRight
import androidx.compose.material.icons.outlined.Folder
import androidx.compose.material.icons.outlined.KeyboardArrowDown
import androidx.compose.material.icons.outlined.Link
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.collections.immutable.ImmutableList
import kotlinx.collections.immutable.persistentListOf
import kotlinx.collections.immutable.toImmutableList
import kotlinx.collections.immutable.toPersistentList
import kotlinx.coroutines.launch
import androidx.compose.runtime.rememberCoroutineScope
import ragewarden.ragedroid.R
import ragewarden.ragedroid.data.RecipientPolicy
import ragewarden.ragedroid.data.RecipientRegistry
import ragewarden.ragedroid.data.VaultBackend
import ragewarden.ragedroid.data.VaultBridge
import ragewarden.ragedroid.data.toUiRecipient
import ragewarden.ragedroid.di.appEntryPoint
import ragewarden.ragedroid.model.NO_FOLDER
import ragewarden.ragedroid.model.Recipient
import ragewarden.ragedroid.model.RecipientKind
import ragewarden.ragedroid.model.VaultItem
import ragewarden.ragedroid.model.VaultItemKind
import java.util.UUID
import ragewarden.ragedroid.ui.components.AppBar
import ragewarden.ragedroid.ui.components.ButtonSize
import ragewarden.ragedroid.ui.components.ButtonVariant
import ragewarden.ragedroid.ui.components.Field
import ragewarden.ragedroid.ui.components.FolderOption
import ragewarden.ragedroid.ui.components.IconBtn
import ragewarden.ragedroid.ui.components.MoveToFolderSheet
import ragewarden.ragedroid.ui.components.PasswordGeneratorSheet
import ragewarden.ragedroid.ui.components.RageButton
import ragewarden.ragedroid.ui.components.TextInput
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.Sans
import ragewarden.ragedroid.ui.theme.rageColors
import ragewarden.ragedroid.ui.uiString

data class AddItemDraft(
    val kind: AddItemKind,
    val name: String,
    val folder: String?,
    val rage: Boolean,
    val recipientIds: ImmutableList<String>,
    val username: String = "",
    val site: String = "",
    val totp: String = "",
    val notes: String = "",
    val cardholder: String = "",
    val cardNumber: String = "",
    val cardExp: String = "",
    val cardCvv: String = "",
    val firstName: String = "",
    val lastName: String = "",
    val email: String = "",
    val phone: String = "",
    val sshType: String = "ed25519",
    val sshPrivateKey: String = "",
)

private val FolderTextStyle = TextStyle(
    fontFamily = Sans,
    fontWeight = FontWeight.Normal,
    fontSize = 13.5.sp,
    lineHeight = 18.sp,
)


private val NotePlainStyle = RageType.body.copy(fontSize = 14.5.sp, lineHeight = 22.sp)

private val NoteMonoStyle = TextStyle(
    fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
    fontWeight = FontWeight.Normal,
    fontSize = 12.sp,
    lineHeight = 17.sp,
)

@Composable
fun AddItemScreen(
    itemKind: AddItemKind,
    existing: VaultItem? = null,
    folderOptions: ImmutableList<FolderOption>? = null,
    repo: VaultBackend? = null,
    onBack: () -> Unit,
    onSave: (AddItemDraft, ByteArray?) -> Unit,
    onToast: (String) -> Unit = {},
) {
    val c = rageColors
    val isEdit = existing != null
    val kind = itemKind
    val scope = rememberCoroutineScope()

    var name by remember(existing?.id) { mutableStateOf(existing?.name ?: "") }
    var username by remember(existing?.id) { mutableStateOf(existing?.username ?: "") }
    var site by remember(existing?.id) { mutableStateOf(existing?.site ?: "") }
    var totp by remember(existing?.id) { mutableStateOf(existing?.totpSeed ?: "") }
    var password by remember(existing?.id) { mutableStateOf("") }
    var notes by remember(existing?.id) { mutableStateOf(existing?.notes ?: "") }
    var protectTotp by remember(existing?.id) { mutableStateOf(false) }
    var protectNotes by remember(existing?.id) { mutableStateOf(false) }

    var cardholder by remember(existing?.id) { mutableStateOf("") }
    var cardNumber by remember(existing?.id) { mutableStateOf("") }
    var cardExp by remember(existing?.id) { mutableStateOf("") }
    var cardCvv by remember(existing?.id) { mutableStateOf("") }

    var identitySsn by remember(existing?.id) { mutableStateOf("") }
    var identityPassport by remember(existing?.id) { mutableStateOf("") }
    var sshPassphrase by remember(existing?.id) { mutableStateOf("") }
    var firstName by remember(existing?.id) { mutableStateOf("") }
    var lastName by remember(existing?.id) { mutableStateOf("") }
    var email by remember(existing?.id) { mutableStateOf("") }
    var phone by remember(existing?.id) { mutableStateOf("") }

    var sshPriv by remember(existing?.id) { mutableStateOf("") }

    var folderId by remember(existing?.id) { mutableStateOf(existing?.folderId) }
    var loadedFolders by remember { mutableStateOf<ImmutableList<FolderOption>?>(null) }
    LaunchedEffect(repo, folderOptions) {
        if (folderOptions == null && repo != null) {
            loadedFolders = runCatching { repo.listFolders() }.getOrNull()
                ?.map { FolderOption(it.id, it.name, null) }
                ?.toImmutableList()
        }
    }
    val folders = folderOptions ?: loadedFolders ?: persistentListOf()
    var protect by remember(existing?.id) { mutableStateOf(existing?.rage ?: true) }
    // Only the local half of the wrap set, and only a fallback now -- see
    // rememberWrapTargets. Reading it as the whole set is what this screen used
    // to do, and what made the chooser disagree with the encrypt path.
    val localRecipients = ragewarden.ragedroid.ui.LocalLiveRecipients.current
    val wrapTargets = rememberWrapTargets(localRecipients)
    /**
     * True when at least one recipient in the set the encrypt path will use is
     * both enrolled here AND nameable in an age header -- which is exactly the
     * condition `ItemDetailScreen` uses to decide it can offer a reveal instead
     * of the "Set up this device" card, and exactly the set `IdentityResolver`
     * can turn into live identities (Recovery and Software are skipped there,
     * and carry no descriptors here, for the same reason).
     *
     * Tying the write gate to the read predicate is the point: an item this app
     * saves must be an item this app can open.
     */
    val openableHere = wrapTargets.any { it.local && it.recipient.descriptors.isNotEmpty() }
    // Not editable, and never was: `BitwardenVaultRepository.create` ignores
    // whatever lands in `VaultItem.recipients` and re-derives the set from the
    // policy. It is carried so the draft handed back to callers (and the demo
    // backend, which has no policy) describes the set the wrap would use.
    val recipientIds: ImmutableList<String> = remember(existing?.id, wrapTargets) {
        existing?.recipients ?: wrapTargets.map { it.recipient.id }.toPersistentList()
    }
    var showFolderSheet by remember { mutableStateOf(false) }
    var showGeneratorSheet by remember { mutableStateOf(false) }
    var confirmUnopenable by remember { mutableStateOf(false) }

    val titleNew = mapOf(
        AddItemKind.Login to stringResource(R.string.new_login),
        AddItemKind.Card to stringResource(R.string.new_card),
        AddItemKind.Note to stringResource(R.string.new_note),
        AddItemKind.Identity to stringResource(R.string.new_identity),
        AddItemKind.Ssh to stringResource(R.string.new_ssh_key),
    )
    val titleEdit = mapOf(
        AddItemKind.Login to stringResource(R.string.edit_login),
        AddItemKind.Card to stringResource(R.string.edit_card),
        AddItemKind.Note to stringResource(R.string.edit_note),
        AddItemKind.Identity to stringResource(R.string.edit_identity),
        AddItemKind.Ssh to stringResource(R.string.edit_ssh_key),
    )
    val title = if (isEdit) titleEdit[kind] ?: stringResource(R.string.edit_item) else titleNew[kind] ?: stringResource(R.string.new_item)

    // Mirrors the `plaintext` computation in `performSave` below: whether this
    // save has a secret to wrap at all.
    val typed = typedFields(
        kind = kind,
        cardholder = cardholder,
        cardNumber = cardNumber,
        cardExp = cardExp,
        cardCvv = cardCvv,
        firstName = firstName,
        lastName = lastName,
        email = email,
        phone = phone,
        ssn = identitySsn,
        passport = identityPassport,
        sshPrivateKey = sshPriv,
        sshPassphrase = sshPassphrase,
        protect = protect,
    )
    val hasSecret = when (kind) {
        AddItemKind.Login -> password.isNotEmpty()
        AddItemKind.Note -> true
        else -> typed?.secrets?.isNotEmpty() == true
    }
    // NOT `protect`. `BitwardenVaultRepository.create` calls
    // `encryptForActiveRecipients` unconditionally -- it never reads
    // `item.rage` -- so a secret reaching a live repository is wrapped whatever
    // the toggle says, and a kind with no secret (card, identity) is wrapped
    // never. Gating on the toggle would be both bypassable and, for those
    // kinds, a refusal to save something that was never going to be encrypted.
    val willWrap = repo != null && hasSecret && protect

    val performSave: () -> Unit = {
        val draft = AddItemDraft(
            kind = kind,
            name = name.ifBlank { uiString(R.string.untitled, uiString(kind.label)) },
            folder = folderId,
            rage = protect,
            recipientIds = recipientIds,
            username = username,
            site = site,
            totp = totp,
            notes = notes,
            cardholder = cardholder,
            cardNumber = cardNumber,
            cardExp = cardExp,
            cardCvv = cardCvv,
            firstName = firstName,
            lastName = lastName,
            email = email,
            phone = phone,
            sshType = typed?.block?.get("publicKey")?.substringBefore(' ') ?: "",
            sshPrivateKey = sshPriv,
        )
        val plaintext = when (kind) {
            AddItemKind.Login -> if (password.isNotEmpty()) password.toByteArray(Charsets.UTF_8) else null
            AddItemKind.Note -> notes.toByteArray(Charsets.UTF_8)
            else -> null
        }
        val storable = when (kind) {
            AddItemKind.Login -> !protect || plaintext != null
            AddItemKind.Note -> plaintext != null
            else -> typed != null && typed.problem == null
        }
        val loginSecrets = if (kind == AddItemKind.Login && protect) {
            buildMap {
                if (password.isNotEmpty()) put("password", password)
                if (protectTotp && totp.isNotBlank()) put("totp", totp.trim())
                if (protectNotes && notes.isNotBlank()) put("notes", notes)
            }
        } else {
            emptyMap()
        }
        if (repo != null && storable && kind == AddItemKind.Login && loginSecrets.keys.any { it != "password" }) {
            val loginItem = VaultItem(
                id = existing?.id ?: UUID.randomUUID().toString(),
                name = draft.name,
                username = draft.username,
                site = draft.site,
                folder = folders.firstOrNull { it.id == draft.folder }?.name ?: NO_FOLDER,
                folderId = draft.folder,
                rage = true,
                recipients = draft.recipientIds,
                password = "",
                totpSeed = totp.trim().ifBlank { null },
                notes = notes.ifBlank { null },
                lastUsed = "",
                history = 0,
                kind = VaultItemKind.Login,
            )
            plaintext?.fill(0)
            scope.launch {
                val result = runCatching { repo.createTyped(loginItem, emptyMap(), loginSecrets) }
                if (result.isSuccess) onSave(draft, null) else onToast(uiString(R.string.save_failed, result.exceptionOrNull()?.message ?: uiString(R.string.unknown_error)))
            }
        } else if (repo != null && storable && typed != null) {
            val typedItem = VaultItem(
                id = existing?.id ?: UUID.randomUUID().toString(),
                name = draft.name,
                username = "",
                site = "",
                folder = folders.firstOrNull { it.id == draft.folder }?.name ?: NO_FOLDER,
                folderId = draft.folder,
                rage = typed.secrets.isNotEmpty(),
                recipients = draft.recipientIds,
                password = "",
                notes = draft.notes.ifBlank { null },
                lastUsed = "",
                history = 0,
                kind = typed.kind,
            )
            scope.launch {
                val result = runCatching { repo.createTyped(typedItem, typed.block, typed.secrets) }
                if (result.isSuccess) {
                    onSave(draft, null)
                } else {
                    onToast(uiString(R.string.save_failed, result.exceptionOrNull()?.message ?: uiString(R.string.unknown_error)))
                }
            }
        } else if (repo != null && storable) {
            val newId = existing?.id ?: UUID.randomUUID().toString()
            val itemKindMapped = when (kind) {
                AddItemKind.Login -> VaultItemKind.Login
                AddItemKind.Card -> VaultItemKind.Card
                AddItemKind.Note -> VaultItemKind.Note
                AddItemKind.Identity -> VaultItemKind.Identity
                AddItemKind.Ssh -> VaultItemKind.SshKey
            }
            val newItem = VaultItem(
                id = newId,
                name = draft.name,
                username = draft.username,
                site = draft.site,
                totpSeed = draft.totp.takeIf { kind == AddItemKind.Login && it.isNotBlank() },
                folder = folders.firstOrNull { it.id == draft.folder }?.name ?: NO_FOLDER,
                rage = draft.rage,
                recipients = draft.recipientIds,
                password = "",
                notes = draft.notes.ifBlank { null },
                lastUsed = "",
                history = 0,
                kind = itemKindMapped,
            )
            scope.launch {
                val result = runCatching {
                    repo.create(newItem, plaintext)
                }
                if (result.isSuccess) {
                    onSave(draft, plaintext)
                } else {
                    val msg = result.exceptionOrNull()?.message
                        ?: result.exceptionOrNull()?.javaClass?.simpleName
                        ?: uiString(R.string.save_failed_3)
                    onToast(uiString(R.string.save_failed, msg))
                }
                plaintext?.fill(0)
            }
        } else {
            plaintext?.fill(0)
            onToast(typed?.problem ?: unsavableReason(kind, hasRepo = repo != null))
        }
    }

    // The write half of fail-closed. Before this, Save had no gate at all: on a
    // device with nothing enrolled the composer showed "Pick at least one
    // recipient" with nothing to pick, and Save still succeeded -- the shared
    // policy wrapped the item to whatever the registry held (another device's
    // paper key) and the phone that wrote it could never read it back. Refusing
    // on read is not enough when the write silently succeeds.
    val onSaveClick: () -> Unit = {
        when {
            !willWrap -> performSave()
            wrapTargets.isEmpty() -> onToast(
                uiString(R.string.not_saving_there_is_no_recipient),
            )
            !openableHere -> confirmUnopenable = true
            else -> performSave()
        }
    }

    Column(modifier = Modifier.fillMaxSize().background(c.background)) {
        AppBar(
            title = title,
            leading = {
                IconBtn(
                    icon = Icons.AutoMirrored.Outlined.ArrowBack,
                    contentDescription = stringResource(R.string.cancel),
                    onClick = onBack,
                )
            },
            trailing = {
                RageButton(
                    label = stringResource(R.string.save),
                    onClick = onSaveClick,
                    size = ButtonSize.Sm,
                )
            },
        )

        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .imePadding()
                .padding(start = 16.dp, end = 16.dp, top = 8.dp, bottom = 24.dp),
        ) {
            Field(label = stringResource(R.string.name)) {
                TextInput(
                    value = name,
                    onValueChange = { name = it },
                    placeholder = namePlaceholder(kind),
                    modifier = Modifier.testTag("add-name"),
                )
            }

            when (kind) {
                AddItemKind.Login -> {
                    Field(label = stringResource(R.string.website)) {
                        TextInput(
                            value = site,
                            onValueChange = { site = it },
                            placeholder = stringResource(R.string.dashboard_stripe_com),
                            mono = true,
                        )
                    }
                    Field(label = stringResource(R.string.username)) {
                        TextInput(
                            value = username,
                            onValueChange = { username = it },
                            placeholder = stringResource(R.string.you_example_com),
                        )
                    }
                    Field(
                        label = stringResource(R.string.totp_seed),
                        hint = stringResource(R.string.optional_either_an_otpauth_uri_or),
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Box(modifier = Modifier.weight(1f)) {
                                TextInput(
                                    value = totp,
                                    onValueChange = { totp = it },
                                    modifier = Modifier.testTag("add-totp"),
                                    mono = true,
                                    password = protect && protectTotp,
                                )
                            }
                            ragewarden.ragedroid.ui.components.TotpScanButton(onScanned = { totp = it })
                        }
                    }
                    if (protect) {
                        ProtectFieldRow(label = stringResource(R.string.protect_the_totp_seed), checked = protectTotp, onChange = { protectTotp = it })
                    }
                    Field(
                        label = stringResource(R.string.password),
                        hint = stringResource(R.string.generate_a_strong_password_ragedroid_will),
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Box(modifier = Modifier.weight(1f)) {
                                TextInput(
                                    value = password,
                                    onValueChange = { password = it },
                                    placeholder = "••••••",
                                    modifier = Modifier.testTag("add-password"),
                                    mono = true,
                                    password = true,
                                )
                            }
                            RageButton(
                                label = stringResource(R.string.gen),
                                onClick = { showGeneratorSheet = true },
                                icon = Icons.Outlined.Refresh,
                                variant = ButtonVariant.Secondary,
                                size = ButtonSize.Sm,
                            )
                        }
                    }
                    Field(label = stringResource(R.string.notes)) {
                        MultilineInput(value = notes, onValueChange = { notes = it }, placeholder = "", mono = false, minLines = 3)
                    }
                    if (protect) {
                        ProtectFieldRow(label = stringResource(R.string.protect_the_notes), checked = protectNotes, onChange = { protectNotes = it })
                    }
                }
                AddItemKind.Card -> {
                    Field(label = stringResource(R.string.cardholder)) {
                        TextInput(
                            value = cardholder,
                            onValueChange = { cardholder = it },
                            placeholder = stringResource(R.string.maya_voss),
                        )
                    }
                    Field(label = stringResource(R.string.card_number)) {
                        TextInput(
                            value = cardNumber,
                            onValueChange = { cardNumber = it },
                            placeholder = "•••• •••• •••• ••••",
                            mono = true,
                        )
                    }
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        Box(modifier = Modifier.weight(1f)) {
                            Field(label = stringResource(R.string.expiry)) {
                                TextInput(
                                    value = cardExp,
                                    onValueChange = { cardExp = it },
                                    placeholder = stringResource(R.string.mm_yy),
                                    mono = true,
                                )
                            }
                        }
                        Box(modifier = Modifier.weight(1f)) {
                            Field(label = stringResource(R.string.cvv)) {
                                TextInput(
                                    value = cardCvv,
                                    onValueChange = { cardCvv = it },
                                    placeholder = "•••",
                                    mono = true,
                                    password = true,
                                )
                            }
                        }
                    }
                }
                AddItemKind.Note -> {
                    Field(
                        label = stringResource(R.string.note),
                        hint = stringResource(R.string.plaintext_encrypted_under_your_recipients_no),
                    ) {
                        MultilineInput(
                            value = notes,
                            onValueChange = { notes = it },
                            placeholder = stringResource(R.string.anything_that_should_never_be_in),
                            mono = false,
                            minLines = 8,
                        )
                    }
                }
                AddItemKind.Identity -> {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        Box(modifier = Modifier.weight(1f)) {
                            Field(label = stringResource(R.string.first_name)) {
                                TextInput(
                                    value = firstName,
                                    onValueChange = { firstName = it },
                                    placeholder = stringResource(R.string.maya),
                                )
                            }
                        }
                        Box(modifier = Modifier.weight(1f)) {
                            Field(label = stringResource(R.string.last_name)) {
                                TextInput(
                                    value = lastName,
                                    onValueChange = { lastName = it },
                                    placeholder = stringResource(R.string.voss),
                                )
                            }
                        }
                    }
                    Field(label = stringResource(R.string.email)) {
                        TextInput(
                            value = email,
                            onValueChange = { email = it },
                            placeholder = stringResource(R.string.name_example_com),
                        )
                    }
                    Field(label = stringResource(R.string.phone)) {
                        TextInput(
                            value = phone,
                            onValueChange = { phone = it },
                            placeholder = "+1 ...",
                            mono = true,
                        )
                    }
                    Field(label = stringResource(R.string.ssn)) {
                        TextInput(
                            value = identitySsn,
                            onValueChange = { identitySsn = it },
                            placeholder = stringResource(R.string.protected_when_the_item_is),
                            mono = true,
                            password = true,
                        )
                    }
                    Field(label = stringResource(R.string.passport_number)) {
                        TextInput(
                            value = identityPassport,
                            onValueChange = { identityPassport = it },
                            placeholder = stringResource(R.string.protected_when_the_item_is),
                            mono = true,
                            password = true,
                        )
                    }
                }
                AddItemKind.Ssh -> {
                    Field(
                        label = stringResource(R.string.private_key),
                        hint = stringResource(R.string.paste_an_openssh_private_key_its),
                    ) {
                        MultilineInput(
                            value = sshPriv,
                            onValueChange = { sshPriv = it },
                            placeholder = stringResource(R.string.paste_an_openssh_private_key),
                            mono = true,
                            minLines = 5,
                        )
                    }
                    Field(label = stringResource(R.string.passphrase), hint = stringResource(R.string.stored_only_when_the_key_is)) {
                        TextInput(
                            value = sshPassphrase,
                            onValueChange = { sshPassphrase = it },
                            placeholder = stringResource(R.string.optional),
                            password = true,
                        )
                    }
                }
            }

            Field(label = stringResource(R.string.folder)) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(c.surfaceSunken, RoundedCornerShape(8.dp))
                        .border(1.dp, c.border, RoundedCornerShape(8.dp))
                        .clickable { showFolderSheet = true }
                        .padding(horizontal = 12.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    val current = folders.firstOrNull { it.id == folderId }
                    Icon(
                        imageVector = Icons.Outlined.Folder,
                        contentDescription = null,
                        tint = if (folderId != null) c.accent else c.fgSecondary,
                        modifier = Modifier.size(16.dp),
                    )
                    Text(
                        text = current?.name ?: stringResource(R.string.unfiled),
                        style = FolderTextStyle,
                        color = if (folderId != null) c.fgEmphasis else c.fgSecondary,
                        modifier = Modifier.weight(1f),
                    )
                    Icon(
                        imageVector = Icons.Outlined.KeyboardArrowDown,
                        contentDescription = null,
                        tint = c.fgSecondary,
                        modifier = Modifier.size(14.dp),
                    )
                }
            }

            ProtectToggleRow(
                protect = protect,
                onChange = { protect = it },
            )
            Spacer(modifier = Modifier.height(14.dp))

            // `willWrap` as well as `protect`: a note's body is encrypted on
            // every save regardless of the toggle, so hiding the recipient set
            // when it is off would hide the one list that says who can read it.
            if (protect || willWrap) {
                Field(
                    label = stringResource(R.string.unlock_recipients),
                    // The set is not "selected" by anyone here: the shared policy
                    // in core/src/policy.rs picks it, and `create` ignores
                    // whatever this screen puts in `VaultItem.recipients`. Saying
                    // "selected" implied a choice the composer never had.
                    hint = stringResource(R.string.any_one_of_these_can_decrypt),
                ) {
                    RecipientSummary(targets = wrapTargets, openableHere = openableHere)
                }
            }
        }
    }

    if (confirmUnopenable) {
        UnopenableSaveDialog(
            targets = wrapTargets,
            onDismiss = { confirmUnopenable = false },
            onConfirm = {
                confirmUnopenable = false
                performSave()
            },
        )
    }

    MoveToFolderSheet(
        open = showFolderSheet,
        onClose = { showFolderSheet = false },
        folders = folders,
        currentId = folderId,
        onPick = { folderId = it.id },
    )

    PasswordGeneratorSheet(
        open = showGeneratorSheet,
        onClose = { showGeneratorSheet = false },
        onUse = { password = it },
    )
}

@Composable
private fun ProtectToggleRow(
    protect: Boolean,
    onChange: (Boolean) -> Unit,
) {
    val c = rageColors
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(if (protect) c.tile else c.surfaceSunken, RoundedCornerShape(10.dp))
            .border(
                1.dp,
                if (protect) c.accent else c.border,
                RoundedCornerShape(10.dp),
            )
            .clickable { onChange(!protect) }
            .padding(horizontal = 14.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Box(
            modifier = Modifier
                .size(36.dp)
                .background(c.surface, RoundedCornerShape(8.dp))
                .border(1.dp, c.border, RoundedCornerShape(8.dp)),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                imageVector = Icons.Outlined.Link,
                contentDescription = null,
                tint = if (protect) c.accent else c.fgSecondary,
                modifier = Modifier.size(18.dp),
            )
        }
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = stringResource(R.string.protect_with_ragedroid),
                style = RageType.rowTitle.copy(fontSize = 15.sp, lineHeight = 19.sp),
                color = c.fgEmphasis,
            )
            Spacer(modifier = Modifier.height(2.dp))
            Text(
                text = stringResource(R.string.each_reveal_will_require_a_tap),
                style = RageType.caption.copy(fontSize = 12.sp, lineHeight = 17.sp),
                color = c.fgSecondary,
            )
        }
        ProtectSwitch(on = protect)
    }
}

@Composable
private fun ProtectSwitch(on: Boolean) {
    val c = rageColors
    val knobOffset by animateDpAsState(targetValue = if (on) 18.dp else 2.dp, label = stringResource(R.string.knob))
    Box(
        modifier = Modifier
            .width(40.dp)
            .height(24.dp)
            .background(if (on) c.accent else c.border, RoundedCornerShape(12.dp)),
    ) {
        Box(
            modifier = Modifier
                .offset(x = knobOffset, y = 2.dp)
                .size(20.dp)
                .background(Color(0xFFFAF6EE), RoundedCornerShape(10.dp)),
        )
    }
}

/**
 * One recipient the encrypt path will wrap to, and whether this device holds
 * material for it.
 */
private data class WrapTarget(val recipient: Recipient, val local: Boolean)

/**
 * The set `BitwardenVaultRepository.collectActiveRecipients()` will actually
 * wrap to: the cross-device registry unioned with this device's enrolments,
 * which is what the shared policy in `core/src/policy.rs` runs over.
 *
 * This screen used to read `LocalLiveRecipients` -- `recipientStore.forAccount`
 * -- which is only the local half of that. On a device with nothing enrolled the
 * chooser therefore rendered "Pick at least one recipient" with nothing to pick,
 * while the save still wrapped the item to whatever the registry carried (some
 * other device's paper key) and reported success. Showing one set and encrypting
 * to another is how an item ends up saved and unreadable on the same phone.
 *
 * Inclusion is NOT re-decided here. `data/RecipientPolicy.kt` says in as many
 * words not to write that `when` in Kotlin -- three clients each deciding for
 * themselves is the bug it was written to end -- so this runs the same
 * `RecipientPolicy.select` the repository runs and simply drops whatever the
 * policy reported as skipped. That is what keeps a `defaultEncrypt = false`
 * entry, an unparseable kind, and another device's PRF authenticator (skipped
 * `NO_LOCAL_AUTHENTICATOR`, since this phone cannot tap it during the wrap) out
 * of the chip list -- and out of the "can this device open it" gate below, which
 * would otherwise be satisfiable by a recipient that is never wrapped in.
 *
 * Reading the registry needs the Hilt graph and a live repository, and the
 * policy call needs the native lib; a preview or a Robolectric render has
 * neither. That falls back to the local half -- the same set this screen showed
 * before -- never to a claim of more coverage than could be confirmed.
 */
@Composable
private fun rememberWrapTargets(localFallback: ImmutableList<Recipient>): List<WrapTarget> {
    val context = androidx.compose.ui.platform.LocalContext.current
    return remember(context, localFallback) {
        runCatching { collectWrapTargets(context) }
            .getOrElse { localFallback.map { WrapTarget(it, local = true) } }
    }
}

private fun collectWrapTargets(context: android.content.Context): List<WrapTarget> {
    val repo = VaultBridge.repository() ?: error("no repository bound yet")
    val accountId = repo.accountId
    if (accountId.isBlank()) return emptyList()
    val store = context.appEntryPoint().recipientStore()
    val stored = store.forAccount(accountId)
    val storedById = stored.associateBy { it.id }
    val registry = RecipientRegistry(store)
    // `readEntries`, not `extractFromSnapshot`, for the reason
    // `collectActiveRecipients` gives: a registry this device cannot parse must
    // not read back as "no other recipients". It throws; the caller falls back
    // to the local half rather than drawing a set the save would not use.
    val registryEntries = registry.readEntries(repo.snapshotWithRegistryMarker())
    // The label lands in a wire display string the policy never reads -- the
    // chips render from `StoredRecipient` -- so it only has to be honest.
    val label = android.os.Build.MODEL ?: uiString(R.string.this_device_2)
    val localEntries = with(RecipientPolicy) { stored.map { it.toPolicyWire(label) } }

    val selection = RecipientPolicy.select(
        registry = registryEntries,
        local = localEntries,
        localPrfEntryIds = RecipientPolicy.localPrfEntryIds(stored),
    )
    val skippedIds = selection.skipped.map { it.id }.toSet()

    return with(registry) {
        mergeEntries(registryEntries, localEntries)
            .filterNot { it.id in skippedIds }
            .mapNotNull { entry ->
                val local = storedById[entry.id]
                if (local != null) {
                    WrapTarget(local.toUiRecipient(), local = true)
                } else {
                    // Already past the policy's UnknownKind skip, so this only
                    // returns null if the enum and `is_known_kind` disagree.
                    entry.toStored()?.toUiRecipient()?.let { WrapTarget(it, local = false) }
                }
            }
    }
}

/**
 * `policy::merge_entries` in Kotlin: the local copy of an id wins over the
 * registry copy, and the result is ordered by `(createdAt, id)` so the chips
 * appear in the order the item's stanzas will be written.
 *
 * This is ordering and de-duplication, not selection -- which recipients are in
 * belongs to core and stays there.
 */
private fun mergeEntries(
    registry: List<RecipientRegistry.WireEntry>,
    local: List<RecipientRegistry.WireEntry>,
): List<RecipientRegistry.WireEntry> {
    val byId = LinkedHashMap<String, RecipientRegistry.WireEntry>()
    for (entry in registry) byId[entry.id] = entry
    for (entry in local) byId[entry.id] = entry
    return byId.values.sortedWith(compareBy({ it.createdAt }, { it.id }))
}

@Composable
private fun UnopenableSaveDialog(
    targets: List<WrapTarget>,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit,
) {
    val c = rageColors
    val names = targets.joinToString(", ") { it.recipient.name }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.this_device_can_t_open_this)) },
        text = {
            Text(
                // Precise about *why*: a paper identity enrolled here is in the
                // set and is still not something this screen can promise a
                // reveal from -- IdentityResolver deliberately refuses it outside
                // Settings -> Recover from phrase.
                text = androidx.compose.ui.res.pluralStringResource(R.plurals.no_recipient_unlocks_here, targets.size, targets.size, names),
                style = RageType.body.copy(fontSize = 14.sp, lineHeight = 20.sp),
                color = c.fgPrimary,
            )
        },
        // Backwards on purpose. M3 puts `confirmButton` in the prominent
        // trailing slot, and the prominent action here has to be the one that
        // does not write an item the user cannot read back. Dismissing the
        // dialog any other way -- back, tap-outside -- lands on Cancel too.
        confirmButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) }
        },
        dismissButton = {
            TextButton(onClick = onConfirm) { Text(stringResource(R.string.save_anyway)) }
        },
    )
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun RecipientSummary(targets: List<WrapTarget>, openableHere: Boolean) {
    val c = rageColors
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(c.surfaceSunken, RoundedCornerShape(8.dp))
            .border(1.dp, if (openableHere) c.border else c.warning, RoundedCornerShape(8.dp))
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Column(modifier = Modifier.weight(1f)) {
            if (targets.isEmpty()) {
                Text(
                    text = stringResource(R.string.no_recipients_nothing_can_decrypt_this),
                    style = RageType.sansBody.copy(fontSize = 13.sp, lineHeight = 17.sp),
                    color = c.warning,
                )
            } else {
                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    targets.forEach { t ->
                        RecipientChip(
                            name = t.recipient.name,
                            kind = t.recipient.kind,
                            local = t.local,
                        )
                    }
                }
            }
            if (targets.isNotEmpty() && !openableHere) {
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = stringResource(R.string.none_of_these_are_keys_this),
                    style = RageType.caption.copy(fontSize = 11.5.sp, lineHeight = 16.sp),
                    color = c.warning,
                )
            }
        }
        Icon(
            imageVector = Icons.AutoMirrored.Outlined.KeyboardArrowRight,
            contentDescription = null,
            tint = c.fgSecondary,
            modifier = Modifier.size(14.dp),
        )
    }
}

@Composable
private fun RecipientChip(name: String, kind: RecipientKind, local: Boolean) {
    val c = rageColors
    val dotColor = when (kind) {
        RecipientKind.YubiKey -> c.accent
        RecipientKind.Fido2 -> c.info
        RecipientKind.PasskeyPrf -> c.info
        RecipientKind.StrongBox -> c.success
        RecipientKind.Recovery -> c.warning
        RecipientKind.Software -> c.fgSecondary
    }
    Row(
        modifier = Modifier
            .background(c.tile, RoundedCornerShape(12.dp))
            .padding(horizontal = 8.dp, vertical = 3.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(5.dp),
    ) {
        Box(
            modifier = Modifier
                .size(8.dp)
                .background(dotColor, RoundedCornerShape(4.dp)),
        )
        Text(
            // A chip for a registry-only key must say so: the user is looking at
            // this list to answer "can I open this again", and a name alone does
            // not distinguish their phone's key from their laptop's.
            text = if (local) name else stringResource(R.string.other_device, name),
            style = RageType.sansBody.copy(
                fontSize = 12.sp,
                lineHeight = 16.sp,
                fontWeight = FontWeight.Medium,
            ),
            color = if (local) c.fgEmphasis else c.fgSecondary,
        )
    }
}

@Composable
private fun MultilineInput(
    value: String,
    onValueChange: (String) -> Unit,
    placeholder: String,
    mono: Boolean,
    minLines: Int,
) {
    val c = rageColors
    val style = if (mono) NoteMonoStyle.copy(color = c.fgPrimary) else NotePlainStyle.copy(color = c.fgPrimary)
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .background(c.surfaceSunken, RoundedCornerShape(8.dp))
            .border(1.dp, c.border, RoundedCornerShape(8.dp))
            .padding(horizontal = 12.dp, vertical = 10.dp),
    ) {
        BasicTextField(
            value = value,
            onValueChange = onValueChange,
            textStyle = style,
            cursorBrush = SolidColor(c.accent),
            visualTransformation = VisualTransformation.None,
            minLines = minLines,
            modifier = Modifier.fillMaxWidth(),
            decorationBox = { inner ->
                if (value.isEmpty()) {
                    Text(
                        text = placeholder,
                        style = style.copy(color = c.fgSecondary),
                    )
                }
                inner()
            },
        )
    }
}

private fun namePlaceholder(kind: AddItemKind): String = when (kind) {
    AddItemKind.Login -> uiString(R.string.e_g_stripe_production)
    AddItemKind.Card -> uiString(R.string.e_g_amex_personal)
    AddItemKind.Note -> uiString(R.string.e_g_apartment_alarm_code)
    AddItemKind.Identity -> uiString(R.string.e_g_maya_primary)
    AddItemKind.Ssh -> uiString(R.string.e_g_ed25519_laptop)
}

internal fun unsavableReason(kind: AddItemKind, hasRepo: Boolean): String = when {
    !hasRepo -> uiString(R.string.not_saved_sign_in_first)
    kind == AddItemKind.Login -> uiString(R.string.not_saved_enter_a_password_to)
    else -> uiString(R.string.not_saved_has_nothing_to_save, uiString(kind.label))
}

/** A card, identity or SSH key split into its Bitwarden block and what the rage blob seals. */
internal data class TypedFields(
    val kind: VaultItemKind,
    val block: Map<String, String>,
    val secrets: Map<String, String>,
    val problem: String? = null,
)

internal fun typedFields(
    kind: AddItemKind,
    cardholder: String = "",
    cardNumber: String = "",
    cardExp: String = "",
    cardCvv: String = "",
    firstName: String = "",
    lastName: String = "",
    email: String = "",
    phone: String = "",
    ssn: String = "",
    passport: String = "",
    sshPrivateKey: String = "",
    sshPassphrase: String = "",
    protect: Boolean,
): TypedFields? {
    val (itemKind, values) = when (kind) {
        AddItemKind.Card -> {
            val (month, year) = cardExp.split('/').map(String::trim).let { it.getOrElse(0) { "" } to it.getOrElse(1) { "" } }
            VaultItemKind.Card to mapOf(
                "cardholderName" to cardholder.trim(),
                "number" to cardNumber.filterNot(Char::isWhitespace),
                "expMonth" to month,
                "expYear" to year,
                "code" to cardCvv.trim(),
            )
        }
        AddItemKind.Identity -> VaultItemKind.Identity to mapOf(
            "firstName" to firstName.trim(),
            "lastName" to lastName.trim(),
            "email" to email.trim(),
            "phone" to phone.trim(),
            "ssn" to ssn.trim(),
            "passportNumber" to passport.trim(),
        )
        AddItemKind.Ssh -> {
            if (sshPrivateKey.isBlank()) {
                return TypedFields(VaultItemKind.SshKey, emptyMap(), emptyMap(), uiString(R.string.not_saved_paste_the_private_key))
            }
            val pub = ragewarden.ragedroid.data.OpenSshKeys.publicOf(sshPrivateKey)
                ?: return TypedFields(
                    VaultItemKind.SshKey,
                    emptyMap(),
                    emptyMap(),
                    uiString(R.string.not_saved_paste_an_openssh_private),
                )
            if (!protect && sshPassphrase.isNotEmpty()) {
                return TypedFields(
                    VaultItemKind.SshKey,
                    emptyMap(),
                    emptyMap(),
                    uiString(R.string.not_saved_a_passphrase_is_only),
                )
            }
            VaultItemKind.SshKey to mapOf(
                "privateKey" to sshPrivateKey.trim() + "\n",
                "publicKey" to pub.publicKey,
                "keyFingerprint" to pub.fingerprint,
                "passphrase" to sshPassphrase,
            )
        }
        else -> return null
    }
    val nonEmpty = values.filterValues { it.isNotEmpty() }
    if (nonEmpty.isEmpty()) return TypedFields(itemKind, emptyMap(), emptyMap(), uiString(R.string.not_saved_has_nothing_to_save, uiString(kind.label)))
    val secrets = if (protect) nonEmpty.filterKeys { it in ragewarden.ragedroid.data.ItemFields.defaultProtected(itemKind) } else emptyMap()
    return TypedFields(itemKind, nonEmpty - secrets.keys - "passphrase", secrets)
}

/** "Also keep this field behind the tap" for one more field of a protected login. */
@Composable
private fun ProtectFieldRow(label: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .toggleable(value = checked, role = androidx.compose.ui.semantics.Role.Checkbox, onValueChange = onChange),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        androidx.compose.material3.Checkbox(checked = checked, onCheckedChange = null)
        Text(text = label, style = RageType.caption, color = rageColors.fgPrimary, modifier = Modifier.padding(start = 12.dp))
    }
}
