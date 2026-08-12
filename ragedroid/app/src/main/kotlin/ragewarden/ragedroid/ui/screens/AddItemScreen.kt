package ragewarden.ragedroid.ui.screens

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
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.collections.immutable.ImmutableList
import kotlinx.collections.immutable.persistentListOf
import kotlinx.collections.immutable.toPersistentList
import kotlinx.coroutines.launch
import androidx.compose.runtime.rememberCoroutineScope
import ragewarden.ragedroid.data.RecipientPolicy
import ragewarden.ragedroid.data.RecipientRegistry
import ragewarden.ragedroid.data.VaultBackend
import ragewarden.ragedroid.data.VaultBridge
import ragewarden.ragedroid.data.toUiRecipient
import ragewarden.ragedroid.di.appEntryPoint
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

data class AddItemDraft(
    val kind: AddItemKind,
    val name: String,
    val folder: String?,
    val rage: Boolean,
    val recipientIds: ImmutableList<String>,
    val username: String = "",
    val site: String = "",
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

private val DEFAULT_FOLDER_OPTIONS: ImmutableList<FolderOption> = persistentListOf(
    FolderOption(id = null, name = "Unfiled", color = null),
    FolderOption(id = "Work", name = "Work", color = Color(0xFFC8552B)),
    FolderOption(id = "Personal", name = "Personal", color = Color(0xFF6B8E5A)),
    FolderOption(id = "Infrastructure", name = "Infrastructure", color = Color(0xFF3A6B8E)),
    FolderOption(id = "Family", name = "Family", color = Color(0xFFB57A2A)),
    FolderOption(id = "Archive", name = "Archive", color = Color(0xFF8C7B6B)),
)

private val FolderTextStyle = TextStyle(
    fontFamily = Sans,
    fontWeight = FontWeight.Normal,
    fontSize = 13.5.sp,
    lineHeight = 18.sp,
)

private val SshKeyTabStyle = TextStyle(
    fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
    fontWeight = FontWeight.SemiBold,
    fontSize = 12.sp,
    lineHeight = 16.sp,
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
    folderOptions: ImmutableList<FolderOption> = DEFAULT_FOLDER_OPTIONS,
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
    var password by remember(existing?.id) { mutableStateOf("") }
    var notes by remember(existing?.id) { mutableStateOf(existing?.notes ?: "") }

    var cardholder by remember(existing?.id) { mutableStateOf("") }
    var cardNumber by remember(existing?.id) { mutableStateOf("") }
    var cardExp by remember(existing?.id) { mutableStateOf("") }
    var cardCvv by remember(existing?.id) { mutableStateOf("") }

    var firstName by remember(existing?.id) { mutableStateOf("") }
    var lastName by remember(existing?.id) { mutableStateOf("") }
    var email by remember(existing?.id) { mutableStateOf("") }
    var phone by remember(existing?.id) { mutableStateOf("") }

    var sshType by remember(existing?.id) { mutableStateOf("ed25519") }
    var sshPriv by remember(existing?.id) { mutableStateOf("") }

    val initialFolder = existing?.folder?.takeIf { it.isNotBlank() && it != "All" }
    var folderId by remember(existing?.id) { mutableStateOf<String?>(initialFolder) }
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
        AddItemKind.Login to "New login",
        AddItemKind.Card to "New card",
        AddItemKind.Note to "New note",
        AddItemKind.Identity to "New identity",
        AddItemKind.Ssh to "New SSH key",
    )
    val titleEdit = mapOf(
        AddItemKind.Login to "Edit login",
        AddItemKind.Card to "Edit card",
        AddItemKind.Note to "Edit note",
        AddItemKind.Identity to "Edit identity",
        AddItemKind.Ssh to "Edit SSH key",
    )
    val title = if (isEdit) titleEdit[kind] ?: "Edit item" else titleNew[kind] ?: "New item"

    // Mirrors the `plaintext` computation in `performSave` below: whether this
    // save has a secret to wrap at all.
    val hasSecret = when (kind) {
        AddItemKind.Login -> password.isNotEmpty()
        AddItemKind.Note -> true
        AddItemKind.Ssh -> sshPriv.isNotEmpty()
        else -> false
    }
    // NOT `protect`. `BitwardenVaultRepository.create` calls
    // `encryptForActiveRecipients` unconditionally -- it never reads
    // `item.rage` -- so a secret reaching a live repository is wrapped whatever
    // the toggle says, and a kind with no secret (card, identity) is wrapped
    // never. Gating on the toggle would be both bypassable and, for those
    // kinds, a refusal to save something that was never going to be encrypted.
    val willWrap = repo != null && hasSecret

    val performSave: () -> Unit = {
        val draft = AddItemDraft(
            kind = kind,
            name = name.ifBlank { "Untitled ${kind.label}" },
            folder = folderId,
            rage = protect,
            recipientIds = recipientIds,
            username = username,
            site = site,
            notes = notes,
            cardholder = cardholder,
            cardNumber = cardNumber,
            cardExp = cardExp,
            cardCvv = cardCvv,
            firstName = firstName,
            lastName = lastName,
            email = email,
            phone = phone,
            sshType = sshType,
            sshPrivateKey = sshPriv,
        )
        val plaintext = when (kind) {
            AddItemKind.Login -> if (password.isNotEmpty()) password.toByteArray(Charsets.UTF_8) else null
            AddItemKind.Note -> notes.toByteArray(Charsets.UTF_8)
            AddItemKind.Ssh -> if (sshPriv.isNotEmpty()) sshPriv.toByteArray(Charsets.UTF_8) else null
            else -> null
        }
        if (repo != null && plaintext != null) {
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
                folder = folderOptions.firstOrNull { it.id == draft.folder }?.name ?: "All",
                rage = draft.rage,
                recipients = draft.recipientIds,
                password = "",
                notes = draft.notes.ifBlank { null },
                lastUsed = "",
                history = 0,
                kind = itemKindMapped,
            )
            scope.launch {
                val result = runCatching { repo.create(newItem, plaintext) }
                if (result.isSuccess) {
                    onSave(draft, plaintext)
                } else {
                    val msg = result.exceptionOrNull()?.message
                        ?: result.exceptionOrNull()?.javaClass?.simpleName
                        ?: "save failed"
                    onToast("Save failed: $msg")
                }
                plaintext.fill(0)
            }
        } else {
            onSave(draft, plaintext)
            plaintext?.fill(0)
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
                "Not saving: there is no recipient to encrypt to. Enrol a key on this " +
                    "device first.",
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
                    contentDescription = "Cancel",
                    onClick = onBack,
                )
            },
            trailing = {
                RageButton(
                    label = "Save",
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
            Field(label = "Name") {
                TextInput(
                    value = name,
                    onValueChange = { name = it },
                    placeholder = namePlaceholder(kind),
                )
            }

            when (kind) {
                AddItemKind.Login -> {
                    Field(label = "Website") {
                        TextInput(
                            value = site,
                            onValueChange = { site = it },
                            placeholder = "dashboard.stripe.com",
                            mono = true,
                        )
                    }
                    Field(label = "Username") {
                        TextInput(
                            value = username,
                            onValueChange = { username = it },
                            placeholder = "you@example.com",
                        )
                    }
                    Field(
                        label = "Password",
                        hint = "Generate a strong password -- RageDroid will encrypt it before saving.",
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
                                    mono = true,
                                    password = true,
                                )
                            }
                            RageButton(
                                label = "Gen",
                                onClick = { showGeneratorSheet = true },
                                icon = Icons.Outlined.Refresh,
                                variant = ButtonVariant.Secondary,
                                size = ButtonSize.Sm,
                            )
                        }
                    }
                }
                AddItemKind.Card -> {
                    Field(label = "Cardholder") {
                        TextInput(
                            value = cardholder,
                            onValueChange = { cardholder = it },
                            placeholder = "Maya Voss",
                        )
                    }
                    Field(label = "Card number") {
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
                            Field(label = "Expiry") {
                                TextInput(
                                    value = cardExp,
                                    onValueChange = { cardExp = it },
                                    placeholder = "MM / YY",
                                    mono = true,
                                )
                            }
                        }
                        Box(modifier = Modifier.weight(1f)) {
                            Field(label = "CVV") {
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
                        label = "Note",
                        hint = "Plaintext encrypted under your recipients. No structure.",
                    ) {
                        MultilineInput(
                            value = notes,
                            onValueChange = { notes = it },
                            placeholder = "Anything that should never be in plaintext.",
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
                            Field(label = "First name") {
                                TextInput(
                                    value = firstName,
                                    onValueChange = { firstName = it },
                                    placeholder = "Maya",
                                )
                            }
                        }
                        Box(modifier = Modifier.weight(1f)) {
                            Field(label = "Last name") {
                                TextInput(
                                    value = lastName,
                                    onValueChange = { lastName = it },
                                    placeholder = "Voss",
                                )
                            }
                        }
                    }
                    Field(label = "Email") {
                        TextInput(
                            value = email,
                            onValueChange = { email = it },
                            placeholder = "name@example.com",
                        )
                    }
                    Field(label = "Phone") {
                        TextInput(
                            value = phone,
                            onValueChange = { phone = it },
                            placeholder = "+1 ...",
                            mono = true,
                        )
                    }
                }
                AddItemKind.Ssh -> {
                    Field(label = "Key type") {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(c.tile, RoundedCornerShape(8.dp))
                                .padding(3.dp),
                        ) {
                            listOf("ed25519", "rsa-4096", "ecdsa-p256").forEach { k ->
                                Box(
                                    modifier = Modifier
                                        .weight(1f)
                                        .background(
                                            if (sshType == k) c.surface else Color.Transparent,
                                            RoundedCornerShape(6.dp),
                                        )
                                        .clickable { sshType = k }
                                        .padding(horizontal = 8.dp, vertical = 8.dp),
                                    contentAlignment = Alignment.Center,
                                ) {
                                    Text(
                                        text = k,
                                        style = SshKeyTabStyle,
                                        color = if (sshType == k) c.fgEmphasis else c.fgSecondary,
                                    )
                                }
                            }
                        }
                    }
                    Field(
                        label = "Private key",
                        hint = "Paste an existing key, or tap Generate to create one on this device.",
                    ) {
                        Column {
                            MultilineInput(
                                value = sshPriv,
                                onValueChange = { sshPriv = it },
                                placeholder = "-----BEGIN OPENSSH PRIVATE KEY-----...",
                                mono = true,
                                minLines = 5,
                            )
                            Spacer(modifier = Modifier.height(8.dp))
                            RageButton(
                                label = "Generate $sshType",
                                onClick = {
                                    sshPriv =
                                        "-----BEGIN OPENSSH PRIVATE KEY-----\n...generated on device...\n-----END OPENSSH PRIVATE KEY-----"
                                },
                                icon = Icons.Outlined.Refresh,
                                variant = ButtonVariant.Secondary,
                                size = ButtonSize.Sm,
                            )
                        }
                    }
                }
            }

            Field(label = "Folder") {
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
                    val current = folderOptions.firstOrNull { it.id == folderId }
                    Icon(
                        imageVector = Icons.Outlined.Folder,
                        contentDescription = null,
                        tint = if (folderId != null) c.accent else c.fgSecondary,
                        modifier = Modifier.size(16.dp),
                    )
                    Text(
                        text = current?.name ?: "Unfiled",
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
                    label = "Unlock recipients",
                    // The set is not "selected" by anyone here: the shared policy
                    // in core/src/policy.rs picks it, and `create` ignores
                    // whatever this screen puts in `VaultItem.recipients`. Saying
                    // "selected" implied a choice the composer never had.
                    hint = "Any one of these can decrypt this item. The set comes from " +
                        "your recipient registry plus the keys enrolled here.",
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
        folders = folderOptions,
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
                text = "Protect with RageDroid",
                style = RageType.rowTitle.copy(fontSize = 15.sp, lineHeight = 19.sp),
                color = c.fgEmphasis,
            )
            Spacer(modifier = Modifier.height(2.dp))
            Text(
                text = "Each reveal will require a tap on one of the recipients below.",
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
    val knobOffset by animateDpAsState(targetValue = if (on) 18.dp else 2.dp, label = "knob")
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
    val label = android.os.Build.MODEL ?: "this device"
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
        title = { Text("This device can't open this item") },
        text = {
            Text(
                // Precise about *why*: a paper identity enrolled here is in the
                // set and is still not something this screen can promise a
                // reveal from -- IdentityResolver deliberately refuses it outside
                // Settings -> Recover from phrase.
                text = "Nothing in the recipient set is a key this device can unlock with. " +
                    "Saving encrypts to ${targets.size} " +
                    "recipient${if (targets.size == 1) "" else "s"} ($names) that either live " +
                    "on other devices or, like a paper identity, only work through " +
                    "Settings -> Recover from phrase. The item will be listed here and will " +
                    "not open here.\n\n" +
                    "Enrol a key on this device and it is included from the next save on.",
                style = RageType.body.copy(fontSize = 14.sp, lineHeight = 20.sp),
                color = c.fgPrimary,
            )
        },
        // Backwards on purpose. M3 puts `confirmButton` in the prominent
        // trailing slot, and the prominent action here has to be the one that
        // does not write an item the user cannot read back. Dismissing the
        // dialog any other way -- back, tap-outside -- lands on Cancel too.
        confirmButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
        dismissButton = {
            TextButton(onClick = onConfirm) { Text("Save anyway") }
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
                    text = "No recipients -- nothing can decrypt this item",
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
                    text = "None of these are keys this device can unlock with.",
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
            text = if (local) name else "$name · other device",
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
    AddItemKind.Login -> "e.g. Stripe -- production"
    AddItemKind.Card -> "e.g. Amex -- personal"
    AddItemKind.Note -> "e.g. Apartment alarm code"
    AddItemKind.Identity -> "e.g. Maya -- primary"
    AddItemKind.Ssh -> "e.g. ed25519 -- laptop"
}
