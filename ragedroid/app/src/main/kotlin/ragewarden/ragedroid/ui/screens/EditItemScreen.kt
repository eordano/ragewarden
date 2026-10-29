package ragewarden.ragedroid.ui.screens

import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.lazy.items
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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material.icons.outlined.Visibility
import androidx.compose.material.icons.outlined.VisibilityOff
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import ragewarden.ragedroid.R
import ragewarden.ragedroid.identities.StanzaTags
import ragewarden.ragedroid.model.VaultItem
import ragewarden.ragedroid.ui.components.buttonTarget
import ragewarden.ragedroid.ui.components.AppBar
import ragewarden.ragedroid.ui.components.Field
import ragewarden.ragedroid.ui.components.IconBtn
import ragewarden.ragedroid.ui.components.RecipientPip
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors

@Composable
fun EditItemScreen(
    item: VaultItem,
    onCancel: () -> Unit,
    onSave: (ragewarden.ragedroid.data.ItemEdit) -> Unit,
    decryptCurrent: suspend () -> ByteArray?,
) {
    val c = rageColors
    val scope = rememberCoroutineScope()
    val liveRecipients = ragewarden.ragedroid.ui.LocalLiveRecipients.current
    // `item.recipients` holds the stanza descriptors the JNI layer parses out of
    // the blob's own age header ("piv-p256:<b64>"), not recipient ids -- see
    // data/RecipientDescriptors.kt. `Recipient.id` is a UUID, so `it.id in
    // item.recipients` intersected two disjoint namespaces and this list was
    // permanently empty: every protected item claimed to have no recipients at
    // all. Same fix as ItemDetailScreen.kt:159, MultiIdentityPickerSheet.kt:51
    // and TapFailureScreen.kt:74.
    val owned = remember(item.id, item.recipients, liveRecipients) {
        val descriptorSet = item.recipients.toSet()
        liveRecipients.filter { r -> r.descriptors.any { it in descriptorSet } }
    }
    /** X25519/scrypt stanzas: real recipients no age header can name. */
    val anonymousRecipientCount = remember(item.recipients) {
        item.recipients.count { it == StanzaTags.X25519 || it == StanzaTags.SCRYPT }
    }

    var name by remember(item.id) { mutableStateOf(item.name) }
    var username by remember(item.id) { mutableStateOf(item.username) }
    var newPassword by remember(item.id) { mutableStateOf("") }
    // A login's TOTP seed and notes may be protected too: then the field is a
    // "new value" (blank keeps it), like the password. An unprotected one can
    // be moved behind the tap.
    val loginProtected = remember(item.id) { ragewarden.ragedroid.data.ItemFields.protectedFields(item).toSet() }
    val totpProtected = "totp" in loginProtected
    val notesProtected = "notes" in loginProtected && item.kind == ragewarden.ragedroid.model.VaultItemKind.Login
    var protectTotpNow by remember(item.id) { mutableStateOf(false) }
    var protectNotesNow by remember(item.id) { mutableStateOf(false) }
    var totp by remember(item.id) { mutableStateOf(if (totpProtected) "" else item.totpSeed ?: "") }
    var notes by remember(item.id) { mutableStateOf(if ("notes" in ragewarden.ragedroid.data.ItemFields.protectedFields(item) && item.kind == ragewarden.ragedroid.model.VaultItemKind.Login) "" else item.notes ?: "") }
    var revealedCurrent by remember(item.id) { mutableStateOf<ByteArray?>(null) }
    val revealedCurrentText = remember(revealedCurrent) { revealedCurrent?.let { String(it, Charsets.UTF_8) } }
    val isProtectedNote = item.rage && item.kind == ragewarden.ragedroid.model.VaultItemKind.Note
    var sshFromNote by remember(item.id) { mutableStateOf<ragewarden.ragedroid.data.OpenSshKeys.Public?>(null) }
    var migrateNote by remember(item.id) { mutableStateOf(false) }
    val protectedNames = remember(item.id) { ragewarden.ragedroid.data.ItemFields.protectedFields(item) }
    val typedFieldNames = remember(item.id) { typedEditFields(item) }
    val typedValues = remember(item.id) {
        androidx.compose.runtime.mutableStateMapOf<String, String>().apply {
            typedFieldNames.filter { it !in protectedNames }.forEach { put(it, item.block[it] ?: "") }
        }
    }
    var showCurrent by remember(item.id) { mutableStateOf(false) }

    DisposableEffect(item.id) {
        onDispose {
            revealedCurrent?.fill(0)
        }
    }

    Column(modifier = Modifier.fillMaxSize().background(c.background)) {
        AppBar(
            title = stringResource(R.string.edit),
            subtitle = item.site.ifBlank { item.name },
            leading = {
                IconBtn(
                    icon = Icons.AutoMirrored.Outlined.ArrowBack,
                    contentDescription = stringResource(R.string.cancel),
                    onClick = onCancel,
                )
            },
            trailing = {
                Box(
                    modifier = Modifier
                        .background(c.accent, RoundedCornerShape(6.dp))
                        .buttonTarget {
                            onSave(
                                when {
                                    item.kind == ragewarden.ragedroid.model.VaultItemKind.Login -> {
                                        val sealTotp = totpProtected || protectTotpNow
                                        val sealNotes = notesProtected || protectNotesNow
                                        ragewarden.ragedroid.data.ItemEdit(
                                            name = name,
                                            username = username,
                                            totp = totp.takeUnless { sealTotp },
                                            notes = notes.takeUnless { sealNotes },
                                            newSecret = newPassword.takeIf { it.isNotEmpty() }?.toByteArray(Charsets.UTF_8),
                                            secretChanges = buildMap {
                                                if (sealTotp && totp.isNotBlank()) put("totp", totp.trim())
                                                if (sealNotes && notes.isNotBlank()) put("notes", notes)
                                            }.takeIf { it.isNotEmpty() },
                                        )
                                    }
                                    isProtectedNote -> ragewarden.ragedroid.data.ItemEdit(
                                        name = name,
                                        newSecret = newPassword.takeIf { it.isNotEmpty() && !migrateNote }?.toByteArray(Charsets.UTF_8),
                                        migrateToSsh = sshFromNote.takeIf { migrateNote },
                                    )
                                    else -> typedEdit(item, name, notes, typedValues, protectedNames)
                                },
                            )
                        }
                        .padding(horizontal = 12.dp, vertical = 6.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        text = stringResource(R.string.save),
                        style = RageType.button,
                        color = c.background,
                    )
                }
            },
        )

        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 16.dp, vertical = 12.dp),
        ) {
            item("name") {
                Field(label = stringResource(R.string.name)) {
                    EditTextField(value = name, onValueChange = { name = it })
                }
            }
            if (item.kind == ragewarden.ragedroid.model.VaultItemKind.Login) {
                item("username") {
                    Field(label = stringResource(R.string.username)) {
                        EditTextField(value = username, onValueChange = { username = it })
                    }
                }
                item("password-current") {
                    Field(
                        label = stringResource(R.string.current_password),
                        hint = stringResource(R.string.tap_to_reveal_hidden_by_default),
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(c.surfaceSunken, RoundedCornerShape(8.dp))
                                .border(1.dp, c.border, RoundedCornerShape(8.dp))
                                .padding(horizontal = 12.dp, vertical = 12.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween,
                        ) {
                            val display = if (showCurrent && revealedCurrentText != null) {
                                revealedCurrentText
                            } else {
                                "••••••••••••"
                            }
                            Text(
                                text = display,
                                style = RageType.mono.copy(color = c.fgPrimary),
                                modifier = Modifier.weight(1f),
                            )
                            Box(
                                modifier = Modifier.buttonTarget {
                                    if (showCurrent) {
                                        revealedCurrent?.fill(0)
                                        revealedCurrent = null
                                        showCurrent = false
                                    } else {
                                        scope.launch {
                                            val pt = decryptCurrent()
                                            if (pt != null) {
                                                revealedCurrent?.fill(0)
                                                revealedCurrent = pt
                                                showCurrent = true
                                            }
                                        }
                                    }
                                },
                                contentAlignment = Alignment.Center,
                            ) {
                                Icon(
                                    imageVector = if (showCurrent) {
                                        Icons.Outlined.VisibilityOff
                                    } else {
                                        Icons.Outlined.Visibility
                                    },
                                    contentDescription = stringResource(R.string.reveal),
                                    tint = c.fgPrimary,
                                    modifier = Modifier.size(18.dp),
                                )
                            }
                        }
                    }
                }
                item("password-new") {
                    Field(
                        label = stringResource(R.string.new_password),
                        hint = stringResource(R.string.leave_blank_to_keep_the_current),
                    ) {
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Box(modifier = Modifier.weight(1f)) {
                                EditTextField(
                                    value = newPassword,
                                    onValueChange = { newPassword = it },
                                    password = true,
                                    placeholder = stringResource(R.string.type_or_generate),
                                )
                            }
                            Box(
                                modifier = Modifier
                                    .background(c.surface, RoundedCornerShape(8.dp))
                                    .border(1.dp, c.border, RoundedCornerShape(8.dp))
                                    .buttonTarget {
                                        newPassword = generateRandomPassword()
                                    }
                                    .padding(horizontal = 12.dp, vertical = 12.dp),
                                contentAlignment = Alignment.Center,
                            ) {
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(4.dp),
                                ) {
                                    Icon(
                                        imageVector = Icons.Outlined.Refresh,
                                        contentDescription = null,
                                        tint = c.fgPrimary,
                                        modifier = Modifier.size(14.dp),
                                    )
                                    Text(
                                        text = stringResource(R.string.gen),
                                        style = RageType.button,
                                        color = c.fgPrimary,
                                    )
                                }
                            }
                        }
                    }
                }
                item("totp") {
                    Field(
                        label = if (totpProtected) stringResource(R.string.new_totp_seed_protected) else stringResource(R.string.totp_seed),
                        hint = if (totpProtected) stringResource(R.string.blank_keeps_it) else stringResource(R.string.optional_either_an_otpauth_uri_or),
                    ) {
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Box(modifier = Modifier.weight(1f)) {
                                EditTextField(value = totp, onValueChange = { totp = it }, mono = true)
                            }
                            ragewarden.ragedroid.ui.components.TotpScanButton(onScanned = { totp = it })
                        }
                    }
                }
            } else if (isProtectedNote) {
                item("note-current") {
                    Field(label = stringResource(R.string.current_note), hint = stringResource(R.string.opening_it_costs_a_tap)) {
                        val shown = revealedCurrent
                        if (shown == null) {
                            ragewarden.ragedroid.ui.components.RageButton(
                                label = stringResource(R.string.open_note),
                                onClick = {
                                    scope.launch {
                                        val pt = decryptCurrent()
                                        if (pt != null) {
                                            revealedCurrent?.fill(0)
                                            revealedCurrent = pt
                                            sshFromNote = ragewarden.ragedroid.data.SecretText.withChars(pt) { ragewarden.ragedroid.data.OpenSshKeys.publicOf(it) }
                                            migrateNote = sshFromNote != null
                                        }
                                    }
                                },
                                fullWidth = true,
                            )
                        } else {
                            Text(text = revealedCurrentText.orEmpty(), style = RageType.mono.copy(color = c.fgPrimary))
                        }
                    }
                }
                if (sshFromNote != null) {
                    item("note-migrate") {
                        Field(
                            label = stringResource(R.string.this_note_is_an_ssh_key),
                            hint = stringResource(R.string.save_it_as_an_ssh_key),
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                androidx.compose.material3.Switch(checked = migrateNote, onCheckedChange = { migrateNote = it })
                                Text(
                                    text = if (migrateNote) stringResource(R.string.save_as_an_ssh_key) else stringResource(R.string.keep_as_a_note),
                                    style = RageType.body,
                                    color = c.fgPrimary,
                                    modifier = Modifier.padding(start = 10.dp),
                                )
                            }
                        }
                    }
                }
                if (!migrateNote) {
                    item("note-new") {
                        Field(label = stringResource(R.string.new_note), hint = stringResource(R.string.leave_blank_to_keep_the_current_2)) {
                            EditTextField(value = newPassword, onValueChange = { newPassword = it }, minLines = 3)
                        }
                    }
                }
            } else {
                items(typedFieldNames, key = { "field-$it" }) { field ->
                    val isProtected = field in protectedNames
                    Field(
                        label = if (isProtected) stringResource(R.string.new_, ragewarden.ragedroid.data.ItemFields.label(field).lowercase()) else ragewarden.ragedroid.data.ItemFields.label(field),
                        hint = if (isProtected) stringResource(R.string.protected_leave_blank_to_keep_it) else null,
                    ) {
                        EditTextField(
                            value = typedValues[field] ?: "",
                            onValueChange = { typedValues[field] = it },
                            password = isProtected,
                            mono = field != "cardholderName",
                            minLines = if (field == "privateKey") 4 else 1,
                        )
                    }
                }
            }
            if (item.rage && item.kind == ragewarden.ragedroid.model.VaultItemKind.Login && !totpProtected) {
                item("protect-totp") {
                    EditProtectRow(stringResource(R.string.protect_the_totp_seed), protectTotpNow) { protectTotpNow = it }
                }
            }
            if (!isProtectedNote) item("notes") {
                Field(
                    label = if (notesProtected) stringResource(R.string.new_notes_protected) else stringResource(R.string.notes),
                    hint = if (notesProtected) stringResource(R.string.blank_keeps_it) else null,
                ) {
                    EditTextField(
                        value = notes,
                        onValueChange = { notes = it },
                        minLines = 3,
                    )
                }
            }
            if (item.rage && item.kind == ragewarden.ragedroid.model.VaultItemKind.Login && !notesProtected) {
                item("protect-notes") {
                    EditProtectRow(stringResource(R.string.protect_the_notes), protectNotesNow) { protectNotesNow = it }
                }
            }
            if (item.rage) {
                item("recipients") {
                    Field(
                        label = stringResource(R.string.recipients_view_only),
                        hint = if (anonymousRecipientCount > 0) {
                            stringResource(R.string.any_one_of_these_can_open, anonymousRecipientCount)
                        } else {
                            stringResource(R.string.any_one_of_these_can_decrypt_2)
                        },
                    ) {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(c.surface, RoundedCornerShape(8.dp))
                                .border(1.dp, c.border, RoundedCornerShape(8.dp)),
                        ) {
                            owned.forEachIndexed { i, recipient ->
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
                                        Text(
                                            text = recipient.fingerprint,
                                            style = RageType.meta,
                                            color = c.fgSecondary,
                                        )
                                    }
                                }
                                if (i < owned.size - 1) {
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
            item("spacer") { Spacer(modifier = Modifier.height(40.dp)) }
        }
    }
}

@Composable
private fun EditTextField(
    value: String,
    onValueChange: (String) -> Unit,
    password: Boolean = false,
    mono: Boolean = false,
    minLines: Int = 1,
    placeholder: String? = null,
) {
    val c = rageColors
    val style = if (mono) {
        RageType.mono.copy(color = c.fgPrimary)
    } else {
        RageType.sansBody.copy(color = c.fgPrimary)
    }
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
            singleLine = minLines == 1,
            minLines = minLines,
            cursorBrush = SolidColor(c.accent),
            visualTransformation = if (password) PasswordVisualTransformation() else VisualTransformation.None,
            modifier = Modifier.fillMaxWidth(),
            decorationBox = { inner ->
                if (placeholder != null && value.isEmpty()) {
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

private fun generateRandomPassword(): String {
    val charset = ("abcdefghijklmnopqrstuvwxyz" +
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
        "0123456789!@#$%^&*()-_=+").toCharArray()
    val rng = java.security.SecureRandom()
    return (1..24).map { charset[rng.nextInt(charset.size)] }.joinToString("")
}


/** The fields the edit form offers for a card, identity or SSH key. */
internal fun typedEditFields(item: VaultItem): List<String> = when (item.kind) {
    ragewarden.ragedroid.model.VaultItemKind.Card -> ragewarden.ragedroid.data.ItemFields.CARD
    ragewarden.ragedroid.model.VaultItemKind.Identity -> listOf("firstName", "lastName", "email", "phone", "ssn", "passportNumber", "licenseNumber")
    ragewarden.ragedroid.model.VaultItemKind.SshKey -> listOf("privateKey") +
        listOf("passphrase").filter { it in ragewarden.ragedroid.data.ItemFields.protectedFields(item) }
    else -> emptyList()
}

/**
 * Splits the form into changed outer fields and new protected values. A new
 * SSH private key brings its public key and fingerprint with it.
 */
internal fun typedEdit(
    item: VaultItem,
    name: String,
    notes: String,
    values: Map<String, String>,
    protectedNames: List<String>,
): ragewarden.ragedroid.data.ItemEdit {
    val secrets = values.filterKeys { it in protectedNames }.filterValues { it.isNotEmpty() }
    val outer = values.filterKeys { it !in protectedNames }.toMutableMap()
    val newKey = secrets["privateKey"] ?: outer["privateKey"]?.takeIf { it != (item.block["privateKey"] ?: "") }
    newKey?.let(ragewarden.ragedroid.data.OpenSshKeys::publicOf)?.let { pub ->
        outer["publicKey"] = pub.publicKey
        outer["keyFingerprint"] = pub.fingerprint
    }
    return ragewarden.ragedroid.data.ItemEdit(
        name = name,
        notes = notes,
        block = outer,
        secretChanges = secrets.takeIf { it.isNotEmpty() },
    )
}

@Composable
private fun EditProtectRow(label: String, checked: Boolean, onChange: (Boolean) -> Unit) {
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
