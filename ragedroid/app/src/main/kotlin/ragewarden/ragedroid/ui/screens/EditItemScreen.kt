package ragewarden.ragedroid.ui.screens

import androidx.activity.compose.rememberLauncherForActivityResult
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
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.outlined.QrCodeScanner
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
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import kotlinx.coroutines.launch
import ragewarden.ragedroid.identities.StanzaTags
import ragewarden.ragedroid.model.VaultItem
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
    onSave: (ByteArray?) -> Unit,
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
    var totp by remember(item.id) { mutableStateOf(item.totpSeed ?: "") }
    var notes by remember(item.id) { mutableStateOf(item.notes ?: "") }
    var revealedCurrent by remember(item.id) { mutableStateOf<ByteArray?>(null) }
    var showCurrent by remember(item.id) { mutableStateOf(false) }

    val qrLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        val contents = result.contents
        if (!contents.isNullOrBlank()) {
            totp = contents
        }
    }

    DisposableEffect(item.id) {
        onDispose {
            revealedCurrent?.fill(0)
        }
    }

    Column(modifier = Modifier.fillMaxSize().background(c.background)) {
        AppBar(
            title = "Edit",
            subtitle = item.site.ifBlank { item.name },
            leading = {
                IconBtn(
                    icon = Icons.AutoMirrored.Outlined.ArrowBack,
                    contentDescription = "Cancel",
                    onClick = onCancel,
                )
            },
            trailing = {
                Box(
                    modifier = Modifier
                        .background(c.accent, RoundedCornerShape(6.dp))
                        .clickable {
                            val pt = if (newPassword.isNotEmpty()) {
                                newPassword.toByteArray(Charsets.UTF_8)
                            } else {
                                null
                            }
                            onSave(pt)
                            pt?.fill(0)
                        }
                        .padding(horizontal = 12.dp, vertical = 6.dp),
                ) {
                    Text(
                        text = "Save",
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
                Field(label = "Name") {
                    EditTextField(value = name, onValueChange = { name = it })
                }
            }
            item("username") {
                Field(label = "Username") {
                    EditTextField(value = username, onValueChange = { username = it })
                }
            }
            item("password-current") {
                Field(
                    label = "Current password",
                    hint = "Tap to reveal. Hidden by default.",
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
                        val display = if (showCurrent && revealedCurrent != null) {
                            String(revealedCurrent!!, Charsets.UTF_8)
                        } else {
                            "••••••••••••"
                        }
                        Text(
                            text = display,
                            style = RageType.mono.copy(color = c.fgPrimary),
                            modifier = Modifier.weight(1f),
                        )
                        Icon(
                            imageVector = if (showCurrent) {
                                Icons.Outlined.VisibilityOff
                            } else {
                                Icons.Outlined.Visibility
                            },
                            contentDescription = "Reveal",
                            tint = c.fgPrimary,
                            modifier = Modifier
                                .size(18.dp)
                                .clickable {
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
                        )
                    }
                }
            }
            item("password-new") {
                Field(
                    label = "New password",
                    hint = "Leave blank to keep the current password.",
                ) {
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Box(modifier = Modifier.weight(1f)) {
                            EditTextField(
                                value = newPassword,
                                onValueChange = { newPassword = it },
                                password = true,
                                placeholder = "type or generate...",
                            )
                        }
                        Box(
                            modifier = Modifier
                                .background(c.surface, RoundedCornerShape(8.dp))
                                .border(1.dp, c.border, RoundedCornerShape(8.dp))
                                .clickable {
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
                                    text = "Gen",
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
                    label = "TOTP seed",
                    hint = "Optional. Either an `otpauth://` URI or a base32 secret.",
                ) {
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Box(modifier = Modifier.weight(1f)) {
                            EditTextField(value = totp, onValueChange = { totp = it }, mono = true)
                        }
                        Box(
                            modifier = Modifier
                                .background(c.surface, RoundedCornerShape(8.dp))
                                .border(1.dp, c.border, RoundedCornerShape(8.dp))
                                .clickable {
                                    val options = ScanOptions().apply {
                                        setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                                        setPrompt("Scan TOTP QR code")
                                        setBeepEnabled(false)
                                        setOrientationLocked(false)
                                    }
                                    qrLauncher.launch(options)
                                }
                                .padding(horizontal = 12.dp, vertical = 12.dp),
                            contentAlignment = Alignment.Center,
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(4.dp),
                            ) {
                                Icon(
                                    imageVector = Icons.Outlined.QrCodeScanner,
                                    contentDescription = null,
                                    tint = c.fgPrimary,
                                    modifier = Modifier.size(14.dp),
                                )
                                Text(
                                    text = "Scan",
                                    style = RageType.button,
                                    color = c.fgPrimary,
                                )
                            }
                        }
                    }
                }
            }
            item("notes") {
                Field(label = "Notes") {
                    EditTextField(
                        value = notes,
                        onValueChange = { notes = it },
                        minLines = 3,
                    )
                }
            }
            if (item.rage) {
                item("recipients") {
                    Field(
                        label = "Recipients · view only",
                        hint = if (anonymousRecipientCount > 0) {
                            "Any one of these can decrypt. $anonymousRecipientCount software or " +
                                "paper recipient(s) are also wrapped in -- age headers do not name " +
                                "those, so they cannot be listed. Editing the recipient set lands " +
                                "with multi-recipient encrypt."
                        } else {
                            "Any one of these can decrypt. Editing the recipient set lands with multi-recipient encrypt."
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
