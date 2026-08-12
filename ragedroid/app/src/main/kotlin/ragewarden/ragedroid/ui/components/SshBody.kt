package ragewarden.ragedroid.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Terminal
import androidx.compose.material.icons.outlined.Visibility
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import ragewarden.ragedroid.data.Clipboard
import ragewarden.ragedroid.model.VaultItem
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors

private const val REVEAL_AUTO_HIDE_SECS = 10

@Composable
fun SshBody(
    item: VaultItem,
    clipboard: Clipboard,
    showToast: (String) -> Unit,
) {
    val c = rageColors
    var showingPrivate by remember { mutableStateOf(false) }

    LaunchedEffect(showingPrivate) {
        if (showingPrivate) {
            delay(REVEAL_AUTO_HIDE_SECS * 1000L)
            showingPrivate = false
        }
    }

    val keyType = item.keyType
    val fingerprint = item.fingerprint
    val publicKey = item.publicKey
    val privateKey = item.privateKey
    val comment = item.comment
    val passphrase = item.passphrase

    Column(modifier = Modifier.fillMaxWidth()) {
        Field(label = "Key type") {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(c.surfaceSunken, RoundedCornerShape(8.dp))
                    .border(1.dp, c.border, RoundedCornerShape(8.dp))
                    .padding(horizontal = 12.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                if (keyType == null) {
                    NotSetText()
                } else {
                    Mono(text = keyType, size = 13)
                }
            }
        }

        Field(label = "Fingerprint") {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(c.surfaceSunken, RoundedCornerShape(8.dp))
                    .border(1.dp, c.border, RoundedCornerShape(8.dp))
                    .padding(horizontal = 12.dp, vertical = 10.dp),
            ) {
                if (fingerprint == null) {
                    NotSetText()
                } else {
                    Mono(
                        text = fingerprint,
                        size = 12,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
            }
        }

        Field(label = "Public key", hint = "Always safe to share.") {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(c.surfaceSunken, RoundedCornerShape(8.dp))
                    .border(1.dp, c.border, RoundedCornerShape(8.dp))
                    .padding(horizontal = 12.dp, vertical = 10.dp),
                verticalAlignment = Alignment.Top,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                if (publicKey == null) {
                    NotSetText(modifier = Modifier.weight(1f))
                } else {
                    Mono(
                        text = publicKey,
                        size = 11,
                        modifier = Modifier.weight(1f),
                    )
                    CopyButton(
                        onCopy = {
                            clipboard.copyVisible(publicKey, "public key")
                            showToast("Public key copied")
                        },
                        compact = true,
                    )
                }
            }
        }

        Field(
            label = "Private key",
            hint = "Copy to clipboard for your SSH tool -- clears in 30s. Reveal to view in full.",
        ) {
            if (privateKey == null) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(c.surfaceSunken, RoundedCornerShape(8.dp))
                        .border(1.dp, c.border, RoundedCornerShape(8.dp))
                        .padding(horizontal = 12.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    NotSetText()
                }
            } else if (showingPrivate) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(c.surfaceElevated, RoundedCornerShape(10.dp))
                        .border(1.dp, c.success, RoundedCornerShape(10.dp))
                        .padding(horizontal = 14.dp, vertical = 12.dp),
                ) {
                    Mono(
                        text = privateKey,
                        size = 11,
                        color = c.fgEmphasis,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Spacer(modifier = Modifier.height(10.dp))
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
                                text = "Auto-hides in 10s",
                                style = RageType.meta.copy(fontWeight = FontWeight.SemiBold),
                                color = c.success,
                            )
                        }
                        CopyButton(
                            onCopy = {
                                val bytes = privateKey.toByteArray(Charsets.UTF_8)
                                clipboard.copySensitive(bytes, "private key")
                                bytes.fill(0)
                                showToast("Private key copied · clears in 30s")
                            },
                            compact = true,
                        )
                    }
                }
            } else {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    RageButton(
                        label = "Copy private key",
                        onClick = {
                            val bytes = privateKey.toByteArray(Charsets.UTF_8)
                            clipboard.copySensitive(bytes, "private key")
                            bytes.fill(0)
                            showToast("Private key copied · clears in 30s")
                        },
                        variant = ButtonVariant.Secondary,
                        icon = Icons.Outlined.Terminal,
                        modifier = Modifier.weight(1f),
                        fullWidth = true,
                    )
                    RageButton(
                        label = "Reveal",
                        onClick = { showingPrivate = true },
                        variant = ButtonVariant.Ghost,
                        icon = Icons.Outlined.Visibility,
                    )
                }
            }
        }

        Field(label = "Comment") {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(c.surfaceSunken, RoundedCornerShape(8.dp))
                    .border(1.dp, c.border, RoundedCornerShape(8.dp))
                    .padding(horizontal = 12.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                if (comment == null) {
                    NotSetText(modifier = Modifier.weight(1f))
                } else {
                    Text(
                        text = comment,
                        style = RageType.sansBody,
                        color = c.fgPrimary,
                        modifier = Modifier.weight(1f),
                    )
                    CopyButton(
                        onCopy = {
                            clipboard.copyVisible(comment, "comment")
                            showToast("Comment copied")
                        },
                        compact = true,
                    )
                }
            }
        }

        Field(label = "Passphrase", hint = "Locks the private key at rest.") {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(c.surfaceSunken, RoundedCornerShape(8.dp))
                    .border(1.dp, c.border, RoundedCornerShape(8.dp))
                    .padding(horizontal = 12.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                if (passphrase == null) {
                    NotSetText(modifier = Modifier.weight(1f))
                } else {
                    Mono(
                        text = "•".repeat(passphrase.length.coerceIn(8, 24)),
                        size = 14,
                        color = c.fgSecondary,
                        modifier = Modifier.weight(1f),
                    )
                    CopyButton(
                        onCopy = {
                            val bytes = passphrase.toByteArray(Charsets.UTF_8)
                            clipboard.copySensitive(bytes, "passphrase")
                            bytes.fill(0)
                            showToast("Passphrase copied · clears in 30s")
                        },
                        compact = true,
                    )
                }
            }
        }

        if (item.notes != null) {
            NotesField(text = item.notes)
        }
    }
}

@Composable
private fun NotSetText(modifier: Modifier = Modifier) {
    val c = rageColors
    Text(
        text = "Not set",
        style = RageType.body.copy(fontSize = 14.sp, fontStyle = FontStyle.Italic),
        color = c.fgSecondary,
        modifier = modifier,
    )
}

@Composable
private fun NotesField(text: String) {
    val c = rageColors
    Field(label = "Notes") {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .background(c.surfaceSunken, RoundedCornerShape(8.dp))
                .border(1.dp, c.border, RoundedCornerShape(8.dp))
                .padding(horizontal = 12.dp, vertical = 10.dp),
        ) {
            Text(
                text = text,
                style = RageType.body.copy(fontSize = 13.5.sp),
                color = c.fgPrimary,
            )
        }
    }
}
