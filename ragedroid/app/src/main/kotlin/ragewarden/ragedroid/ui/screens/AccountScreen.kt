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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.outlined.Check
import androidx.compose.material.icons.outlined.ChevronRight
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material.icons.outlined.DeleteOutline
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import ragewarden.ragedroid.data.VaultBridge
import ragewarden.ragedroid.ui.components.AppBar
import ragewarden.ragedroid.ui.components.ButtonVariant
import ragewarden.ragedroid.ui.components.IconBtn
import ragewarden.ragedroid.ui.components.Mono
import ragewarden.ragedroid.ui.components.RageButton
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors

private enum class SyncPhase { Idle, Syncing, Done }

@Composable
fun AccountScreen(
    email: String = VaultBridge.repository()?.email.orEmpty(),
    server: String = VaultBridge.repository()?.serverUrl.orEmpty(),
    accountId: String = VaultBridge.repository()?.accountId.orEmpty(),
    kdfIterations: Int = VaultBridge.repository()?.kdfIterations ?: 0,
    deviceName: String = android.os.Build.MODEL ?: "This device",
    onBack: () -> Unit,
    onSignOut: () -> Unit,
    onToast: (String) -> Unit = {},
) {
    val c = rageColors
    val repo = VaultBridge.repository()
    val scope = rememberCoroutineScope()

    var syncPhase by remember { mutableStateOf(SyncPhase.Idle) }
    var lastSync by remember { mutableStateOf<String?>(null) }
    var syncStatus by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(syncPhase) {
        if (syncPhase == SyncPhase.Done) {
            delay(1800)
            syncPhase = SyncPhase.Idle
        }
    }

    val syncSubtitle = when (syncPhase) {
        SyncPhase.Syncing -> if (server.isNotEmpty()) "Pulling latest blob from $server..." else "Pulling latest blob..."
        SyncPhase.Done -> syncStatus ?: "Up to date"
        SyncPhase.Idle -> lastSync?.let { "Last sync $it" } ?: "Tap to sync now"
    }
    val syncIcon: ImageVector = if (syncPhase == SyncPhase.Done) Icons.Outlined.Check else Icons.Outlined.Refresh

    val kdfDisplay = if (kdfIterations > 0) {
        val grouped = kdfIterations.toString().reversed().chunked(3).joinToString(" ").reversed()
        grouped
    } else {
        ""
    }

    Column(modifier = Modifier.fillMaxSize().background(c.background)) {
        AppBar(
            title = "Account",
            leading = {
                IconBtn(
                    icon = Icons.AutoMirrored.Outlined.ArrowBack,
                    contentDescription = "Back",
                    onClick = onBack,
                )
            },
        )

        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(bottom = 32.dp),
        ) {
            SectionLabel("Identity")
            Card {
                Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 14.dp)) {
                    Text(
                        text = email,
                        style = RageType.h2.copy(fontSize = 18.sp),
                        color = c.fgEmphasis,
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Mono(
                        text = "account: $accountId",
                        size = 11,
                        color = c.fgSecondary,
                    )
                }
            }

            SectionLabel("Server")
            Card {
                AccountRow(
                    title = "URL",
                    value = server,
                    onClick = { onToast("Server URL is set at sign-in") },
                )
                Divider()
                AccountRow(
                    title = "KDF",
                    subtitle = "PBKDF2-HMAC-SHA256",
                    value = kdfDisplay,
                    onClick = null,
                )
            }

            SectionLabel("This device")
            Card {
                // Read-only on purpose: nothing here can rename the device, so
                // the row must not carry a chevron or a tap that only toasts.
                AccountRow(
                    title = "Device name",
                    value = deviceName,
                    onClick = null,
                )
                Divider()
                AccountRow(
                    icon = syncIcon,
                    title = "Sync now",
                    subtitle = syncSubtitle,
                    onClick = {
                        if (syncPhase != SyncPhase.Syncing) {
                            if (repo == null) {
                                onToast("No signed-in vault to sync.")
                            } else {
                                syncPhase = SyncPhase.Syncing
                                syncStatus = null
                                scope.launch {
                                    val result = repo.sync()
                                    result.fold(
                                        onSuccess = { snap ->
                                            lastSync = "now"
                                            syncStatus = "Up to date · ${snap.items.size} items"
                                            syncPhase = SyncPhase.Done
                                        },
                                        onFailure = { e ->
                                            syncStatus = e.message ?: "Sync failed."
                                            onToast(syncStatus!!)
                                            syncPhase = SyncPhase.Done
                                        },
                                    )
                                }
                            }
                        }
                    },
                )
            }

            Spacer(modifier = Modifier.height(20.dp))
            Column(modifier = Modifier.padding(horizontal = 16.dp)) {
                RageButton(
                    label = "Sign out & forget device",
                    onClick = onSignOut,
                    variant = ButtonVariant.Danger,
                    icon = Icons.Outlined.DeleteOutline,
                    fullWidth = true,
                )
                Spacer(modifier = Modifier.height(10.dp))
                Text(
                    text = "Removes the encrypted cache, keys derived on this device, and " +
                        "the autofill registration. Your server vault is untouched.",
                    style = RageType.caption.copy(
                        fontSize = 11.5.sp,
                        textAlign = TextAlign.Center,
                    ),
                    color = c.fgSecondary,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        }
    }
}

@Composable
private fun SectionLabel(label: String) {
    val c = rageColors
    Text(
        text = label.uppercase(),
        style = RageType.eyebrow.copy(letterSpacing = 0.08.em),
        color = c.fgSecondary,
        modifier = Modifier.padding(start = 18.dp, end = 18.dp, top = 20.dp, bottom = 8.dp),
    )
}

@Composable
internal fun Card(content: @Composable () -> Unit) {
    val c = rageColors
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(c.surface)
            .border(1.dp, c.border),
    ) {
        content()
    }
}

@Composable
internal fun Divider() {
    val c = rageColors
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(1.dp)
            .background(c.divider),
    )
}

@Composable
private fun AccountRow(
    title: String,
    icon: ImageVector? = null,
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
internal fun ToggleSwitch(on: Boolean, onChange: (Boolean) -> Unit) {
    val c = rageColors
    Box(
        modifier = Modifier
            .size(width = 40.dp, height = 24.dp)
            .background(if (on) c.accent else c.border, RoundedCornerShape(12.dp))
            .clickable { onChange(!on) },
        contentAlignment = if (on) Alignment.CenterEnd else Alignment.CenterStart,
    ) {
        Box(
            modifier = Modifier
                .padding(horizontal = 2.dp)
                .size(20.dp)
                .background(c.background, CircleShape),
        )
    }
}
