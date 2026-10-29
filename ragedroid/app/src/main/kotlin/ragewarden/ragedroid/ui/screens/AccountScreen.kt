package ragewarden.ragedroid.ui.screens

import androidx.compose.ui.res.stringResource
import ragewarden.ragedroid.R
import ragewarden.ragedroid.ui.describe
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
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
import androidx.compose.material.icons.outlined.Check
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material.icons.outlined.DeleteOutline
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import ragewarden.ragedroid.data.VaultBridge
import ragewarden.ragedroid.ui.components.AppBar
import ragewarden.ragedroid.ui.components.BackButton
import ragewarden.ragedroid.ui.components.ButtonVariant
import ragewarden.ragedroid.ui.components.Mono
import ragewarden.ragedroid.ui.components.RageButton
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors
import ragewarden.ragedroid.ui.uiString

private enum class SyncPhase { Idle, Syncing, Done }

@Composable
fun AccountScreen(
    email: String = VaultBridge.repository()?.email.orEmpty(),
    server: String = VaultBridge.repository()?.serverUrl.orEmpty(),
    accountId: String = VaultBridge.repository()?.accountId.orEmpty(),
    kdf: ragewarden.ragedroid.data.KdfSummary? = VaultBridge.repository()?.kdf,
    deviceName: String = android.os.Build.MODEL ?: uiString(R.string.this_device),
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
        SyncPhase.Syncing -> if (server.isNotEmpty()) stringResource(R.string.syncing_with, server) else stringResource(R.string.syncing)
        SyncPhase.Done -> syncStatus ?: stringResource(R.string.up_to_date)
        SyncPhase.Idle -> lastSync?.let { stringResource(R.string.last_sync, it) } ?: stringResource(R.string.tap_to_sync_now)
    }
    val syncIcon: ImageVector = if (syncPhase == SyncPhase.Done) Icons.Outlined.Check else Icons.Outlined.Refresh

    val kdfDisplay = kdf?.takeIf { it.iterations > 0 }?.describe(LocalContext.current.resources).orEmpty()

    Column(modifier = Modifier.fillMaxSize().background(c.background)) {
        AppBar(
            title = stringResource(R.string.account),
            leading = { BackButton(onBack) },
        )

        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(bottom = 32.dp),
        ) {
            SectionLabel(stringResource(R.string.identity))
            Card {
                Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 14.dp)) {
                    Text(
                        text = email,
                        style = RageType.h2.copy(fontSize = 18.sp),
                        color = c.fgEmphasis,
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Mono(
                        text = stringResource(R.string.account_2, accountId),
                        size = 11,
                        color = c.fgSecondary,
                    )
                }
            }

            SectionLabel(stringResource(R.string.server))
            Card {
                SettingsRow(
                    title = stringResource(R.string.url),
                    value = server,
                    onClick = null,
                )
                Divider()
                SettingsRow(
                    title = stringResource(R.string.password_stretching),
                    subtitle = kdfDisplay,
                    onClick = null,
                )
            }

            SectionLabel(stringResource(R.string.this_device))
            Card {
                // Read-only on purpose: nothing here can rename the device, so
                // the row must not carry a chevron or a tap that only toasts.
                SettingsRow(
                    title = stringResource(R.string.device_name),
                    value = deviceName,
                    onClick = null,
                )
                Divider()
                SettingsRow(
                    icon = syncIcon,
                    title = stringResource(R.string.sync_now),
                    subtitle = syncSubtitle,
                    onClick = {
                        if (syncPhase != SyncPhase.Syncing) {
                            if (repo == null) {
                                onToast(uiString(R.string.no_signed_in_vault_to_sync))
                            } else {
                                syncPhase = SyncPhase.Syncing
                                syncStatus = null
                                scope.launch {
                                    val result = repo.sync()
                                    result.fold(
                                        onSuccess = { snap ->
                                            lastSync = "now"
                                            syncStatus = uiString(R.string.up_to_date_items, snap.items.size)
                                            syncPhase = SyncPhase.Done
                                        },
                                        onFailure = { e ->
                                            syncStatus = e.message ?: uiString(R.string.sync_failed)
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
                    label = stringResource(R.string.sign_out_2),
                    onClick = onSignOut,
                    variant = ButtonVariant.Danger,
                    icon = Icons.Outlined.DeleteOutline,
                    fullWidth = true,
                )
                Spacer(modifier = Modifier.height(10.dp))
                Text(
                    text = stringResource(R.string.removes_the_session_the_offline_vault),
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
