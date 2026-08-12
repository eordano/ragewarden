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
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material.icons.outlined.ErrorOutline
import androidx.compose.material.icons.outlined.Fingerprint
import androidx.compose.material.icons.outlined.Memory
import androidx.compose.material.icons.outlined.Nfc
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp
import androidx.fragment.app.FragmentActivity
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.collections.immutable.ImmutableList
import ragewarden.ragedroid.data.RecipientStore
import ragewarden.ragedroid.model.Recipient
import ragewarden.ragedroid.model.RecipientKind
import ragewarden.ragedroid.identities.passkeyEnrollmentSupported
import ragewarden.ragedroid.ui.components.AppBar
import ragewarden.ragedroid.ui.components.ButtonVariant
import ragewarden.ragedroid.ui.components.IconBtn
import ragewarden.ragedroid.ui.components.RageButton
import ragewarden.ragedroid.ui.components.SecurePinField
import ragewarden.ragedroid.ui.components.rememberSecurePinFieldState
import ragewarden.ragedroid.ui.findActivity
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors

@Composable
fun AddRecipientScreen(
    recipients: ImmutableList<Recipient> = ragewarden.ragedroid.ui.LocalLiveRecipients.current,
    @Suppress("UNUSED_PARAMETER") recipientStore: RecipientStore? = null,
    @Suppress("UNUSED_PARAMETER") accountId: String? = null,
    viewModel: AddRecipientViewModel = hiltViewModel(),
    onBack: () -> Unit,
    onPaperRecovery: (() -> Unit)? = null,
    onToast: (String) -> Unit = {},
) {
    val c = rageColors
    val context = LocalContext.current
    val activity = context.findActivity() as? FragmentActivity
    val state by viewModel.state.collectAsStateWithLifecycle()

    LaunchedEffect(viewModel) {
        viewModel.events.collect { event ->
            when (event) {
                is AddRecipientEvent.Toast -> onToast(event.message)
                AddRecipientEvent.NavigateToPaperRecovery -> onPaperRecovery?.invoke()
                AddRecipientEvent.Done -> onBack()
            }
        }
    }

    LaunchedEffect(Unit) { viewModel.resetToPicker() }

    val enrolledKinds = remember(recipients) { recipients.map { it.kind }.toSet() }
    val yubiCount = remember(recipients) { recipients.count { it.kind == RecipientKind.YubiKey } }
    val hasRecovery = RecipientKind.Recovery in enrolledKinds
    val hasStrongBox = RecipientKind.StrongBox in enrolledKinds

    if (state.pinPromptOpen && activity != null) {
        YubiKeyPinPrompt(
            onCancel = { viewModel.onAction(AddRecipientAction.CancelEnrollment) },
            onSubmit = { pin ->
                viewModel.onAction(AddRecipientAction.SubmitPin(pin, activity))
            },
        )
    }

    Column(modifier = Modifier.fillMaxSize().background(c.background)) {
        AppBar(
            title = "Add recipient",
            leading = {
                IconBtn(
                    icon = Icons.AutoMirrored.Outlined.ArrowBack,
                    contentDescription = "Back",
                    onClick = { viewModel.onAction(AddRecipientAction.Back) },
                )
            },
        )

        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(start = 16.dp, end = 16.dp, bottom = 24.dp),
        ) {
            val pickedKind = state.pickedKind
            if (pickedKind == null) {
                PickPhase(
                    enrolledKinds = enrolledKinds,
                    yubiCount = yubiCount,
                    hasRecovery = hasRecovery,
                    hasStrongBox = hasStrongBox,
                    passkeySupported = passkeyEnrollmentSupported(),
                    onSelect = { kind ->
                        if (activity != null) {
                            viewModel.onAction(AddRecipientAction.PickKind(kind, activity))
                        }
                    },
                )
            } else {
                EnrollPhaseView(
                    kind = pickedKind,
                    phase = state.phase,
                    onDone = {
                        onToast("Recipient added")
                        viewModel.resetToPicker()
                        onBack()
                    },
                    onRetry = { viewModel.onAction(AddRecipientAction.Retry) },
                    onPickDifferent = { viewModel.onAction(AddRecipientAction.CancelEnrollment) },
                )
            }
        }
    }
}

@Composable
private fun PickPhase(
    enrolledKinds: Set<RecipientKind>,
    yubiCount: Int,
    hasRecovery: Boolean,
    hasStrongBox: Boolean,
    passkeySupported: Boolean,
    onSelect: (EnrollKind) -> Unit,
) {
    val c = rageColors
    Text(
        text = "A recipient is anything that can decrypt one of the age stanzas in your vault. Pick a kind.",
        style = RageType.body.copy(fontSize = 16.sp, lineHeight = 24.sp),
        color = c.fgSecondary,
        modifier = Modifier.padding(start = 2.dp, end = 2.dp, top = 6.dp, bottom = 16.dp),
    )

    val recommended = mutableListOf<Pair<EnrollKind, String>>()
    val available = mutableListOf<EnrollKind>()
    val enrolled = mutableListOf<Pair<EnrollKind, String>>()

    val kinds = EnrollKind.entries.filter { it != EnrollKind.Fido2 || passkeySupported }

    kinds.forEach { kind ->
        when (kind) {
            EnrollKind.StrongBox -> {
                if (hasStrongBox) {
                    enrolled.add(kind to "Enrolled on this device")
                } else {
                    recommended.add(kind to "Convenience tier for everyday unlocks.")
                }
            }
            EnrollKind.Recovery -> {
                if (hasRecovery) {
                    enrolled.add(
                        kind to "Recovery identity active -- re-print available in Settings",
                    )
                } else {
                    recommended.add(kind to "Survives losing every device.")
                }
            }
            EnrollKind.YubiKey -> {
                val reason = when (yubiCount) {
                    0 -> "Hardware-rooted protection."
                    1 -> "A backup key prevents single-point-of-failure lockout."
                    else -> null
                }
                if (reason != null) recommended.add(kind to reason) else available.add(kind)
            }
            EnrollKind.Fido2 -> {
                if (yubiCount == 0) {
                    recommended.add(kind to "Use any passkey-capable authenticator.")
                } else {
                    available.add(kind)
                }
            }
        }
    }

    if (recommended.isNotEmpty()) {
        SectionHeader("Recommended next")
        recommended.forEach { (kind, reason) ->
            EnrollKindCard(kind = kind, recommended = true, reason = reason, onClick = { onSelect(kind) })
        }
    }

    if (available.isNotEmpty()) {
        SectionHeader("Other options")
        available.forEach { kind ->
            EnrollKindCard(kind = kind, recommended = false, reason = null, onClick = { onSelect(kind) })
        }
    }

    if (enrolled.isNotEmpty()) {
        SectionHeader("Already enrolled")
        enrolled.forEach { (kind, note) ->
            EnrolledKindCard(kind = kind, note = note)
        }
    }

    Spacer(modifier = Modifier.height(24.dp))
}

@Composable
private fun SectionHeader(label: String) {
    val c = rageColors
    Text(
        text = label.uppercase(),
        style = RageType.eyebrow.copy(letterSpacing = 0.08.em),
        color = c.fgSecondary,
        modifier = Modifier.padding(top = 18.dp, bottom = 8.dp),
    )
}

@Composable
private fun EnrollKindCard(
    kind: EnrollKind,
    recommended: Boolean,
    reason: String?,
    onClick: () -> Unit,
) {
    val c = rageColors
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(bottom = 8.dp)
            .background(c.surfaceElevated, RoundedCornerShape(10.dp))
            .border(
                1.dp,
                if (recommended) c.accent else c.border,
                RoundedCornerShape(10.dp),
            )
            .clickable(onClick = onClick)
            .padding(14.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalAlignment = Alignment.Top,
    ) {
        Box(
            modifier = Modifier
                .size(36.dp)
                .background(c.tile, RoundedCornerShape(8.dp)),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                imageVector = enrollIcon(kind),
                contentDescription = null,
                tint = c.accent,
                modifier = Modifier.size(18.dp),
            )
        }
        Column(modifier = Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    text = kind.title,
                    style = RageType.rowTitle.copy(fontSize = 15.sp),
                    color = c.fgEmphasis,
                )
                if (recommended) {
                    Box(
                        modifier = Modifier
                            .background(c.tile, RoundedCornerShape(4.dp))
                            .padding(horizontal = 6.dp, vertical = 2.dp),
                    ) {
                        Text(
                            text = "RECOMMENDED",
                            style = RageType.eyebrow.copy(fontSize = 10.sp),
                            color = c.accent,
                        )
                    }
                }
            }
            Text(
                text = kind.desc,
                style = RageType.body.copy(fontSize = 13.5.sp, lineHeight = 19.sp),
                color = c.fgSecondary,
                modifier = Modifier.padding(top = 2.dp),
            )
            if (reason != null) {
                Text(
                    text = reason,
                    style = RageType.caption.copy(
                        fontSize = 12.sp,
                        fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold,
                    ),
                    color = c.accent,
                    modifier = Modifier.padding(top = 6.dp),
                )
            }
        }
        Icon(
            imageVector = Icons.Outlined.ChevronRight,
            contentDescription = null,
            tint = c.fgSecondary,
            modifier = Modifier
                .padding(top = 8.dp)
                .size(18.dp),
        )
    }
}

@Composable
private fun EnrolledKindCard(kind: EnrollKind, note: String) {
    val c = rageColors
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(bottom = 8.dp)
            .background(c.surfaceSunken, RoundedCornerShape(10.dp))
            .border(1.dp, c.border, RoundedCornerShape(10.dp))
            .alpha(0.7f)
            .padding(start = 14.dp, end = 14.dp, top = 12.dp, bottom = 12.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalAlignment = Alignment.Top,
    ) {
        Box(
            modifier = Modifier
                .size(32.dp)
                .background(c.tile, RoundedCornerShape(8.dp)),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                imageVector = enrollIcon(kind),
                contentDescription = null,
                tint = c.fgSecondary,
                modifier = Modifier.size(16.dp),
            )
        }
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = kind.title,
                style = RageType.rowTitle.copy(fontSize = 14.sp),
                color = c.fgEmphasis,
            )
            Text(
                text = note,
                style = RageType.caption,
                color = c.fgSecondary,
                modifier = Modifier.padding(top = 2.dp),
            )
        }
        Icon(
            imageVector = Icons.Outlined.Check,
            contentDescription = null,
            tint = c.success,
            modifier = Modifier
                .padding(top = 6.dp)
                .size(14.dp),
        )
    }
}

@Composable
private fun EnrollPhaseView(
    kind: EnrollKind,
    phase: AddRecipientPhase,
    onDone: () -> Unit,
    onRetry: () -> Unit,
    onPickDifferent: () -> Unit,
) {
    val c = rageColors
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(start = 8.dp, end = 8.dp, top = 24.dp, bottom = 24.dp),
    ) {
        if (phase is AddRecipientPhase.Failed) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(c.surfaceElevated, RoundedCornerShape(12.dp))
                    .border(1.dp, c.danger, RoundedCornerShape(12.dp))
                    .padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Box(
                    modifier = Modifier
                        .size(64.dp)
                        .background(c.danger, CircleShape),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        imageVector = Icons.Outlined.ErrorOutline,
                        contentDescription = null,
                        tint = c.background,
                        modifier = Modifier.size(28.dp),
                    )
                }
                Spacer(modifier = Modifier.height(10.dp))
                Text(
                    text = phase.title,
                    style = RageType.h2.copy(fontSize = 18.sp),
                    color = c.fgEmphasis,
                )
                if (phase.detail.isNotBlank()) {
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = phase.detail,
                        style = RageType.caption.copy(fontSize = 13.sp, lineHeight = 19.5.sp),
                        color = c.fgSecondary,
                    )
                }
            }
            Spacer(modifier = Modifier.height(18.dp))
            if (phase.recoverable) {
                RageButton(
                    label = "Try again",
                    onClick = onRetry,
                    variant = ButtonVariant.Primary,
                    fullWidth = true,
                )
                Spacer(modifier = Modifier.height(8.dp))
            }
            RageButton(
                label = "Pick a different kind",
                onClick = onPickDifferent,
                variant = ButtonVariant.Secondary,
                fullWidth = true,
            )
        } else {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(c.surfaceElevated, RoundedCornerShape(12.dp))
                    .border(1.dp, c.border, RoundedCornerShape(12.dp))
                    .padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(110.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    Box(
                        modifier = Modifier
                            .size(64.dp)
                            .background(
                                if (phase is AddRecipientPhase.Done) c.success else c.tile,
                                CircleShape,
                            ),
                        contentAlignment = Alignment.Center,
                    ) {
                        Icon(
                            imageVector = if (phase is AddRecipientPhase.Done) {
                                Icons.Outlined.Check
                            } else {
                                enrollIcon(kind)
                            },
                            contentDescription = null,
                            tint = if (phase is AddRecipientPhase.Done) c.background else c.accent,
                            modifier = Modifier.size(28.dp),
                        )
                    }
                }
                Spacer(modifier = Modifier.height(4.dp))
                val title = when (phase) {
                    AddRecipientPhase.Listening -> "Listening..."
                    AddRecipientPhase.Found -> "Touch to confirm"
                    AddRecipientPhase.Done -> "Recipient enrolled"
                    AddRecipientPhase.Picker -> "Listening..."
                    is AddRecipientPhase.Failed -> phase.title
                }
                Text(
                    text = title,
                    style = RageType.h2.copy(fontSize = 18.sp),
                    color = c.fgEmphasis,
                )
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = if (phase is AddRecipientPhase.Done) {
                        "Re-encrypting protected items in batch..."
                    } else {
                        "Hold steady against the back of the phone."
                    },
                    style = RageType.caption.copy(fontSize = 13.sp, lineHeight = 19.5.sp),
                    color = c.fgSecondary,
                )
            }
            if (phase is AddRecipientPhase.Done) {
                Spacer(modifier = Modifier.height(18.dp))
                RageButton(
                    label = "Done",
                    onClick = onDone,
                    variant = ButtonVariant.Primary,
                    fullWidth = true,
                )
            }
        }
    }
}

private fun enrollIcon(kind: EnrollKind): ImageVector = when (kind) {
    EnrollKind.YubiKey -> Icons.Outlined.Nfc
    EnrollKind.Fido2 -> Icons.Outlined.Fingerprint
    EnrollKind.StrongBox -> Icons.Outlined.Memory
    EnrollKind.Recovery -> Icons.Outlined.Description
}

@Composable
private fun YubiKeyPinPrompt(
    onCancel: () -> Unit,
    onSubmit: (CharArray) -> Unit,
) {
    val pinState = rememberSecurePinFieldState()
    AlertDialog(
        onDismissRequest = {
            pinState.zero()
            onCancel()
        },
        title = { Text("YubiKey PIN") },
        text = {
            Column {
                Text(
                    text = "Enter your YubiKey PIV PIN. The default is 123456 if you haven't set one.",
                    style = RageType.body.copy(fontSize = 13.sp, lineHeight = 18.sp),
                )
                Spacer(modifier = Modifier.height(12.dp))
                SecurePinField(state = pinState)
            }
        },
        confirmButton = {
            TextButton(onClick = {
                val chars = pinState.submit()
                pinState.zero()
                onSubmit(chars)
            }) { Text("Continue") }
        },
        dismissButton = {
            TextButton(onClick = {
                pinState.zero()
                onCancel()
            }) { Text("Cancel") }
        },
    )
}
