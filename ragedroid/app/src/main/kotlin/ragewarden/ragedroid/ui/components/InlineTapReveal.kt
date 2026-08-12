package ragewarden.ragedroid.ui.components

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.KeyboardArrowRight
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.East
import androidx.compose.material.icons.outlined.ErrorOutline
import androidx.compose.material.icons.outlined.Nfc
import androidx.compose.material.icons.outlined.Visibility
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.CancellationException
import ragewarden.ragedroid.identities.HardwareTapCoordinator
import ragewarden.ragedroid.identities.IdentitySet
import ragewarden.ragedroid.identities.MockHardware
import ragewarden.ragedroid.identities.PinRequest
import ragewarden.ragedroid.ui.theme.MotionTokens
import ragewarden.ragedroid.ui.theme.RageTheme
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors

enum class TapAction(val verb: String, val noun: String, val description: String, val ctaIcon: ImageVector) {
    Autofill(
        verb = "Autofill into",
        noun = "fill",
        description = "Deliver to the active app. Plaintext never on screen.",
        ctaIcon = Icons.Outlined.East,
    ),
    Copy(
        verb = "Copy",
        noun = "copy",
        description = "Auto-clears in 30 seconds, or when the app loses focus.",
        ctaIcon = Icons.Outlined.ContentCopy,
    ),
    Reveal(
        verb = "Reveal",
        noun = "reveal",
        description = "Display until you dismiss. Last-resort path.",
        ctaIcon = Icons.Outlined.Visibility,
    );
}

/**
 * Everything the prompt is allowed to claim about the key behind this item.
 *
 * It is built from a real [IdentitySet] ([from]) rather than from a string the
 * call site invents. Two of the three call sites used to hardcode
 * `recipientLabel = "Software identity"` and the footer always read
 * "NFC · USB-C · ..." whether or not anything with an NFC antenna was involved.
 */
data class TapPresentation(
    val recipientLabel: String,
    val transportHint: String?,
    val requiresPhysicalTap: Boolean,
    val isMock: Boolean,
    /** Non-null when the ceremony cannot even be attempted from here. */
    val blockedReason: String?,
) {
    companion object {
        fun from(set: IdentitySet): TapPresentation {
            val blocked = if (set.isEmpty) {
                buildString {
                    append("No key on this device can unlock this item.")
                    set.skipped.forEach { append("\n• ${it.label}: ${it.reason}") }
                }
            } else {
                null
            }
            return TapPresentation(
                recipientLabel = set.promptLabel,
                transportHint = set.transportHint,
                requiresPhysicalTap = set.hardwareTapRequired,
                isMock = set.containsMock,
                blockedReason = blocked,
            )
        }

        /** For previews and for non-protected items, which need no ceremony. */
        fun softwareOnly(label: String): TapPresentation = TapPresentation(
            recipientLabel = label,
            transportHint = null,
            requiresPhysicalTap = false,
            isMock = false,
            blockedReason = null,
        )
    }
}

/**
 * The consent-and-authorize surface.
 *
 * [onAuthorize] is a **suspend** function that must perform the real work
 * (decrypt, deliver) and throw on failure. The composable stays in
 * [Phase.Contacting] for its whole duration -- which is exactly the window in
 * which a YubiKey has to be presented and touched, because the tap happens
 * inside the identity that `onAuthorize`'s decrypt drives. Success copy is only
 * reachable after it returns; the old component printed "Tap accepted.
 * Plaintext lifetime: microseconds." 700 ms after a button press, before any
 * decrypt had been attempted.
 *
 * [pinRequest] is the coordinator's pending PIV PIN prompt, if any.
 */
@Composable
fun InlineTapReveal(
    itemName: String,
    itemSite: String?,
    presentation: TapPresentation,
    onAuthorize: suspend (TapAction) -> Unit,
    onCancel: () -> Unit,
    initialAction: TapAction? = null,
    pinRequest: PinRequest? = null,
    modifier: Modifier = Modifier,
) {
    var phase by remember { mutableStateOf(if (initialAction != null) Phase.Waiting else Phase.Choose) }
    var chosenAction by remember { mutableStateOf(initialAction) }
    var failure by remember { mutableStateOf<Failure?>(null) }

    LaunchedEffect(phase, chosenAction) {
        if (phase != Phase.Contacting) return@LaunchedEffect
        val action = chosenAction ?: return@LaunchedEffect
        try {
            onAuthorize(action)
            // The caller owns what happens next (navigate away, show plaintext).
            // If it leaves us composed, go back to a truthful idle state rather
            // than showing a success badge for a use that already happened.
            phase = Phase.Waiting
        } catch (ce: CancellationException) {
            throw ce
        } catch (t: Throwable) {
            failure = Failure(
                message = HardwareTapCoordinator.describe(t),
                retryable = HardwareTapCoordinator.isRetryable(t),
            )
            phase = Phase.Failed
        }
    }

    if (pinRequest != null) {
        PivPinPrompt(request = pinRequest)
        return
    }

    when (phase) {
        Phase.Choose -> ChooseActions(
            modifier = modifier,
            onPick = { action ->
                chosenAction = action
                phase = Phase.Waiting
            },
            onCancel = onCancel,
        )
        Phase.Waiting, Phase.Contacting -> TapPrompt(
            modifier = modifier,
            itemName = itemName,
            itemSite = itemSite,
            presentation = presentation,
            action = chosenAction!!,
            contacting = phase == Phase.Contacting,
            onTap = { phase = Phase.Contacting },
            onCancel = onCancel,
        )
        Phase.Failed -> TapFailure(
            modifier = modifier,
            failure = failure,
            onRetry = { failure = null; phase = Phase.Waiting },
            onCancel = onCancel,
        )
    }
}

private enum class Phase { Choose, Waiting, Contacting, Failed }

private data class Failure(val message: String, val retryable: Boolean)

@Composable
private fun ChooseActions(
    modifier: Modifier,
    onPick: (TapAction) -> Unit,
    onCancel: () -> Unit,
) {
    val c = rageColors
    Column(
        modifier = modifier
            .fillMaxWidth()
            .background(c.surfaceElevated, RoundedCornerShape(10.dp))
            .border(1.dp, c.border, RoundedCornerShape(10.dp))
            .padding(horizontal = 12.dp, vertical = 12.dp),
    ) {
        Text(
            text = "PICK AN ACTION -- TAP WILL AUTHORIZE THAT SPECIFIC USE",
            style = RageType.eyebrow,
            color = c.fgSecondary,
            modifier = Modifier.padding(horizontal = 4.dp, vertical = 4.dp),
        )
        Spacer(modifier = Modifier.height(4.dp))
        TapAction.entries.forEach { action ->
            ActionRow(action = action, onClick = { onPick(action) })
        }
        Spacer(modifier = Modifier.height(4.dp))
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .clickable(onClick = onCancel)
                .padding(vertical = 6.dp),
            contentAlignment = Alignment.Center,
        ) {
            Text(text = "Cancel", style = RageType.caption, color = c.fgSecondary)
        }
    }
}

@Composable
private fun ActionRow(action: TapAction, onClick: () -> Unit) {
    val c = rageColors
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 8.dp, vertical = 10.dp),
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
                imageVector = action.ctaIcon,
                contentDescription = null,
                tint = c.accent,
                modifier = Modifier.size(16.dp),
            )
        }
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = when (action) {
                    TapAction.Autofill -> "Autofill"
                    TapAction.Copy -> "Copy to clipboard"
                    TapAction.Reveal -> "Reveal on screen"
                },
                style = RageType.rowTitle,
                color = c.fgEmphasis,
            )
            Text(
                text = action.description,
                style = RageType.body,
                color = c.fgSecondary,
            )
        }
        Icon(
            imageVector = Icons.AutoMirrored.Outlined.KeyboardArrowRight,
            contentDescription = null,
            tint = c.fgSecondary,
            modifier = Modifier.size(16.dp),
        )
    }
}

@Composable
private fun TapPrompt(
    modifier: Modifier,
    itemName: String,
    itemSite: String?,
    presentation: TapPresentation,
    action: TapAction,
    contacting: Boolean,
    onTap: () -> Unit,
    onCancel: () -> Unit,
) {
    val c = rageColors
    val blocked = presentation.blockedReason
    val borderColor = when {
        blocked != null -> c.danger
        contacting -> c.accent
        else -> c.accent
    }
    val target = when (action) {
        TapAction.Autofill -> itemSite ?: itemName
        TapAction.Copy, TapAction.Reveal -> "$itemName password"
    }
    val pulseAlpha by animateFloatAsState(
        targetValue = if (contacting) 0.35f else 0f,
        animationSpec = tween(durationMillis = MotionTokens.DurBaseMs, easing = MotionTokens.EaseOut),
        label = "pulse-alpha",
    )

    Column(
        modifier = modifier
            .fillMaxWidth()
            .background(c.surfaceElevated, RoundedCornerShape(10.dp))
            .border(1.dp, borderColor, RoundedCornerShape(10.dp))
            .padding(horizontal = 16.dp, vertical = 14.dp),
    ) {
        if (presentation.isMock) {
            MockBadge()
            Spacer(modifier = Modifier.height(10.dp))
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                modifier = Modifier.size(44.dp),
                contentAlignment = Alignment.Center,
            ) {
                if (contacting) {
                    Box(
                        modifier = Modifier
                            .size(44.dp)
                            .border(1.5.dp, c.accent.copy(alpha = pulseAlpha), CircleShape),
                    )
                }
                Box(
                    modifier = Modifier
                        .size(36.dp)
                        .background(c.tile, CircleShape),
                    contentAlignment = Alignment.Center,
                ) {
                    if (contacting) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(18.dp),
                            strokeWidth = 2.dp,
                            color = c.accent,
                        )
                    } else {
                        Icon(
                            imageVector = if (blocked != null) Icons.Outlined.ErrorOutline else Icons.Outlined.Nfc,
                            contentDescription = null,
                            tint = if (blocked != null) c.danger else c.accent,
                            modifier = Modifier.size(20.dp),
                        )
                    }
                }
            }
            Spacer(modifier = Modifier.width(14.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "${action.verb} $target?",
                    style = RageType.rowTitle,
                    color = c.fgEmphasis,
                )
                Text(
                    text = promptSubtitle(presentation, action, contacting),
                    style = RageType.caption,
                    color = if (blocked != null) c.danger else c.fgSecondary,
                )
            }
        }
        Spacer(modifier = Modifier.height(10.dp))
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(1.dp)
                .background(c.divider),
        )
        Spacer(modifier = Modifier.height(10.dp))
        Text(
            text = footerText(presentation),
            style = RageType.meta,
            color = c.fgSecondary,
            maxLines = 2,
            overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
            modifier = Modifier.fillMaxWidth(),
        )
        if (!contacting) {
            Spacer(modifier = Modifier.height(10.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.End),
            ) {
                Box(
                    modifier = Modifier
                        .clickable(onClick = onCancel)
                        .padding(horizontal = 8.dp, vertical = 6.dp),
                ) {
                    Text(text = "Cancel", style = RageType.caption, color = c.fgSecondary)
                }
                if (blocked == null) {
                    Box(
                        modifier = Modifier
                            .background(c.accent, RoundedCornerShape(8.dp))
                            .clickable(onClick = onTap)
                            .padding(horizontal = 14.dp, vertical = 8.dp),
                    ) {
                        Text(
                            text = if (presentation.requiresPhysicalTap) "Authorize with key" else "Authorize",
                            style = RageType.button,
                            color = c.background,
                            maxLines = 1,
                        )
                    }
                }
            }
        }
    }
}

/**
 * Honest copy. The old component said "Tap your YubiKey to authorize this
 * $noun" unconditionally, on every surface, whatever was actually enrolled.
 */
private fun promptSubtitle(
    presentation: TapPresentation,
    action: TapAction,
    contacting: Boolean,
): String {
    presentation.blockedReason?.let { return it }
    return when {
        contacting && presentation.requiresPhysicalTap ->
            "Present ${presentation.recipientLabel} now and hold it until the light stops."
        contacting -> "Unlocking with ${presentation.recipientLabel}..."
        presentation.requiresPhysicalTap ->
            "${presentation.recipientLabel} must authorize this ${action.noun}."
        else ->
            "This item unlocks with ${presentation.recipientLabel}. " +
                "No separate hardware confirmation is enrolled for it."
    }
}

private fun footerText(presentation: TapPresentation): String {
    val transport = presentation.transportHint
    return if (transport != null) {
        "$transport · ${presentation.recipientLabel}"
    } else {
        presentation.recipientLabel
    }
}

@Composable
private fun MockBadge() {
    val c = rageColors
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .background(c.danger.copy(alpha = 0.18f), RoundedCornerShape(6.dp))
            .border(1.dp, c.danger, RoundedCornerShape(6.dp))
            .padding(horizontal = 10.dp, vertical = 6.dp),
    ) {
        Text(
            text = "${MockHardware.LABEL_PREFIX}simulated authenticator. " +
                "No physical device is involved. Debug builds only.",
            style = RageType.caption,
            color = c.danger,
        )
    }
}

@Composable
private fun TapFailure(
    modifier: Modifier,
    failure: Failure?,
    onRetry: () -> Unit,
    onCancel: () -> Unit,
) {
    val c = rageColors
    Column(
        modifier = modifier
            .fillMaxWidth()
            .background(c.surfaceElevated, RoundedCornerShape(10.dp))
            .border(1.dp, c.danger, RoundedCornerShape(10.dp))
            .padding(horizontal = 16.dp, vertical = 14.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                imageVector = Icons.Outlined.ErrorOutline,
                contentDescription = null,
                tint = c.danger,
                modifier = Modifier.size(20.dp),
            )
            Spacer(modifier = Modifier.width(10.dp))
            Text(
                text = "Not authorized",
                style = RageType.rowTitle,
                color = c.fgEmphasis,
            )
        }
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = failure?.message ?: "The key did not authorize this use.",
            style = RageType.caption,
            color = c.fgSecondary,
        )
        Spacer(modifier = Modifier.height(12.dp))
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.End),
        ) {
            Box(
                modifier = Modifier
                    .clickable(onClick = onCancel)
                    .padding(horizontal = 8.dp, vertical = 6.dp),
            ) {
                Text(text = "Dismiss", style = RageType.caption, color = c.fgSecondary)
            }
            if (failure?.retryable != false) {
                Box(
                    modifier = Modifier
                        .background(c.accent, RoundedCornerShape(8.dp))
                        .clickable(onClick = onRetry)
                        .padding(horizontal = 14.dp, vertical = 8.dp),
                ) {
                    Text(
                        text = "Try again",
                        style = RageType.button,
                        color = c.background,
                        maxLines = 1,
                    )
                }
            }
        }
    }
}

/** PIV PIN entry, driven by [HardwareTapCoordinator]'s pending [PinRequest]. */
@Composable
private fun PivPinPrompt(request: PinRequest) {
    val c = rageColors
    val pinState = rememberSecurePinFieldState()
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(c.surfaceElevated, RoundedCornerShape(10.dp))
            .border(1.dp, c.accent, RoundedCornerShape(10.dp))
            .padding(horizontal = 16.dp, vertical = 14.dp),
    ) {
        Text(
            text = "PIV PIN for ${request.recipientLabel}",
            style = RageType.rowTitle,
            color = c.fgEmphasis,
        )
        Text(
            text = "The PIN unlocks the slot; the key still requires a physical touch afterwards.",
            style = RageType.caption,
            color = c.fgSecondary,
        )
        Spacer(modifier = Modifier.height(10.dp))
        SecurePinField(state = pinState, modifier = Modifier.fillMaxWidth())
        Spacer(modifier = Modifier.height(10.dp))
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.End),
        ) {
            Box(
                modifier = Modifier
                    .clickable {
                        pinState.zero()
                        request.cancel()
                    }
                    .padding(horizontal = 8.dp, vertical = 6.dp),
            ) {
                Text(text = "Cancel", style = RageType.caption, color = c.fgSecondary)
            }
            Box(
                modifier = Modifier
                    .background(c.accent, RoundedCornerShape(8.dp))
                    .clickable {
                        val pin = pinState.submit()
                        pinState.zero()
                        request.submit(pin)
                    }
                    .padding(horizontal = 14.dp, vertical = 8.dp),
            ) {
                Text(text = "Continue", style = RageType.button, color = c.background, maxLines = 1)
            }
        }
    }
}

@Preview
@Composable
private fun InlineTapRevealPreview() {
    RageTheme {
        InlineTapReveal(
            itemName = "GitHub",
            itemSite = "github.com",
            presentation = TapPresentation(
                recipientLabel = "YubiKey #12345678 (slot 0x9a)",
                transportHint = "NFC · USB-C",
                requiresPhysicalTap = true,
                isMock = false,
                blockedReason = null,
            ),
            initialAction = TapAction.Reveal,
            onAuthorize = {},
            onCancel = {},
        )
    }
}
