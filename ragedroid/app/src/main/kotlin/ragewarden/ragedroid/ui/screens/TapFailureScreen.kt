package ragewarden.ragedroid.ui.screens

import ragewarden.ragedroid.R
import androidx.compose.ui.res.stringResource
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
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.KeyboardArrowRight
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.Nfc
import androidx.compose.material.icons.outlined.Schedule
import androidx.compose.material.icons.outlined.WarningAmber
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import ragewarden.ragedroid.model.Recipient
import ragewarden.ragedroid.model.VaultItem
import ragewarden.ragedroid.ui.components.AppBar
import ragewarden.ragedroid.ui.components.BackButton
import ragewarden.ragedroid.ui.components.ButtonVariant
import ragewarden.ragedroid.ui.components.RageButton
import ragewarden.ragedroid.ui.components.RecipientPip
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors

enum class TapFailureKind { Timeout, WrongKey, Cancelled, NoMatch, Unknown }

@Composable
fun TapFailureScreen(
    kind: TapFailureKind,
    item: VaultItem?,
    onRetry: () -> Unit,
    onPick: (Recipient) -> Unit,
    onBack: () -> Unit,
    onSetUpDevice: (() -> Unit)? = null,
) {
    val c = rageColors
    val copy = failureCopy(kind)
    val tone = when (copy.tone) {
        Tone.Danger -> ToneColors(bg = c.dangerStrong, fg = Color(0xFFFAF6EE))
        Tone.Warning -> ToneColors(bg = c.warning, fg = Color(0xFF1A140A))
        Tone.Muted -> ToneColors(bg = c.tile, fg = c.fgEmphasis)
    }

    val liveRecipients = ragewarden.ragedroid.ui.LocalLiveRecipients.current
    // `item.recipients` holds stanza descriptors parsed out of the blob's age
    // header ("piv-p256:<b64>"), not recipient ids -- see
    // data/RecipientDescriptors.kt. Matching them against `Recipient.id`, a
    // UUID, never hit, so the "or try a different recipient" list this screen's
    // WrongKey copy points at was never rendered.
    val recipients: List<Recipient> = item?.recipients
        ?.toSet()
        ?.let { descriptors -> liveRecipients.filter { r -> r.descriptors.any { it in descriptors } } }
        ?: emptyList()

    Column(modifier = Modifier.fillMaxSize().background(c.background)) {
        AppBar(
            title = stringResource(R.string.reveal),
            leading = { BackButton(onBack) },
        )

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 18.dp, vertical = 24.dp),
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(c.surfaceElevated, RoundedCornerShape(12.dp))
                    .border(1.dp, c.border, RoundedCornerShape(12.dp))
                    .padding(horizontal = 16.dp, vertical = 20.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Box(
                    modifier = Modifier
                        .size(72.dp)
                        .background(tone.bg, CircleShape),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        imageVector = copy.icon,
                        contentDescription = null,
                        tint = tone.fg,
                        modifier = Modifier.size(32.dp),
                    )
                }
                Spacer(modifier = Modifier.height(16.dp))
                Text(
                    text = stringResource(copy.title),
                    style = RageType.h1.copy(fontSize = 22.sp, lineHeight = 26.sp),
                    color = c.fgEmphasis,
                    textAlign = TextAlign.Center,
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = stringResource(copy.body),
                    style = RageType.body.copy(fontSize = 14.sp, lineHeight = 22.sp),
                    color = c.fgSecondary,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.padding(horizontal = 4.dp),
                )
            }

            if (recipients.size > 1) {
                Spacer(modifier = Modifier.height(20.dp))
                Text(
                    text = stringResource(R.string.or_try_a_different_recipient),
                    style = RageType.eyebrow,
                    color = c.fgSecondary,
                    modifier = Modifier.padding(start = 4.dp, bottom = 8.dp),
                )
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(c.surface, RoundedCornerShape(10.dp))
                        .border(1.dp, c.border, RoundedCornerShape(10.dp)),
                ) {
                    recipients.forEachIndexed { index, r ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { onPick(r) }
                                .padding(horizontal = 14.dp, vertical = 12.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            RecipientPip(kind = r.kind)
                            Text(
                                text = r.name,
                                style = RageType.rowTitle.copy(fontSize = 14.sp, lineHeight = 18.sp),
                                color = c.fgEmphasis,
                                modifier = Modifier.weight(1f),
                            )
                            Icon(
                                imageVector = Icons.AutoMirrored.Outlined.KeyboardArrowRight,
                                contentDescription = null,
                                tint = c.fgSecondary,
                                modifier = Modifier.size(14.dp),
                            )
                        }
                        if (index < recipients.size - 1) {
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

            Spacer(modifier = Modifier.weight(1f))
            if (kind == TapFailureKind.NoMatch && onSetUpDevice != null) {
                RageButton(
                    label = stringResource(R.string.set_up_this_device),
                    onClick = onSetUpDevice,
                    icon = Icons.Outlined.Nfc,
                    fullWidth = true,
                    variant = ButtonVariant.Primary,
                )
            } else {
                RageButton(
                    label = stringResource(R.string.try_again),
                    onClick = onRetry,
                    icon = Icons.Outlined.Nfc,
                    fullWidth = true,
                    variant = ButtonVariant.Primary,
                )
            }
        }
    }
}

private enum class Tone { Danger, Warning, Muted }

private data class FailureCopy(
    @androidx.annotation.StringRes val title: Int,
    @androidx.annotation.StringRes val body: Int,
    val icon: ImageVector,
    val tone: Tone,
)

private data class ToneColors(val bg: Color, val fg: Color)

private fun failureCopy(kind: TapFailureKind): FailureCopy = when (kind) {
    TapFailureKind.WrongKey -> FailureCopy(
        title = R.string.that_key_isn_t_on_the,
        body = R.string.the_key_you_tapped_is_registered,
        icon = Icons.Outlined.Close,
        tone = Tone.Warning,
    )
    TapFailureKind.Timeout -> FailureCopy(
        title = R.string.timed_out,
        body = R.string.no_tap_detected_within_30_seconds,
        icon = Icons.Outlined.Schedule,
        tone = Tone.Warning,
    )
    TapFailureKind.Cancelled -> FailureCopy(
        title = R.string.cancelled,
        body = R.string.you_dismissed_the_prompt_before_tapping,
        icon = Icons.Outlined.Close,
        tone = Tone.Muted,
    )
    TapFailureKind.NoMatch -> FailureCopy(
        title = R.string.you_ll_need_to_set_up,
        body = R.string.this_item_was_protected_on_another,
        icon = Icons.Outlined.WarningAmber,
        tone = Tone.Warning,
    )
    TapFailureKind.Unknown -> FailureCopy(
        title = R.string.couldn_t_open_this_item,
        body = R.string.something_failed_before_or_after_your,
        icon = Icons.Outlined.WarningAmber,
        tone = Tone.Warning,
    )
}

