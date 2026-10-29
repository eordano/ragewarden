package ragewarden.ragedroid.ui.components

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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.KeyboardArrowRight
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.collections.immutable.ImmutableList
import kotlinx.collections.immutable.toImmutableList
import ragewarden.ragedroid.R
import ragewarden.ragedroid.model.Recipient
import ragewarden.ragedroid.model.VaultItem
import ragewarden.ragedroid.ui.theme.RageTheme
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors
import ragewarden.ragedroid.ui.uiString

@Composable
fun MultiIdentityPickerSheet(
    open: Boolean,
    item: VaultItem?,
    onPick: (Recipient) -> Unit,
    onClose: () -> Unit,
    enrolledRecipients: ImmutableList<Recipient> = ragewarden.ragedroid.ui.LocalLiveRecipients.current,
    onUseRecovery: (() -> Unit)? = null,
) {
    val c = rageColors
    // `item.recipients` holds stanza descriptors from the blob's age header, not
    // recipient ids (data/RecipientDescriptors.kt). Matching on `it.id == id`
    // never hit anything, so this sheet was permanently empty.
    val ids: ImmutableList<Recipient> = item?.recipients
        ?.toSet()
        ?.let { descriptors ->
            enrolledRecipients.filter { r -> r.descriptors.any { it in descriptors } }
        }
        ?.toImmutableList()
        ?: kotlinx.collections.immutable.persistentListOf()

    Sheet(open = open, onDismiss = onClose, title = stringResource(R.string.choose_which_key_to_use)) {
        Column(modifier = Modifier.fillMaxWidth().padding(bottom = 4.dp)) {
            if (ids.isEmpty()) {
                Text(
                    text = stringResource(R.string.no_identities_on_this_device_can),
                    style = RageType.body.copy(fontSize = 14.sp, lineHeight = 21.sp),
                    color = c.fgSecondary,
                    modifier = Modifier.padding(bottom = 12.dp),
                )
                if (onUseRecovery != null) {
                    Spacer(modifier = Modifier.height(4.dp))
                    Box(modifier = Modifier.fillMaxWidth()) {
                        RageButton(
                            label = stringResource(R.string.use_recovery_phrase),
                            icon = Icons.Outlined.Description,
                            variant = ButtonVariant.Primary,
                            fullWidth = true,
                            onClick = {
                                onClose()
                                onUseRecovery()
                            },
                        )
                    }
                }
            } else {
                Text(
                    text = stringResource(R.string.more_than_one_identity_can_decrypt, item?.name ?: stringResource(R.string.this_item)),
                    style = RageType.body.copy(fontSize = 14.sp, lineHeight = 21.sp),
                    color = c.fgSecondary,
                    modifier = Modifier.padding(bottom = 12.dp),
                )
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(c.surface, RoundedCornerShape(10.dp))
                        .border(1.dp, c.border, RoundedCornerShape(10.dp)),
                ) {
                    ids.forEachIndexed { index, r ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    onPick(r)
                                    onClose()
                                }
                                .padding(horizontal = 14.dp, vertical = 12.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(36.dp)
                                    .background(c.tile, RoundedCornerShape(8.dp)),
                                contentAlignment = Alignment.Center,
                            ) {
                                RecipientPip(kind = r.kind)
                            }
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = r.name,
                                    style = RageType.rowTitle.copy(fontSize = 14.5.sp, lineHeight = 18.sp),
                                    color = c.fgEmphasis,
                                )
                                Text(
                                    text = if (r.lastUsed.isBlank()) kindLabel(r) else stringResource(R.string.last_used_3, kindLabel(r), r.lastUsed),
                                    style = RageType.sansBody.copy(fontSize = 11.5.sp, lineHeight = 14.sp),
                                    color = c.fgSecondary,
                                    modifier = Modifier.padding(top = 2.dp),
                                )
                            }
                            Icon(
                                imageVector = Icons.AutoMirrored.Outlined.KeyboardArrowRight,
                                contentDescription = null,
                                tint = c.fgSecondary,
                                modifier = Modifier.size(14.dp),
                            )
                        }
                        if (index < ids.size - 1) {
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
}

private fun kindLabel(r: Recipient): String = when (r.kind) {
    ragewarden.ragedroid.model.RecipientKind.YubiKey -> "YubiKey"
    ragewarden.ragedroid.model.RecipientKind.Fido2 -> uiString(R.string.fido2_token)
    ragewarden.ragedroid.model.RecipientKind.PasskeyPrf -> uiString(R.string.passkey)
    ragewarden.ragedroid.model.RecipientKind.StrongBox -> "StrongBox"
    ragewarden.ragedroid.model.RecipientKind.Recovery -> uiString(R.string.paper_recovery)
    ragewarden.ragedroid.model.RecipientKind.Software -> uiString(R.string.software_identity)
}

