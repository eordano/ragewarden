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
import androidx.compose.material.icons.outlined.Visibility
import androidx.compose.material.icons.outlined.VisibilityOff
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
fun CardBody(
    item: VaultItem,
    clipboard: Clipboard,
    showToast: (String) -> Unit,
) {
    val c = rageColors
    var revealedField by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(revealedField) {
        if (revealedField != null) {
            delay(REVEAL_AUTO_HIDE_SECS * 1000L)
            revealedField = null
        }
    }

    val number = item.cardNumber
    val cvv = item.cvv
    val expiry = item.expiry
    val cardholder = item.cardholder
    val brand = item.brand
    val last4 = number?.replace(" ", "")?.takeLast(4)
    val masked = if (last4 != null) "•••• •••• •••• $last4" else "•••• •••• •••• ••••"

    Column(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .background(c.fgEmphasis, RoundedCornerShape(12.dp))
                .padding(horizontal = 18.dp, vertical = 20.dp),
        ) {
            Text(
                text = (brand ?: "Card").uppercase(),
                style = RageType.eyebrow.copy(
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 11.sp,
                ),
                color = c.background.copy(alpha = 0.7f),
            )
            Spacer(modifier = Modifier.height(24.dp))
            Text(
                text = if (revealedField == "number" && number != null) number else masked,
                style = RageType.mono.copy(fontSize = 18.sp),
                color = c.background,
            )
            Spacer(modifier = Modifier.height(14.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.Bottom,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Column {
                    Text(
                        text = "CARDHOLDER",
                        style = RageType.eyebrow.copy(fontSize = 9.5.sp),
                        color = c.background.copy(alpha = 0.6f),
                    )
                    Spacer(modifier = Modifier.height(2.dp))
                    Text(
                        text = cardholder ?: "Not set",
                        style = RageType.rowTitle.copy(
                            fontSize = 14.sp,
                            fontWeight = FontWeight.SemiBold,
                            fontStyle = if (cardholder == null) FontStyle.Italic else FontStyle.Normal,
                        ),
                        color = c.background,
                    )
                }
                Column(horizontalAlignment = Alignment.End) {
                    Text(
                        text = "EXPIRY",
                        style = RageType.eyebrow.copy(fontSize = 9.5.sp),
                        color = c.background.copy(alpha = 0.6f),
                    )
                    Spacer(modifier = Modifier.height(2.dp))
                    Text(
                        text = expiry ?: "Not set",
                        style = RageType.mono.copy(
                            fontSize = 14.sp,
                            fontStyle = if (expiry == null) FontStyle.Italic else FontStyle.Normal,
                        ),
                        color = c.background,
                    )
                }
            }
        }
        Spacer(modifier = Modifier.height(16.dp))

        Field(label = "Card number") {
            if (number == null) {
                EmptyValueRow()
            } else {
                SecretRow(
                    value = if (revealedField == "number") number else masked,
                    isRevealed = revealedField == "number",
                    onReveal = { revealedField = if (revealedField == "number") null else "number" },
                    onCopy = {
                        val bytes = number.toByteArray(Charsets.UTF_8)
                        clipboard.copySensitive(bytes, "card number")
                        bytes.fill(0)
                        showToast("Card number copied")
                    },
                )
            }
        }
        Field(
            label = "CVV",
            hint = "3 or 4-digit verification code on the card.",
        ) {
            if (cvv == null) {
                EmptyValueRow()
            } else {
                SecretRow(
                    value = if (revealedField == "cvv") cvv else "•••",
                    isRevealed = revealedField == "cvv",
                    onReveal = { revealedField = if (revealedField == "cvv") null else "cvv" },
                    onCopy = {
                        val bytes = cvv.toByteArray(Charsets.UTF_8)
                        clipboard.copySensitive(bytes, "cvv")
                        bytes.fill(0)
                        showToast("CVV copied")
                    },
                )
            }
        }
        if (item.notes != null) {
            NotesField(text = item.notes)
        }
    }
}

@Composable
private fun EmptyValueRow() {
    val c = rageColors
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(c.surfaceSunken, RoundedCornerShape(8.dp))
            .border(1.dp, c.border, RoundedCornerShape(8.dp))
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = "Not set",
            style = RageType.body.copy(fontSize = 14.sp, fontStyle = FontStyle.Italic),
            color = c.fgSecondary,
        )
    }
}

@Composable
private fun SecretRow(
    value: String,
    isRevealed: Boolean,
    onReveal: () -> Unit,
    onCopy: () -> Unit,
) {
    val c = rageColors
    val borderColor = if (isRevealed) c.success else c.border
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(c.surfaceSunken, RoundedCornerShape(8.dp))
            .border(1.dp, borderColor, RoundedCornerShape(8.dp))
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Mono(
            text = value,
            size = 14,
            color = if (isRevealed) c.fgEmphasis else c.fgPrimary,
            modifier = Modifier.weight(1f),
            style = RageType.mono.copy(
                fontWeight = if (isRevealed) FontWeight.Medium else FontWeight.Normal,
            ),
        )
        Box(
            modifier = Modifier
                .size(28.dp)
                .clickable(onClick = onReveal),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                imageVector = if (isRevealed) Icons.Outlined.VisibilityOff else Icons.Outlined.Visibility,
                contentDescription = if (isRevealed) "Hide" else "Reveal",
                tint = c.fgPrimary,
                modifier = Modifier.size(16.dp),
            )
        }
        CopyButton(onCopy = onCopy, compact = true)
    }
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
