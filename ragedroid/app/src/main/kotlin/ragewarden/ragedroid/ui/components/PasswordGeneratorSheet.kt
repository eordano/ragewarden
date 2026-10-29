package ragewarden.ragedroid.ui.components

import ragewarden.ragedroid.R
import androidx.compose.ui.res.stringResource
import ragewarden.ragedroid.jni.RageNative
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material3.Slider
import androidx.compose.material3.SliderDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors

private enum class GenMode { Chars, Words }

private val ResultStyle = RageType.mono.copy(
    fontWeight = FontWeight.Normal,
    fontSize = 16.sp,
    lineHeight = 22.sp,
)

private val ModeTabStyle = RageType.button.copy(fontSize = 12.5.sp, lineHeight = 16.sp)

private val LengthLabelStyle = RageType.sansBody.copy(fontSize = 13.sp, lineHeight = 17.sp)

private val LengthValueStyle = RageType.mono.copy(
    fontWeight = FontWeight.SemiBold,
    fontSize = 13.sp,
    lineHeight = 17.sp,
)

private val WordsHintStyle = RageType.body.copy(
    fontSize = 13.sp,
    lineHeight = 19.5.sp,
    fontStyle = FontStyle.Italic,
)

private val CharsetLabelStyle = TextStyle(
    fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
    fontWeight = FontWeight.Normal,
    fontSize = 14.sp,
    lineHeight = 20.sp,
)

@Composable
fun PasswordGeneratorSheet(
    open: Boolean,
    onClose: () -> Unit,
    onUse: (String) -> Unit,
    onCopy: (String) -> Unit = {},
) {
    var mode by remember { mutableStateOf(GenMode.Chars) }
    var length by remember { mutableStateOf(20) }
    var wordCount by remember { mutableStateOf(4) }
    var upper by remember { mutableStateOf(true) }
    var lower by remember { mutableStateOf(true) }
    var digits by remember { mutableStateOf(true) }
    var symbols by remember { mutableStateOf(true) }
    var pw by remember { mutableStateOf("") }

    val regen: () -> Unit = {
        pw = runCatching {
            if (mode == GenMode.Words) {
                RageNative.generatePassphrase(wordCount.coerceIn(4, 24), "-")
            } else {
                val anyClass = lower || upper || digits || symbols
                RageNative.generatePassword(length.coerceIn(8, 128), lower || !anyClass, upper, digits, symbols)
            }
        }.getOrElse { "" }
    }

    LaunchedEffect(open, mode, length, wordCount, upper, lower, digits, symbols) {
        if (open) regen()
    }

    Sheet(open = open, onDismiss = onClose, title = stringResource(R.string.generate_password)) {
        val c = rageColors
        Column(modifier = Modifier.fillMaxWidth()) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .defaultMinSize(minHeight = 72.dp)
                    .background(c.tile, RoundedCornerShape(10.dp))
                    .border(1.dp, c.border, RoundedCornerShape(10.dp))
                    .padding(14.dp),
            ) {
                Text(
                    text = pw.ifEmpty { "..." },
                    style = ResultStyle,
                    color = c.fgEmphasis,
                )
            }
            Spacer(modifier = Modifier.height(10.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RageButton(
                    label = stringResource(R.string.regenerate),
                    onClick = regen,
                    icon = Icons.Outlined.Refresh,
                    variant = ButtonVariant.Secondary,
                )
                RageButton(
                    label = stringResource(R.string.copy),
                    onClick = { onCopy(pw) },
                    icon = Icons.Outlined.ContentCopy,
                    variant = ButtonVariant.Secondary,
                )
                Box(modifier = Modifier.weight(1f)) {
                    RageButton(
                        label = stringResource(R.string.use),
                        onClick = {
                            onUse(pw)
                            onClose()
                        },
                        fullWidth = true,
                    )
                }
            }
            Spacer(modifier = Modifier.height(18.dp))

            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(c.tile, RoundedCornerShape(8.dp))
                    .padding(3.dp),
            ) {
                ModeToggle(
                    label = stringResource(R.string.random_characters),
                    active = mode == GenMode.Chars,
                    modifier = Modifier.weight(1f),
                    onClick = { mode = GenMode.Chars },
                )
                ModeToggle(
                    label = stringResource(R.string.memorable_words),
                    active = mode == GenMode.Words,
                    modifier = Modifier.weight(1f),
                    onClick = { mode = GenMode.Words },
                )
            }
            Spacer(modifier = Modifier.height(16.dp))

            if (mode == GenMode.Chars) {
                LengthRow(label = stringResource(R.string.length), value = length)
                Spacer(modifier = Modifier.height(6.dp))
                Slider(
                    value = length.toFloat(),
                    onValueChange = { length = it.toInt() },
                    valueRange = 8f..48f,
                    steps = 39,
                    colors = SliderDefaults.colors(
                        thumbColor = c.accent,
                        activeTrackColor = c.accent,
                        inactiveTrackColor = c.border,
                    ),
                )
                Spacer(modifier = Modifier.height(16.dp))
                CharsetToggle(label = "A-Z", on = upper, onChange = { upper = it }, last = false)
                CharsetToggle(label = "a-z", on = lower, onChange = { lower = it }, last = false)
                CharsetToggle(label = "0-9", on = digits, onChange = { digits = it }, last = false)
                CharsetToggle(label = "!@#%...", on = symbols, onChange = { symbols = it }, last = true)
            } else {
                LengthRow(label = stringResource(R.string.words), value = wordCount)
                Spacer(modifier = Modifier.height(6.dp))
                Slider(
                    value = wordCount.toFloat(),
                    onValueChange = { wordCount = it.toInt() },
                    valueRange = 3f..8f,
                    steps = 4,
                    colors = SliderDefaults.colors(
                        thumbColor = c.accent,
                        activeTrackColor = c.accent,
                        inactiveTrackColor = c.border,
                    ),
                )
                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = stringResource(R.string.hyphenated_words_are_easier_to_dictate),
                    style = WordsHintStyle,
                    color = c.fgSecondary,
                )
            }
        }
    }
}

@Composable
private fun ModeToggle(
    label: String,
    active: Boolean,
    modifier: Modifier,
    onClick: () -> Unit,
) {
    val c = rageColors
    val base = if (active) {
        modifier
            .shadow(elevation = 2.dp, shape = RoundedCornerShape(6.dp))
            .background(c.surface, RoundedCornerShape(6.dp))
    } else {
        modifier.background(Color.Transparent, RoundedCornerShape(6.dp))
    }
    Box(
        modifier = base
            .clickable(onClick = onClick)
            .padding(horizontal = 10.dp, vertical = 8.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = label,
            style = ModeTabStyle,
            color = if (active) c.fgEmphasis else c.fgSecondary,
        )
    }
}

@Composable
private fun LengthRow(label: String, value: Int) {
    val c = rageColors
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(text = label, style = LengthLabelStyle, color = c.fgPrimary)
        Text(text = value.toString(), style = LengthValueStyle, color = c.fgEmphasis)
    }
}

@Composable
private fun CharsetToggle(
    label: String,
    on: Boolean,
    onChange: (Boolean) -> Unit,
    last: Boolean,
) {
    val c = rageColors
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(text = label, style = CharsetLabelStyle, color = c.fgPrimary)
        Switch(
            checked = on,
            onCheckedChange = onChange,
            colors = SwitchDefaults.colors(
                checkedThumbColor = c.background,
                checkedTrackColor = c.accent,
                uncheckedThumbColor = c.surface,
                uncheckedTrackColor = c.border,
                checkedBorderColor = c.accent,
                uncheckedBorderColor = c.border,
            ),
        )
    }
    if (!last) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(1.dp)
                .background(c.divider),
        )
    }
}
