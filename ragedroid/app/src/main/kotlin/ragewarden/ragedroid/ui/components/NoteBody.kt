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
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import ragewarden.ragedroid.data.Clipboard
import ragewarden.ragedroid.model.VaultItem
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors

private const val REVEAL_AUTO_HIDE_SECS = 10
private val URL_REGEX: Regex = Regex(
    pattern = "(https?://[^\\s)]+|[a-z0-9.-]+\\.[a-z]{2,}(?:/[^\\s)]*)?)",
    options = setOf(RegexOption.IGNORE_CASE),
)

@Composable
fun NoteBody(
    item: VaultItem,
    clipboard: Clipboard,
    showToast: (String) -> Unit,
) {
    val c = rageColors
    var showing by remember { mutableStateOf(false) }
    val body: String = item.notes.orEmpty()

    LaunchedEffect(showing) {
        if (showing) {
            delay(REVEAL_AUTO_HIDE_SECS * 1000L)
            showing = false
        }
    }

    val linkified: AnnotatedString = remember(body) { linkifyNotes(body, c.accent) }

    Field(label = "Body") {
        if (showing) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(c.surfaceElevated, RoundedCornerShape(10.dp))
                    .border(1.dp, c.success, RoundedCornerShape(10.dp))
                    .padding(horizontal = 14.dp, vertical = 14.dp),
            ) {
                Text(
                    text = linkified,
                    style = RageType.body.copy(fontSize = 14.5.sp),
                    color = c.fgEmphasis,
                )
                Spacer(modifier = Modifier.height(12.dp))
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
                            val bytes = body.toByteArray(Charsets.UTF_8)
                            clipboard.copySensitive(bytes, "note")
                            bytes.fill(0)
                            showToast("Note copied")
                        },
                        compact = true,
                    )
                }
            }
        } else {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(c.surfaceSunken, RoundedCornerShape(10.dp))
                    .border(1.dp, c.border, RoundedCornerShape(10.dp))
                    .clickable { showing = true }
                    .padding(horizontal = 14.dp, vertical = 20.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Icon(
                    imageVector = Icons.Outlined.Visibility,
                    contentDescription = null,
                    tint = c.accent,
                    modifier = Modifier.size(20.dp),
                )
                Text(
                    text = "Tap your authenticator to reveal",
                    style = RageType.sansBody.copy(
                        fontSize = 13.sp,
                        textAlign = TextAlign.Center,
                    ),
                    color = c.fgSecondary,
                )
            }
        }
    }
}

private fun linkifyNotes(
    text: String,
    accent: androidx.compose.ui.graphics.Color,
): AnnotatedString = buildAnnotatedString {
    if (text.isEmpty()) return@buildAnnotatedString
    var last = 0
    URL_REGEX.findAll(text).forEach { m ->
        val start = m.range.first
        val end = m.range.last + 1
        if (start > last) append(text.substring(last, start))
        withStyle(
            SpanStyle(
                color = accent,
                textDecoration = TextDecoration.Underline,
            ),
        ) {
            append(text.substring(start, end))
        }
        last = end
    }
    if (last < text.length) append(text.substring(last))
}
