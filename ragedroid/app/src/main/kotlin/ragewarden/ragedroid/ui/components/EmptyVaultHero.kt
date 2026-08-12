package ragewarden.ragedroid.ui.components

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Bolt
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors

private val HeroTitle = RageType.h1.copy(
    fontSize = 26.sp,
    lineHeight = 30.sp,
    letterSpacing = (-0.015).em,
)

private val HeroBody = RageType.body.copy(fontSize = 15.sp, lineHeight = 23.sp)

private val HeroFooter = RageType.body.copy(
    fontSize = 12.5.sp,
    lineHeight = 19.sp,
    fontStyle = FontStyle.Italic,
)

@Composable
fun EmptyVaultHero(
    syncHost: String,
    onAdd: () -> Unit,
    onAutofill: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val c = rageColors
    Column(
        modifier = modifier
            .fillMaxSize()
            .background(c.background)
            .padding(horizontal = 24.dp, vertical = 40.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        VaultGlyph(modifier = Modifier.size(140.dp))
        Spacer(modifier = Modifier.height(24.dp))
        Text(
            text = "An empty vault.",
            style = HeroTitle,
            color = c.fgEmphasis,
            textAlign = TextAlign.Center,
        )
        Spacer(modifier = Modifier.height(12.dp))
        Text(
            text = "Add your first secret, or let RageDroid catch credentials as you sign into apps.",
            style = HeroBody.copy(textAlign = TextAlign.Center),
            color = c.fgSecondary,
            modifier = Modifier.widthIn(max = 280.dp),
        )
        Spacer(modifier = Modifier.height(20.dp))

        Column(
            modifier = Modifier.widthIn(max = 280.dp).fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            HeroButton(
                label = "Add your first secret",
                icon = Icons.Outlined.Add,
                primary = true,
                onClick = onAdd,
            )
            HeroButton(
                label = "Catch a credential via autofill",
                icon = Icons.Outlined.Bolt,
                primary = false,
                onClick = onAutofill,
            )
        }
        Spacer(modifier = Modifier.height(24.dp))
        Text(
            text = buildSyncFooter(syncHost),
            style = HeroFooter.copy(textAlign = TextAlign.Center),
            color = c.fgSecondary,
        )
    }
}

private fun buildSyncFooter(host: String): AnnotatedString = buildAnnotatedString {
    append("Your vault syncs from ")
    withStyle(
        SpanStyle(
            fontFamily = FontFamily.Monospace,
            fontStyle = FontStyle.Normal,
            fontSize = 11.5.sp,
        ),
    ) {
        append(host)
    }
    append(". Nothing here yet.")
}

@Composable
private fun VaultGlyph(modifier: Modifier = Modifier) {
    val c = rageColors
    val borderColor = c.border
    val accentColor = c.accent
    val secondaryColor = c.fgSecondary.copy(alpha = 0.5f)
    Canvas(modifier = modifier) {
        val s = size.width
        val cx = s / 2f
        val cy = size.height / 2f
        val rOuter = s * 0.45f
        val rInner = s * 0.317f
        drawCircle(color = borderColor, radius = rOuter, center = Offset(cx, cy), style = Stroke(width = 2f))
        drawCircle(color = borderColor, radius = rInner, center = Offset(cx, cy), style = Stroke(width = 2f))
        drawCircle(color = accentColor, radius = s * 0.05f, center = Offset(cx, cy))
        val tickLen = s * 0.133f
        val tickOff = s * 0.05f
        val tickPairs = listOf(
            Offset(cx, cy - rOuter - tickOff) to Offset(cx, cy - rOuter - tickOff + tickLen),
            Offset(cx, cy + rOuter + tickOff) to Offset(cx, cy + rOuter + tickOff - tickLen),
            Offset(cx - rOuter - tickOff, cy) to Offset(cx - rOuter - tickOff + tickLen, cy),
            Offset(cx + rOuter + tickOff, cy) to Offset(cx + rOuter + tickOff - tickLen, cy),
        )
        tickPairs.forEach { (start, end) ->
            drawLine(color = accentColor, start = start, end = end, strokeWidth = 2f, cap = StrokeCap.Round)
        }
        val diagLen = s * 0.033f
        val diagPairs = listOf(
            Offset(cx + rInner * 0.74f, cy - rInner * 0.74f) to Offset(cx + rInner * 0.74f + diagLen, cy - rInner * 0.74f - diagLen),
            Offset(cx - rInner * 0.74f, cy - rInner * 0.74f) to Offset(cx - rInner * 0.74f - diagLen, cy - rInner * 0.74f - diagLen),
            Offset(cx + rInner * 0.74f, cy + rInner * 0.74f) to Offset(cx + rInner * 0.74f + diagLen, cy + rInner * 0.74f + diagLen),
            Offset(cx - rInner * 0.74f, cy + rInner * 0.74f) to Offset(cx - rInner * 0.74f - diagLen, cy + rInner * 0.74f + diagLen),
        )
        diagPairs.forEach { (start, end) ->
            drawLine(color = secondaryColor, start = start, end = end, strokeWidth = 1.5f, cap = StrokeCap.Round)
        }
    }
}

@Composable
private fun HeroButton(
    label: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    primary: Boolean,
    onClick: () -> Unit,
) {
    val variant = if (primary) ButtonVariant.Primary else ButtonVariant.Secondary
    RageButton(
        label = label,
        onClick = onClick,
        icon = icon,
        variant = variant,
        fullWidth = true,
    )
}
