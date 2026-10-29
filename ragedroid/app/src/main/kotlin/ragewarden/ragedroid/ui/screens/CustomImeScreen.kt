package ragewarden.ragedroid.ui.screens

import ragewarden.ragedroid.R
import androidx.compose.ui.res.stringResource
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
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
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.automirrored.outlined.Backspace
import androidx.compose.material.icons.automirrored.outlined.KeyboardReturn
import androidx.compose.material.icons.outlined.Bolt
import androidx.compose.material.icons.outlined.Nfc
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import ragewarden.ragedroid.autofill.HostMatcher
import ragewarden.ragedroid.data.VaultBridge
import ragewarden.ragedroid.model.VaultItem
import ragewarden.ragedroid.ui.components.AppBar
import ragewarden.ragedroid.ui.components.BackButton
import ragewarden.ragedroid.ui.components.Field
import ragewarden.ragedroid.ui.components.TextInput
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors

private val QWERTY: List<List<String>> = listOf(
    listOf("q", "w", "e", "r", "t", "y", "u", "i", "o", "p"),
    listOf("a", "s", "d", "f", "g", "h", "j", "k", "l"),
    listOf("z", "x", "c", "v", "b", "n", "m"),
)

@Composable
fun CustomImeScreen(
    domain: String?,
    packageName: String?,
    onAutofill: (VaultItem) -> Unit,
    onBack: () -> Unit,
) {
    val c = rageColors
    val ctx = androidx.compose.ui.platform.LocalContext.current.applicationContext
    val backend = remember(ctx) { VaultBridge.ensureBackend(ctx) }
    val matches: List<VaultItem> = remember(domain, packageName) {
        HostMatcher.matchVaultItems(
            items = backend.snapshot(),
            webDomain = domain,
            packageName = packageName,
        ).take(3)
    }
    val title = stringResource(R.string.preview_nothing_here_is_live)
    val subtitle = domain ?: packageName

    Column(modifier = Modifier.fillMaxSize().background(c.background)) {
        Column(
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .padding(start = 16.dp, end = 16.dp, top = 40.dp, bottom = 8.dp),
        ) {
            AppBar(
                title = title,
                subtitle = subtitle,
                leading = { BackButton(onBack) },
            )
            Spacer(modifier = Modifier.height(16.dp))
            Field(label = stringResource(R.string.email)) {
                TextInput(value = "", onValueChange = {}, placeholder = stringResource(R.string.you_example_com))
            }
            Field(label = stringResource(R.string.password)) {
                TextInput(value = "", onValueChange = {}, placeholder = "••••••••", mono = true, password = true)
            }
        }

        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(1.dp)
                .background(c.border),
        )
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .background(c.surfaceSunken)
                .padding(start = 6.dp, end = 6.dp, top = 6.dp, bottom = 8.dp),
        ) {
            SuggestStrip(matches = matches, onAutofill = onAutofill)
            Spacer(modifier = Modifier.height(6.dp))
            QWERTY.forEachIndexed { index, row ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(
                            start = if (index == 1) 14.dp else 0.dp,
                            end = if (index == 1) 14.dp else 0.dp,
                            bottom = 4.dp,
                        ),
                    horizontalArrangement = Arrangement.spacedBy(4.dp, Alignment.CenterHorizontally),
                ) {
                    if (index == 2) {
                        KeyCap(modifier = Modifier.width(38.dp), small = true) {
                            Icon(
                                imageVector = Icons.AutoMirrored.Outlined.ArrowBack,
                                contentDescription = null,
                                tint = c.fgEmphasis,
                                modifier = Modifier.size(14.dp),
                            )
                        }
                    }
                    row.forEach { k ->
                        KeyCap(modifier = Modifier.weight(1f)) {
                            Text(
                                text = k,
                                style = RageType.sansBody.copy(fontSize = 15.sp, fontWeight = FontWeight.Medium),
                                color = c.fgEmphasis,
                            )
                        }
                    }
                    if (index == 2) {
                        KeyCap(modifier = Modifier.width(38.dp), small = true) {
                            Icon(
                                imageVector = Icons.AutoMirrored.Outlined.Backspace,
                                contentDescription = null,
                                tint = c.fgEmphasis,
                                modifier = Modifier.size(14.dp),
                            )
                        }
                    }
                }
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                KeyCap(modifier = Modifier.width(50.dp), small = true) {
                    Text(
                        text = "?123",
                        style = RageType.sansBody.copy(fontSize = 11.sp, fontWeight = FontWeight.Medium),
                        color = c.fgEmphasis,
                    )
                }
                KeyCap(modifier = Modifier.width(32.dp)) {
                    Text(
                        text = ",",
                        style = RageType.sansBody.copy(fontSize = 15.sp, fontWeight = FontWeight.Medium),
                        color = c.fgEmphasis,
                    )
                }
                KeyCap(modifier = Modifier.weight(1f)) {
                    Text(
                        text = stringResource(R.string.space),
                        style = RageType.sansBody.copy(fontSize = 15.sp, fontWeight = FontWeight.Medium),
                        color = c.fgEmphasis,
                    )
                }
                KeyCap(modifier = Modifier.width(32.dp)) {
                    Text(
                        text = ".",
                        style = RageType.sansBody.copy(fontSize = 15.sp, fontWeight = FontWeight.Medium),
                        color = c.fgEmphasis,
                    )
                }
                KeyCap(modifier = Modifier.width(50.dp), small = true) {
                    Icon(
                        imageVector = Icons.AutoMirrored.Outlined.KeyboardReturn,
                        contentDescription = null,
                        tint = c.fgEmphasis,
                        modifier = Modifier.size(14.dp),
                    )
                }
            }
        }
    }
}

@Composable
private fun SuggestStrip(matches: List<VaultItem>, onAutofill: (VaultItem) -> Unit) {
    val c = rageColors
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(c.surface, RoundedCornerShape(10.dp))
            .padding(horizontal = 10.dp, vertical = 8.dp)
            .horizontalScroll(rememberScrollState()),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Box(
            modifier = Modifier
                .size(24.dp)
                .background(c.accent, RoundedCornerShape(4.dp)),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                imageVector = Icons.Outlined.Bolt,
                contentDescription = null,
                tint = c.background,
                modifier = Modifier.size(12.dp),
            )
        }
        matches.forEach { m ->
            Row(
                modifier = Modifier
                    .background(c.tile, RoundedCornerShape(14.dp))
                    .border(1.dp, c.border, RoundedCornerShape(14.dp))
                    .clickable { onAutofill(m) }
                    .padding(horizontal = 10.dp, vertical = 5.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                if (m.rage) {
                    Icon(
                        imageVector = Icons.Outlined.Nfc,
                        contentDescription = null,
                        tint = c.accent,
                        modifier = Modifier.size(10.dp),
                    )
                }
                Text(
                    text = m.name,
                    style = RageType.sansBody.copy(fontSize = 12.sp, fontWeight = FontWeight.SemiBold),
                    color = c.fgEmphasis,
                )
            }
        }
    }
}

@Composable
private fun KeyCap(
    modifier: Modifier = Modifier,
    height: Dp = 38.dp,
    small: Boolean = false,
    content: @Composable () -> Unit,
) {
    val c = rageColors
    Box(
        modifier = modifier
            .height(height)
            .background(c.surface, RoundedCornerShape(6.dp))
            .border(1.dp, c.border, RoundedCornerShape(6.dp))
            .padding(horizontal = if (small) 4.dp else 6.dp),
        contentAlignment = Alignment.Center,
    ) {
        content()
    }
}

