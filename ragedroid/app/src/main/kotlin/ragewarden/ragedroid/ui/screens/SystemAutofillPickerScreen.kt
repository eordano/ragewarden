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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Bolt
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.Nfc
import androidx.compose.material.icons.outlined.Search
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import ragewarden.ragedroid.autofill.HostMatcher
import ragewarden.ragedroid.data.VaultBridge
import ragewarden.ragedroid.model.VaultItem
import ragewarden.ragedroid.ui.components.IconBtn
import ragewarden.ragedroid.ui.components.Mono
import ragewarden.ragedroid.ui.components.RageButton
import ragewarden.ragedroid.ui.theme.RageTheme
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors

@Composable
fun SystemAutofillPickerScreen(
    domain: String?,
    packageName: String?,
    onAutofill: (VaultItem) -> Unit,
    onCreate: () -> Unit,
    onBack: () -> Unit,
) {
    val c = rageColors
    val ctx = androidx.compose.ui.platform.LocalContext.current.applicationContext
    val backend = remember(ctx) { VaultBridge.ensureBackend(ctx) }
    val sampleDomains: List<String> = remember(backend) {
        backend.snapshot()
            .mapNotNull { it.site.takeIf { s -> s.isNotBlank() } }
            .distinct()
            .take(3)
    }
    var activeDomain by remember(domain, sampleDomains) {
        mutableStateOf(domain ?: sampleDomains.firstOrNull() ?: "")
    }
    val matches: List<VaultItem> = remember(activeDomain, packageName) {
        HostMatcher.matchVaultItems(
            items = backend.snapshot(),
            webDomain = activeDomain,
            packageName = packageName,
        )
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(Color(0x66000000)),
    ) {
        Box(
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .clickable(onClick = onBack),
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(start = 16.dp, end = 16.dp, top = 40.dp),
            ) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(c.surfaceElevated, RoundedCornerShape(12.dp))
                        .padding(horizontal = 14.dp, vertical = 14.dp),
                ) {
                    Column {
                        Mono(
                            text = "https://$activeDomain/sign_in",
                            size = 11,
                            color = c.fgSecondary,
                        )
                        Spacer(modifier = Modifier.height(12.dp))
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(c.tile, RoundedCornerShape(6.dp))
                                .padding(horizontal = 8.dp, vertical = 8.dp),
                        ) {
                            Text(
                                text = "Email",
                                style = RageType.sansBody.copy(fontSize = 13.sp),
                                color = c.fgSecondary,
                            )
                        }
                        Spacer(modifier = Modifier.height(8.dp))
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(c.tile, RoundedCornerShape(6.dp))
                                .padding(horizontal = 8.dp, vertical = 8.dp),
                        ) {
                            Text(
                                text = "Password",
                                style = RageType.sansBody.copy(fontSize = 13.sp),
                                color = c.fgSecondary,
                            )
                        }
                    }
                }
            }
        }

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .background(
                    c.surface,
                    RoundedCornerShape(topStart = 18.dp, topEnd = 18.dp),
                )
                .padding(top = 6.dp, bottom = 16.dp),
        ) {
            Box(
                modifier = Modifier
                    .padding(top = 6.dp, bottom = 12.dp)
                    .size(width = 36.dp, height = 4.dp)
                    .align(Alignment.CenterHorizontally)
                    .background(c.border, RoundedCornerShape(2.dp)),
            )

            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(start = 16.dp, end = 8.dp, bottom = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Box(
                    modifier = Modifier
                        .size(28.dp)
                        .background(c.accent, RoundedCornerShape(6.dp)),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        imageVector = Icons.Outlined.Bolt,
                        contentDescription = null,
                        tint = c.background,
                        modifier = Modifier.size(14.dp),
                    )
                }
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "RageDroid",
                        style = RageType.rowTitle.copy(fontSize = 14.sp, lineHeight = 18.sp),
                        color = c.fgEmphasis,
                    )
                    Mono(
                        text = "autofill · $activeDomain",
                        size = 11,
                        color = c.fgSecondary,
                    )
                }
                IconBtn(
                    icon = Icons.Outlined.Close,
                    contentDescription = "Close",
                    onClick = onBack,
                    iconSize = 18,
                )
            }

            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 0.dp),
                horizontalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                sampleDomains.forEach { d ->
                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .background(
                                if (activeDomain == d) c.tile else Color.Transparent,
                                RoundedCornerShape(6.dp),
                            )
                            .border(
                                1.dp,
                                if (activeDomain == d) c.border else Color.Transparent,
                                RoundedCornerShape(6.dp),
                            )
                            .clickable { activeDomain = d }
                            .padding(horizontal = 8.dp, vertical = 6.dp),
                    ) {
                        Mono(
                            text = d,
                            size = 10,
                            color = c.fgSecondary,
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(8.dp))

            if (matches.isEmpty()) {
                NoMatchView(domain = activeDomain, onCreate = onCreate)
            } else {
                Column(modifier = Modifier.fillMaxWidth()) {
                    matches.take(3).forEach { item ->
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(1.dp)
                                .background(c.divider),
                        )
                        AutofillRow(item = item, onClick = { onAutofill(item) })
                    }
                }
            }
        }
    }
}

@Composable
private fun NoMatchView(domain: String, onCreate: () -> Unit) {
    val c = rageColors
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 20.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Box(
            modifier = Modifier
                .size(48.dp)
                .background(c.tile, RoundedCornerShape(24.dp)),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                imageVector = Icons.Outlined.Search,
                contentDescription = null,
                tint = c.fgSecondary,
                modifier = Modifier.size(20.dp),
            )
        }
        Spacer(modifier = Modifier.height(12.dp))
        Text(
            text = "No match for $domain",
            style = RageType.h2.copy(fontSize = 16.sp, lineHeight = 20.sp),
            color = c.fgEmphasis,
            textAlign = TextAlign.Center,
        )
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = "Save your credentials here and they'll appear next time.",
            style = RageType.body.copy(fontSize = 13.sp, lineHeight = 20.sp),
            color = c.fgSecondary,
            textAlign = TextAlign.Center,
        )
        Spacer(modifier = Modifier.height(14.dp))
        RageButton(
            label = "Save new login",
            onClick = onCreate,
            icon = Icons.Outlined.Add,
        )
    }
}

@Composable
private fun AutofillRow(item: VaultItem, onClick: () -> Unit) {
    val c = rageColors
    val initials = item.name.filter { it.isLetter() }.take(2).uppercase().ifEmpty { "··" }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Box(
            modifier = Modifier
                .size(36.dp)
                .background(c.tile, RoundedCornerShape(8.dp)),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                text = initials,
                style = RageType.rowTitle.copy(fontSize = 14.sp, lineHeight = 18.sp, fontWeight = FontWeight.Bold),
                color = c.accent,
            )
        }
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = item.name,
                style = RageType.rowTitle.copy(fontSize = 14.5.sp, lineHeight = 18.sp),
                color = c.fgEmphasis,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = item.username,
                style = RageType.sansBody.copy(fontSize = 11.5.sp, lineHeight = 14.sp),
                color = c.fgSecondary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.padding(top = 2.dp),
            )
        }
        if (item.rage) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Icon(
                    imageVector = Icons.Outlined.Nfc,
                    contentDescription = null,
                    tint = c.accent,
                    modifier = Modifier.size(12.dp),
                )
                Text(
                    text = "TAP TO FILL",
                    style = RageType.eyebrow.copy(fontSize = 10.sp, fontWeight = FontWeight.Bold),
                    color = c.accent,
                )
            }
        } else {
            Text(
                text = "FILL",
                style = RageType.eyebrow.copy(fontSize = 10.sp, fontWeight = FontWeight.SemiBold),
                color = c.fgSecondary,
            )
        }
    }
}

