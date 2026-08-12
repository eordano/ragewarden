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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material.icons.outlined.LockOpen
import androidx.compose.material.icons.outlined.VisibilityOff
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import ragewarden.ragedroid.data.BitwardenVaultRepository
import ragewarden.ragedroid.data.VaultBridge
import ragewarden.ragedroid.model.VaultItem
import ragewarden.ragedroid.ui.components.AppBar
import ragewarden.ragedroid.ui.components.ButtonVariant
import ragewarden.ragedroid.ui.components.IconBtn
import ragewarden.ragedroid.ui.components.Mono
import ragewarden.ragedroid.ui.components.RageButton
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors

private const val REVEAL_AUTO_CLEAR_SECS = 8

@Composable
fun RecoverFromPhraseScreen(
    onBack: () -> Unit,
    onToast: (String) -> Unit = {},
    repo: BitwardenVaultRepository? = VaultBridge.repository(),
) {
    val c = rageColors
    val scope = rememberCoroutineScope()
    var phrase by remember { mutableStateOf("") }
    var working by remember { mutableStateOf(false) }
    var failedItemIds by remember { mutableStateOf<Set<String>>(emptySet()) }
    var openItemId by remember { mutableStateOf<String?>(null) }
    var revealedPlaintext by remember { mutableStateOf<ByteArray?>(null) }
    var revealSecsLeft by remember { mutableStateOf(REVEAL_AUTO_CLEAR_SECS) }

    val items = remember(repo) {
        repo?.snapshot()?.filter { it.rage } ?: emptyList()
    }

    DisposableEffect(Unit) {
        onDispose { revealedPlaintext?.fill(0) }
    }

    LaunchedEffect(revealedPlaintext) {
        val pt = revealedPlaintext ?: return@LaunchedEffect
        revealSecsLeft = REVEAL_AUTO_CLEAR_SECS
        while (revealSecsLeft > 0) {
            delay(1000)
            revealSecsLeft -= 1
        }
        pt.fill(0)
        revealedPlaintext = null
        openItemId = null
        onToast("Plaintext cleared from screen")
    }

    val wordCount = remember(phrase) {
        phrase.trim().split(Regex("\\s+")).count { it.isNotBlank() }
    }
    val canRecover = wordCount == 24 && !working && repo != null

    Column(modifier = Modifier.fillMaxSize().background(c.background)) {
        AppBar(
            title = "Recover from paper backup",
            leading = {
                IconBtn(
                    icon = Icons.AutoMirrored.Outlined.ArrowBack,
                    contentDescription = "Back",
                    onClick = onBack,
                )
            },
        )

        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 18.dp, vertical = 12.dp),
        ) {
            item("intro") {
                Text(
                    text = "Type the 24-word recovery phrase you printed when you enrolled the paper backup.",
                    style = RageType.body.copy(fontSize = 14.5.sp, lineHeight = 21.sp),
                    color = c.fgPrimary,
                )
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = "Nothing is saved. The derived identity stays in memory only long enough to unwrap the secrets you ask for.",
                    style = RageType.caption.copy(fontSize = 12.5.sp, lineHeight = 18.sp),
                    color = c.fgSecondary,
                )
                Spacer(modifier = Modifier.height(14.dp))
            }

            item("phrase") {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(c.surfaceSunken, RoundedCornerShape(8.dp))
                        .border(1.dp, c.border, RoundedCornerShape(8.dp))
                        .padding(horizontal = 12.dp, vertical = 10.dp),
                ) {
                    BasicTextField(
                        value = phrase,
                        onValueChange = { phrase = it },
                        textStyle = RageType.mono.copy(
                            fontFamily = FontFamily.Monospace,
                            fontSize = 13.5.sp,
                            lineHeight = 20.sp,
                            color = c.fgPrimary,
                        ),
                        cursorBrush = SolidColor(c.accent),
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(160.dp),
                        decorationBox = { inner ->
                            if (phrase.isEmpty()) {
                                Text(
                                    text = "abandon ability able about above ...",
                                    style = RageType.mono.copy(
                                        fontFamily = FontFamily.Monospace,
                                        fontSize = 13.5.sp,
                                        color = c.fgSecondary,
                                    ),
                                )
                            }
                            inner()
                        },
                    )
                }
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = "$wordCount of 24 words",
                    style = RageType.caption.copy(fontSize = 12.sp),
                    color = if (wordCount == 24) c.success else c.fgSecondary,
                )
                Spacer(modifier = Modifier.height(14.dp))
                RageButton(
                    label = if (working) "Working..." else "Recover",
                    onClick = onRecover@{
                        val r = repo ?: return@onRecover
                        if (!canRecover) return@onRecover
                        working = true
                        failedItemIds = emptySet()
                        scope.launch {
                            val sample = items.firstOrNull()
                            if (sample != null) {
                                val probe = r.decryptWithRecoveryPhrase(sample.id, phrase)
                                if (probe.isFailure) {
                                    val msg = probe.exceptionOrNull()?.message.orEmpty()
                                    val isPhraseError = msg.contains("recovery::from_phrase") ||
                                        msg.contains("mnemonic", ignoreCase = true)
                                    if (isPhraseError) {
                                        onToast("That phrase isn't a valid 24-word backup")
                                    }
                                }
                            }
                            working = false
                        }
                    },
                    icon = Icons.Outlined.LockOpen,
                    fullWidth = true,
                    enabled = canRecover,
                )
                Spacer(modifier = Modifier.height(20.dp))
            }

            if (items.isEmpty()) {
                item("empty") {
                    Text(
                        text = "No protected items in this vault yet.",
                        style = RageType.body.copy(fontSize = 14.sp),
                        color = c.fgSecondary,
                    )
                }
            } else {
                item("items_header") {
                    Text(
                        text = "Tap an item to reveal its plaintext using the typed phrase.",
                        style = RageType.caption.copy(fontSize = 12.sp),
                        color = c.fgSecondary,
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                }
                items(items.size, key = { idx -> items[idx].id }) { idx ->
                    val it = items[idx]
                    val expanded = openItemId == it.id && revealedPlaintext != null
                    val failed = it.id in failedItemIds
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(bottom = 8.dp)
                            .background(c.surfaceElevated, RoundedCornerShape(10.dp))
                            .border(
                                1.dp,
                                if (expanded) c.success else if (failed) c.danger else c.border,
                                RoundedCornerShape(10.dp),
                            )
                            .clickable(enabled = phrase.isNotBlank() && repo != null) {
                                if (repo == null) return@clickable
                                if (expanded) {
                                    revealedPlaintext?.fill(0)
                                    revealedPlaintext = null
                                    openItemId = null
                                    return@clickable
                                }
                                scope.launch {
                                    revealedPlaintext?.fill(0)
                                    revealedPlaintext = null
                                    val res = repo.decryptWithRecoveryPhrase(it.id, phrase)
                                    res.onSuccess { pt ->
                                        revealedPlaintext = pt
                                        openItemId = it.id
                                        failedItemIds = failedItemIds - it.id
                                    }.onFailure { e ->
                                        failedItemIds = failedItemIds + it.id
                                        val msg = e.message.orEmpty()
                                        val hint = when {
                                            msg.contains("mnemonic", ignoreCase = true) ->
                                                "Phrase is not a valid 24-word backup"
                                            msg.contains("no matching key", ignoreCase = true) ||
                                                msg.contains("decrypt", ignoreCase = true) ->
                                                "${it.name} can't be unlocked by this phrase"
                                            else -> "Recover failed: ${e.message}"
                                        }
                                        onToast(hint)
                                    }
                                }
                            }
                            .padding(horizontal = 14.dp, vertical = 12.dp),
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Box(
                                modifier = Modifier
                                    .size(32.dp)
                                    .background(c.tile, RoundedCornerShape(8.dp)),
                                contentAlignment = Alignment.Center,
                            ) {
                                Icon(
                                    imageVector = Icons.Outlined.Description,
                                    contentDescription = null,
                                    tint = c.accent,
                                    modifier = Modifier.size(16.dp),
                                )
                            }
                            Spacer(modifier = Modifier.size(12.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = it.name,
                                    style = RageType.rowTitle.copy(fontSize = 14.5.sp),
                                    color = c.fgEmphasis,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                )
                                Text(
                                    text = it.username.ifBlank { it.site.ifBlank { "--" } },
                                    style = RageType.caption.copy(fontSize = 11.5.sp),
                                    color = c.fgSecondary,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                )
                            }
                        }
                        if (expanded) {
                            Spacer(modifier = Modifier.size(10.dp))
                            Box(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(1.dp)
                                    .background(c.divider),
                            )
                            Spacer(modifier = Modifier.size(10.dp))
                            Mono(
                                text = String(revealedPlaintext!!, Charsets.UTF_8),
                                size = 13,
                                color = c.fgEmphasis,
                                modifier = Modifier.fillMaxWidth(),
                            )
                            Spacer(modifier = Modifier.size(8.dp))
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
                                    text = "Auto-clear in ${revealSecsLeft}s",
                                    style = RageType.meta,
                                    color = c.fgSecondary,
                                )
                                Spacer(modifier = Modifier.weight(1f))
                                Row(
                                    modifier = Modifier
                                        .background(c.surface, RoundedCornerShape(6.dp))
                                        .border(1.dp, c.border, RoundedCornerShape(6.dp))
                                        .clickable {
                                            revealedPlaintext?.fill(0)
                                            revealedPlaintext = null
                                            openItemId = null
                                        }
                                        .padding(horizontal = 8.dp, vertical = 4.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(4.dp),
                                ) {
                                    Icon(
                                        imageVector = Icons.Outlined.VisibilityOff,
                                        contentDescription = null,
                                        tint = c.fgPrimary,
                                        modifier = Modifier.size(13.dp),
                                    )
                                    Text(text = "Hide", style = RageType.caption, color = c.fgPrimary)
                                }
                            }
                        }
                    }
                }
            }

            item("footer") {
                Spacer(modifier = Modifier.height(18.dp))
                RageButton(
                    label = "Done",
                    onClick = onBack,
                    variant = ButtonVariant.Secondary,
                    fullWidth = true,
                )
                Spacer(modifier = Modifier.height(24.dp))
            }
        }
    }
}
