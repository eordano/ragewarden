package ragewarden.ragedroid.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.outlined.Check
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material.icons.outlined.TouchApp
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import ragewarden.ragedroid.ui.components.AppBar
import ragewarden.ragedroid.ui.components.IconBtn
import ragewarden.ragedroid.ui.components.Mono
import ragewarden.ragedroid.ui.components.RageButton
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors

@Composable
fun BackfillWizardScreen(
    onBack: () -> Unit,
    onComplete: () -> Unit,
    onToast: (String) -> Unit = {},
    viewModel: BackfillViewModel = hiltViewModel(),
) {
    val c = rageColors
    val state by viewModel.state.collectAsStateWithLifecycle()

    LaunchedEffect(Unit) {
        viewModel.loadCandidates()
    }

    val backHandler: () -> Unit = {
        when {
            state.running -> Unit
            state.complete -> onComplete()
            else -> onBack()
        }
    }

    Column(modifier = Modifier.fillMaxSize().background(c.background)) {
        AppBar(
            title = "Protect existing items",
            leading = {
                IconBtn(
                    icon = Icons.AutoMirrored.Outlined.ArrowBack,
                    contentDescription = "Back",
                    onClick = { if (!state.running) backHandler() },
                )
            },
        )

        when {
            !state.running && !state.complete -> IntroStep(
                count = state.total,
                staleRageCount = state.staleRageItemCount,
                onBegin = { viewModel.start() },
                onMarkRotated = {
                    viewModel.markRotationFresh()
                    onToast("Rotation banner cleared")
                    onComplete()
                },
            )
            state.running -> RunningStep(
                processed = state.processed,
                total = state.total,
                currentName = state.currentName,
            )
            else -> DoneStep(
                processed = state.processed,
                failed = state.failed,
                onClose = {
                    val protectedCount = state.total - state.failed.size
                    onToast(
                        if (state.failed.isEmpty()) {
                            "Protected $protectedCount item${if (protectedCount == 1) "" else "s"}"
                        } else {
                            "Protected $protectedCount, ${state.failed.size} failed"
                        },
                    )
                    onComplete()
                },
            )
        }
    }
}

@Composable
private fun IntroStep(
    count: Int,
    staleRageCount: Int,
    onBegin: () -> Unit,
    onMarkRotated: () -> Unit,
) {
    val c = rageColors
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(start = 18.dp, end = 18.dp, top = 6.dp, bottom = 18.dp),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(c.surfaceSunken, RoundedCornerShape(10.dp))
                .border(1.dp, c.border, RoundedCornerShape(10.dp))
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Box(
                modifier = Modifier
                    .size(36.dp)
                    .background(c.surfaceElevated, RoundedCornerShape(8.dp)),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = Icons.Outlined.Shield,
                    contentDescription = null,
                    tint = c.accent,
                    modifier = Modifier.size(18.dp),
                )
            }
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = if (count == 1) "1 item" else "$count items",
                    style = RageType.rowTitle.copy(fontSize = 14.sp),
                    color = c.fgEmphasis,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = "Currently unprotected",
                    style = RageType.caption.copy(fontSize = 11.5.sp),
                    color = c.fgSecondary,
                )
            }
        }
        Spacer(modifier = Modifier.height(18.dp))
        Text(
            text = if (count == 0) {
                "Nothing to protect."
            } else {
                "$count item${if (count == 1) "" else "s"} in your vault aren't yet rage-protected."
            },
            style = RageType.h1.copy(
                fontSize = 22.sp,
                lineHeight = 26.sp,
                letterSpacing = (-0.015).em,
            ),
            color = c.fgEmphasis,
        )
        Spacer(modifier = Modifier.height(12.dp))
        Text(
            text = when {
                count == 0 && staleRageCount > 0 -> {
                    val itemForm = if (staleRageCount == 1) "item is" else "items are"
                    "All items are already protected, but $staleRageCount $itemForm encrypted to a previous recipient set."
                }
                count == 0 ->
                    "All your existing items are already wrapped with rage. There's nothing to do here."
                else ->
                    "Encrypting them now will make them require a tap to reveal."
            },
            style = RageType.body.copy(fontSize = 15.sp, lineHeight = 22.sp),
            color = c.fgPrimary,
        )
        Spacer(modifier = Modifier.height(14.dp))
        InfoCallout(
            text = if (count == 0 && staleRageCount > 0) {
                "Reveal an item from the vault and the app silently re-encrypts it to the current recipient set in the background. Once every item has been touched, the banner clears itself. You can also dismiss the banner now if you've already rotated everything you care about."
            } else {
                "Each item is decrypted with your current session key, then re-encrypted as a multi-recipient age stanza using your enrolled recipients."
            },
        )
        Spacer(modifier = Modifier.weight(1f))
        if (count == 0 && staleRageCount > 0) {
            RageButton(
                label = "Mark all rotated",
                onClick = onMarkRotated,
                icon = Icons.Outlined.Check,
                fullWidth = true,
            )
        } else {
            RageButton(
                label = "Begin",
                onClick = onBegin,
                icon = Icons.Outlined.TouchApp,
                fullWidth = true,
                enabled = count > 0,
            )
        }
    }
}

@Composable
private fun RunningStep(processed: Int, total: Int, currentName: String?) {
    val c = rageColors
    val progress = if (total == 0) 0f else processed.toFloat() / total.toFloat()
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(start = 18.dp, end = 18.dp, top = 6.dp, bottom = 18.dp),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .background(c.surfaceElevated, RoundedCornerShape(12.dp))
                .border(1.dp, c.border, RoundedCornerShape(12.dp))
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(110.dp),
                contentAlignment = Alignment.Center,
            ) {
                CircularProgressIndicator(
                    color = c.accent,
                    trackColor = c.surfaceSunken,
                    modifier = Modifier.size(56.dp),
                )
            }
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = "Re-encrypting...",
                style = RageType.h2.copy(fontSize = 18.sp),
                color = c.fgEmphasis,
                textAlign = TextAlign.Center,
            )
            Spacer(modifier = Modifier.height(6.dp))
            Text(
                text = "$processed of $total",
                style = RageType.caption.copy(fontSize = 12.5.sp),
                color = c.fgSecondary,
                textAlign = TextAlign.Center,
            )
            Spacer(modifier = Modifier.height(12.dp))
            LinearProgressIndicator(
                progress = { progress },
                color = c.accent,
                trackColor = c.surfaceSunken,
                modifier = Modifier.fillMaxWidth(),
            )
            if (currentName != null) {
                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = currentName,
                    style = RageType.rowTitle.copy(fontSize = 14.sp),
                    color = c.fgEmphasis,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
    }
}

@Composable
private fun DoneStep(
    processed: Int,
    failed: List<Pair<String, String>>,
    onClose: () -> Unit,
) {
    val c = rageColors
    val protectedCount = processed - failed.size
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(start = 18.dp, end = 18.dp, top = 6.dp, bottom = 18.dp),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f)
                .verticalScroll(rememberScrollState()),
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(c.surfaceElevated, RoundedCornerShape(12.dp))
                    .border(1.dp, c.border, RoundedCornerShape(12.dp))
                    .padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Box(
                    modifier = Modifier
                        .size(70.dp)
                        .background(
                            if (failed.isEmpty()) c.success else c.warning,
                            RoundedCornerShape(35.dp),
                        ),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        imageVector = if (failed.isEmpty()) Icons.Outlined.Check else Icons.Outlined.Lock,
                        contentDescription = null,
                        tint = c.background,
                        modifier = Modifier.size(32.dp),
                    )
                }
                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = "Done.",
                    style = RageType.h2.copy(fontSize = 20.sp),
                    color = c.fgEmphasis,
                    textAlign = TextAlign.Center,
                )
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = "$protectedCount item${if (protectedCount == 1) "" else "s"} now protected.",
                    style = RageType.body.copy(fontSize = 14.sp, lineHeight = 20.sp),
                    color = c.fgSecondary,
                    textAlign = TextAlign.Center,
                )
            }
            if (failed.isNotEmpty()) {
                Spacer(modifier = Modifier.height(14.dp))
                Text(
                    text = "Failed (${failed.size})",
                    style = RageType.rowTitle.copy(fontSize = 14.sp),
                    color = c.fgEmphasis,
                )
                Spacer(modifier = Modifier.height(8.dp))
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    failed.forEach { (id, err) ->
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(c.surfaceSunken, RoundedCornerShape(8.dp))
                                .border(1.dp, c.border, RoundedCornerShape(8.dp))
                                .padding(horizontal = 12.dp, vertical = 10.dp),
                        ) {
                            Mono(
                                text = id,
                                size = 11,
                                color = c.fgEmphasis,
                                modifier = Modifier.fillMaxWidth(),
                            )
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                text = err,
                                style = RageType.caption.copy(fontSize = 12.sp, lineHeight = 17.sp),
                                color = c.fgSecondary,
                            )
                        }
                    }
                }
            }
        }
        Spacer(modifier = Modifier.height(14.dp))
        RageButton(
            label = "Close",
            onClick = onClose,
            icon = Icons.Outlined.Check,
            fullWidth = true,
        )
    }
}

@Composable
private fun InfoCallout(text: String) {
    val c = rageColors
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(c.surfaceSunken, RoundedCornerShape(8.dp))
            .border(1.dp, c.border, RoundedCornerShape(8.dp)),
        verticalAlignment = Alignment.Top,
    ) {
        Box(
            modifier = Modifier
                .width(3.dp)
                .fillMaxHeight()
                .background(c.info),
        )
        Text(
            text = text,
            style = RageType.body.copy(fontSize = 13.sp, lineHeight = 19.sp, fontStyle = FontStyle.Italic),
            color = c.fgSecondary,
            modifier = Modifier.padding(start = 10.dp, top = 10.dp, end = 12.dp, bottom = 10.dp),
        )
    }
}
