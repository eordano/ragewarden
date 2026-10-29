package ragewarden.ragedroid.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch
import ragewarden.ragedroid.R
import ragewarden.ragedroid.data.BitwardenVaultRepository
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors
import ragewarden.ragedroid.ui.uiString

/**
 * Master-password gate in front of a destructive action.
 *
 * [repository] is deliberately non-null and has no default: the only check that
 * means anything here is `verifyMasterPassword`, and when it was nullable the
 * null branch slept 150 ms and then called [onConfirm] regardless of what was
 * typed. Callers that forgot the argument -- RecipientDetailScreen's revoke, at
 * the time -- got a sheet that looked identical to the real one and accepted any
 * single character. If you have no repository you have no gate: do not render
 * this, drop the affordance instead.
 */
@Composable
fun MasterPasswordConfirm(
    open: Boolean,
    onClose: () -> Unit,
    onConfirm: () -> Unit,
    repository: BitwardenVaultRepository,
    title: String = uiString(R.string.confirm_with_master_password),
    body: String? = null,
    action: String = uiString(R.string.confirm),
    danger: Boolean = true,
) {
    val c = rageColors
    var pw by remember(open) { mutableStateOf("") }
    var err by remember(open) { mutableStateOf<String?>(null) }
    var working by remember(open) { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    LaunchedEffect(open) {
        if (open) {
            pw = ""
            err = null
            working = false
        }
    }

    val submit: () -> Unit = submit@{
        if (working) return@submit
        if (pw.isEmpty()) {
            err = uiString(R.string.enter_your_master_password)
            return@submit
        }
        working = true
        err = null
        scope.launch {
            val result = repository.verifyMasterPassword(pw)
            working = false
            result.fold(
                onSuccess = { ok ->
                    if (ok) {
                        onConfirm()
                        onClose()
                    } else {
                        err = uiString(R.string.wrong_master_password)
                    }
                },
                // Verification failing is not verification passing. Surface the
                // error and keep the sheet open rather than letting the action
                // through.
                onFailure = { e ->
                    err = e.message ?: uiString(R.string.could_not_verify_password)
                },
            )
        }
    }

    Sheet(open = open, onDismiss = onClose, title = title) {
        Column(modifier = Modifier.fillMaxWidth()) {
            if (body != null) {
                Text(
                    text = body,
                    style = RageType.body.copy(fontSize = 14.sp, lineHeight = 21.sp),
                    color = c.fgPrimary,
                    modifier = Modifier.padding(bottom = 14.dp),
                )
            }
            Field(label = stringResource(R.string.master_password)) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(c.surfaceSunken, RoundedCornerShape(8.dp))
                        .border(
                            1.dp,
                            if (err != null) c.danger else c.border,
                            RoundedCornerShape(8.dp),
                        )
                        .padding(horizontal = 12.dp, vertical = 10.dp),
                ) {
                    BasicTextField(
                        value = pw,
                        onValueChange = {
                            pw = it
                            err = null
                        },
                        singleLine = true,
                        textStyle = RageType.mono.copy(color = c.fgPrimary),
                        cursorBrush = SolidColor(c.accent),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                        visualTransformation = PasswordVisualTransformation(),
                        modifier = Modifier.fillMaxWidth(),
                        decorationBox = { inner ->
                            if (pw.isEmpty()) {
                                Text(
                                    text = "••••••••••••",
                                    style = RageType.mono.copy(color = c.fgSecondary),
                                )
                            }
                            inner()
                        },
                    )
                }
            }
            if (err != null) {
                Text(
                    text = err!!,
                    style = RageType.caption,
                    color = c.dangerStrong,
                    modifier = Modifier.padding(bottom = 14.dp),
                )
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                RageButton(
                    label = stringResource(R.string.cancel),
                    onClick = onClose,
                    variant = ButtonVariant.Secondary,
                )
                RageButton(
                    label = if (working) stringResource(R.string.working) else action,
                    onClick = submit,
                    variant = if (danger) ButtonVariant.Danger else ButtonVariant.Primary,
                    enabled = !working,
                    rejectObscured = true,
                    modifier = Modifier.weight(1f),
                    fullWidth = true,
                )
            }
        }
    }
}
