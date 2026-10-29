package ragewarden.ragedroid.autofill

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.launch
import ragewarden.ragedroid.R
import ragewarden.ragedroid.data.VaultBridge
import ragewarden.ragedroid.di.appEntryPoint
import ragewarden.ragedroid.identities.CredentialManagerPrfTapper
import ragewarden.ragedroid.ui.components.ButtonVariant
import ragewarden.ragedroid.ui.components.RageButton
import ragewarden.ragedroid.ui.screens.LockScreen
import ragewarden.ragedroid.ui.secureWindow
import ragewarden.ragedroid.ui.theme.RageTheme
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors

/**
 * Saves a login another app submitted. Opened by the system from
 * [RagewardenAutofillService.onSaveRequest] with a [PendingSaves] token. A
 * locked vault is unlocked first; then the user confirms what will happen --
 * a new protected login, or a new password for the login already saved for
 * this site and username -- and only "Save" writes anything.
 */
class AutofillSaveActivity : FragmentActivity() {
    private var candidate: SaveCandidate? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        secureWindow()
        val taken = intent.getStringExtra(EXTRA_TOKEN)?.let { PendingSaves.take(it) }
        if (taken == null) {
            finish()
            return
        }
        candidate = taken
        val lockState = appEntryPoint().lockState()
        setContent {
            RageTheme {
                var locked by remember { mutableStateOf(lockState.isLocked) }
                if (locked) {
                    LockScreen(
                        onUnlock = {
                            lockState.unlock()
                            locked = false
                        },
                        onSignOut = { finish() },
                        repo = VaultBridge.repository() ?: appEntryPoint().bitwardenRepo(),
                    )
                } else {
                    val backend = remember { VaultBridge.ensureBackend(this) }
                    val plan = remember { AutofillSave.plan(taken, backend.snapshot()) }
                    var busy by remember { mutableStateOf(false) }
                    var error by remember { mutableStateOf<String?>(null) }
                    val scope = rememberCoroutineScope()
                    AutofillSaveSheet(
                        site = taken.label,
                        username = taken.username,
                        plan = plan,
                        busy = busy,
                        error = error,
                        onSave = {
                            busy = true
                            error = null
                            scope.launch {
                                runCatching { withPrfTapper { AutofillSave.run(plan, taken.password, backend) } }
                                    .onSuccess {
                                        Toast.makeText(this@AutofillSaveActivity, R.string.autofill_saved, Toast.LENGTH_SHORT).show()
                                        setResult(RESULT_OK)
                                        finish()
                                    }
                                    .onFailure { e ->
                                        busy = false
                                        error = e.message ?: getString(R.string.unknown_error)
                                    }
                            }
                        },
                        onDismiss = { finish() },
                    )
                }
            }
        }
    }

    /** A passkey or FIDO2 recipient needs a tap to wrap the new secret; this activity can ask for it while the save runs. */
    private suspend fun <T> withPrfTapper(block: suspend () -> T): T {
        val repo = VaultBridge.repository() ?: return block()
        val previous = repo.installedPrfTapper
        repo.installPrfTapper(CredentialManagerPrfTapper(this, appEntryPoint().recipientStore(), repo.accountId))
        return try {
            block()
        } finally {
            repo.installPrfTapper(previous)
        }
    }

    override fun onDestroy() {
        candidate?.password?.fill('\u0000')
        candidate = null
        super.onDestroy()
    }

    companion object {
        private const val EXTRA_TOKEN = "ragedroid.autofill.save.token"

        fun intent(context: Context, token: String): Intent =
            Intent(context, AutofillSaveActivity::class.java).putExtra(EXTRA_TOKEN, token)
    }
}

@Composable
internal fun AutofillSaveSheet(
    site: String,
    username: String,
    plan: SavePlan,
    busy: Boolean,
    error: String?,
    onSave: () -> Unit,
    onDismiss: () -> Unit,
) {
    val c = rageColors
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(c.background)
            .padding(horizontal = 22.dp, vertical = 28.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            text = when (plan) {
                is SavePlan.Create -> stringResource(R.string.autofill_save_title_new)
                is SavePlan.Update -> stringResource(R.string.autofill_save_title_update, plan.item.name)
                is SavePlan.Unchanged -> stringResource(R.string.autofill_save_title_unchanged, plan.item.name)
            },
            style = RageType.display.copy(fontSize = 22.sp, lineHeight = 28.sp),
            color = c.fgEmphasis,
        )
        Text(text = site, style = RageType.mono, color = c.fgSecondary)
        Text(
            text = username.ifEmpty { stringResource(R.string.autofill_save_no_username) },
            style = RageType.body,
            color = c.fgPrimary,
        )
        if (plan is SavePlan.Create) {
            Text(text = stringResource(R.string.autofill_save_protected), style = RageType.caption, color = c.fgSecondary)
        }
        error?.let { Text(text = it, style = RageType.caption, color = c.danger) }
        Spacer(modifier = Modifier.weight(1f))
        if (plan !is SavePlan.Unchanged) {
            RageButton(
                label = when {
                    busy -> stringResource(R.string.saving)
                    plan is SavePlan.Update -> stringResource(R.string.autofill_save_update)
                    else -> stringResource(R.string.autofill_save_save)
                },
                onClick = onSave,
                enabled = !busy,
                fullWidth = true,
                rejectObscured = true,
            )
        }
        RageButton(
            label = stringResource(if (plan is SavePlan.Unchanged) R.string.close else R.string.not_now),
            onClick = onDismiss,
            variant = ButtonVariant.Secondary,
            fullWidth = true,
        )
    }
}
