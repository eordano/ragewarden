package ragewarden.ragedroid.ime

import android.content.Context
import android.content.Intent
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import ragewarden.ragedroid.R
import ragewarden.ragedroid.data.LockState
import ragewarden.ragedroid.data.VaultBridge
import ragewarden.ragedroid.data.audit.AuditAction
import ragewarden.ragedroid.di.appEntryPoint
import ragewarden.ragedroid.identities.HardwareTapCoordinator
import ragewarden.ragedroid.ui.components.InlineTapReveal
import ragewarden.ragedroid.ui.components.TapAction
import ragewarden.ragedroid.ui.components.TapPresentation
import ragewarden.ragedroid.ui.secureWindow
import ragewarden.ragedroid.ui.theme.RageTheme
import ragewarden.ragedroid.ui.theme.rageColors
import ragewarden.ragedroid.ui.uiString

/**
 * The hardware tap for a protected item the keyboard was asked to type. An
 * `InputMethodService` cannot host BiometricPrompt, Credential Manager or NFC
 * reader mode, so the keyboard opens this sheet, which runs the same
 * [InlineTapReveal] ceremony as autofill and hands the plaintext back through
 * [ImeAuthChannel]. The keyboard types it only once the same field is focused
 * again and the vault is still unlocked.
 */
class ImeAuthActivity : FragmentActivity() {

    private val lockState: LockState by lazy { applicationContext.appEntryPoint().lockState() }
    private var nonce: String = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        secureWindow()

        nonce = intent.getStringExtra(EXTRA_NONCE).orEmpty()
        val itemId = intent.getStringExtra(EXTRA_ITEM_ID).orEmpty()
        val target = intent.getStringExtra(EXTRA_TARGET).orEmpty().ifBlank { "this field" }

        if (nonce.isBlank() || !ImeAuthChannel.isPending(nonce) || itemId.isBlank() || lockState.isLocked) {
            cancelAndFinish()
            return
        }
        val backend = VaultBridge.ensureBackend(this)
        val item = backend.get(itemId)
        if (item == null || !item.rage) {
            cancelAndFinish()
            return
        }

        val coordinator = HardwareTapCoordinator(
            activity = this,
            recipientStore = applicationContext.appEntryPoint().recipientStore(),
            accountId = VaultBridge.repository()?.accountId.orEmpty(),
        )
        val presentation = TapPresentation.from(coordinator.identitySet())

        setContent {
            RageTheme {
                val pinRequest by coordinator.pinRequest.collectAsState()
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .background(rageColors.background)
                        .padding(20.dp),
                ) {
                    InlineTapReveal(
                        itemName = item.name.ifBlank { itemId },
                        itemSite = item.site.ifBlank { null },
                        presentation = presentation,
                        initialAction = TapAction.Autofill,
                        pinRequest = pinRequest,
                        onAuthorize = {
                            val plaintext = coordinator.authorize(purpose = uiString(R.string.type_into, target)) { identities ->
                                backend.decrypt(itemId, identities, AuditAction.Autofill)
                            }
                            if (lockState.isLocked) {
                                plaintext.fill(0)
                                error(uiString(R.string.the_vault_locked_while_this_was))
                            }
                            if (!ImeAuthChannel.complete(nonce, plaintext)) {
                                plaintext.fill(0)
                                error(uiString(R.string.the_keyboard_stopped_waiting_for_this))
                            }
                            finish()
                        },
                        onCancel = { cancelAndFinish() },
                    )
                }
            }
        }
    }

    override fun onDestroy() {
        if (isFinishing) ImeAuthChannel.complete(nonce, null)
        super.onDestroy()
    }

    private fun cancelAndFinish() {
        ImeAuthChannel.complete(nonce, null)
        finish()
    }

    companion object {
        private const val EXTRA_NONCE = "ragedroid.ime.nonce"
        private const val EXTRA_ITEM_ID = "ragedroid.ime.item_id"
        private const val EXTRA_TARGET = "ragedroid.ime.target"

        fun intent(context: Context, nonce: String, itemId: String, target: String): Intent =
            Intent(context, ImeAuthActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                putExtra(EXTRA_NONCE, nonce)
                putExtra(EXTRA_ITEM_ID, itemId)
                putExtra(EXTRA_TARGET, target)
            }
    }
}
