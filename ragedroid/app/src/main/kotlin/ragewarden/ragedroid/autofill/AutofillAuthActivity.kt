@file:Suppress("DEPRECATION")

package ragewarden.ragedroid.autofill

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.Parcelable
import android.service.autofill.Dataset
import android.service.autofill.FillResponse
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import ragewarden.ragedroid.R
import ragewarden.ragedroid.data.LockState
import ragewarden.ragedroid.data.VaultBridge
import ragewarden.ragedroid.di.appEntryPoint
import ragewarden.ragedroid.identities.HardwareTapCoordinator
import ragewarden.ragedroid.ui.components.InlineTapReveal
import ragewarden.ragedroid.ui.components.TapAction
import ragewarden.ragedroid.ui.components.TapPresentation
import ragewarden.ragedroid.ui.secureWindow
import ragewarden.ragedroid.ui.theme.RageTheme
import ragewarden.ragedroid.ui.theme.rageColors

class AutofillAuthActivity : FragmentActivity() {

    private val lockState: LockState by lazy { applicationContext.appEntryPoint().lockState() }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // The tap IS the consent gesture, so an overlay that supplies the touch
        // is a full bypass of it. Reject any touch delivered while another
        // window is on top of ours.
        window.decorView.filterTouchesWhenObscured = true
        // This sheet names the item being unlocked and sits directly in front of
        // a plaintext delivery.
        secureWindow()

        val itemId = intent.getStringExtra(EXTRA_ITEM_ID).orEmpty()
        val displayLabel = intent.getStringExtra(EXTRA_DISPLAY_LABEL).orEmpty()
        val domain = intent.getStringExtra(EXTRA_DOMAIN).orEmpty()
        val usernameId: AutofillId? = parcelableExtraCompat(EXTRA_USERNAME_ID, AutofillId::class.java)
        val passwordId: AutofillId? = parcelableExtraCompat(EXTRA_PASSWORD_ID, AutofillId::class.java)

        if (itemId.isBlank()) {
            setResult(Activity.RESULT_CANCELED)
            finish()
            return
        }

        // A dataset's PendingIntent outlives the fill request that built it, so
        // this can be entered after the vault has locked. Refuse before the item
        // is even looked up -- the sheet names the item, which is vault content.
        if (lockState.isLocked) {
            setResult(Activity.RESULT_CANCELED)
            finish()
            return
        }

        val backend = VaultBridge.ensureBackend(this)
        val item = backend.get(itemId)
        if (item == null) {
            setResult(Activity.RESULT_CANCELED)
            finish()
            return
        }

        val recipientStore = applicationContext.appEntryPoint().recipientStore()
        val accountId = VaultBridge.repository()?.accountId.orEmpty()
        val coordinator = HardwareTapCoordinator(
            activity = this,
            recipientStore = recipientStore,
            accountId = accountId,
        )
        // §0a: the consent prompt names what is about to happen. It used to pass
        // `itemName = itemId` -- a raw UUID -- and `recipientLabel = "Software
        // identity"` regardless of what was enrolled.
        val presentation = if (item.rage) {
            TapPresentation.from(coordinator.identitySet())
        } else {
            TapPresentation.softwareOnly("this vault's server-side key (item not Ragewarden-protected)")
        }

        setContent {
            RageTheme {
                val c = rageColors
                var dismissed by remember { mutableStateOf(false) }
                val pinRequest by coordinator.pinRequest.collectAsState()
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .background(c.background)
                        .padding(20.dp),
                ) {
                    if (!dismissed) {
                        InlineTapReveal(
                            itemName = item.name.ifBlank { itemId },
                            itemSite = domain.ifBlank { item.site.ifBlank { null } },
                            presentation = presentation,
                            initialAction = TapAction.Autofill,
                            pinRequest = pinRequest,
                            onAuthorize = {
                                // Throws on any failure; InlineTapReveal renders it.
                                deliverAutofill(
                                    coordinator = coordinator,
                                    itemId = itemId,
                                    isRage = item.rage,
                                    username = item.username,
                                    usernameId = usernameId,
                                    passwordId = passwordId,
                                    displayLabel = displayLabel,
                                )
                                dismissed = true
                            },
                            onCancel = {
                                setResult(Activity.RESULT_CANCELED)
                                finish()
                            },
                        )
                    }
                }
            }
        }
    }

    /**
     * Performs the authorized use. Any failure propagates so the prompt can
     * explain it -- the previous version swallowed every decrypt error into
     * `RESULT_CANCELED` and finished the Activity, which the user saw as the
     * sheet blinking away with no reason given.
     */
    private suspend fun deliverAutofill(
        coordinator: HardwareTapCoordinator,
        itemId: String,
        isRage: Boolean,
        username: String,
        usernameId: AutofillId?,
        passwordId: AutofillId?,
        displayLabel: String,
    ) {
        val backend = VaultBridge.ensureBackend(this)
        val target = displayLabel.substringAfter("into ").ifBlank { "this app" }
        val plaintext: ByteArray = if (isRage) {
            coordinator.authorize(purpose = "Autofill into $target") { identities ->
                backend.decrypt(itemId, identities)
            }
        } else {
            backend.decrypt(itemId, emptyList())
        }
        // The tap ceremony and the decrypt both suspend, and the user can lock
        // the vault from the main app while this sheet is up. Re-check before
        // the plaintext is handed to the autofill framework. Thrown rather than
        // silently cancelled so `InlineTapReveal` explains why nothing was
        // filled; it is deliberately outside the try/finally below, whose
        // `finish()` would tear the sheet down before the message was readable.
        if (lockState.isLocked) {
            plaintext.fill(0)
            error("The vault locked while this was authorizing. Unlock Ragewarden and try again.")
        }
        try {
            val datasetBuilder = freshDatasetBuilder(displayLabel)
            usernameId?.let { id ->
                attachValue(datasetBuilder, id, AutofillValue.forText(username), displayLabel)
            }
            passwordId?.let { id ->
                attachValue(
                    datasetBuilder,
                    id,
                    AutofillValue.forText(String(plaintext, Charsets.UTF_8)),
                    displayLabel,
                )
            }
            val response = FillResponse.Builder().addDataset(datasetBuilder.build()).build()
            val resultIntent = Intent().apply {
                putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, response)
            }
            setResult(Activity.RESULT_OK, resultIntent)
        } finally {
            plaintext.fill(0)
            finish()
        }
    }

    private fun freshDatasetBuilder(label: String): Dataset.Builder {
        val rv = RemoteViews(packageName, R.layout.ragedroid_autofill_chip).apply {
            setTextViewText(R.id.ragedroid_autofill_label, label)
        }
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            Dataset.Builder()
        } else {
            @Suppress("DEPRECATION")
            Dataset.Builder(rv)
        }
    }

    private fun attachValue(
        builder: Dataset.Builder,
        id: AutofillId,
        value: AutofillValue,
        label: String,
    ) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val rv = RemoteViews(packageName, R.layout.ragedroid_autofill_chip).apply {
                setTextViewText(R.id.ragedroid_autofill_label, label)
            }
            builder.setValue(id, value, rv)
        } else {
            @Suppress("DEPRECATION")
            builder.setValue(id, value)
        }
    }

    @Suppress("UNCHECKED_CAST", "DEPRECATION")
    private fun <T : Parcelable> parcelableExtraCompat(name: String, klass: Class<T>): T? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableExtra(name, klass)
        } else {
            intent.getParcelableExtra(name) as? T
        }

    companion object {
        private const val EXTRA_ITEM_ID = "ragedroid.autofill.item_id"
        private const val EXTRA_DISPLAY_LABEL = "ragedroid.autofill.label"
        private const val EXTRA_DOMAIN = "ragedroid.autofill.domain"
        private const val EXTRA_USERNAME_ID = "ragedroid.autofill.username_id"
        private const val EXTRA_PASSWORD_ID = "ragedroid.autofill.password_id"

        fun intent(
            context: Context,
            itemId: String,
            displayLabel: String,
            domain: String,
            usernameId: AutofillId?,
            passwordId: AutofillId?,
        ): Intent = Intent(context, AutofillAuthActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            putExtra(EXTRA_ITEM_ID, itemId)
            putExtra(EXTRA_DISPLAY_LABEL, displayLabel)
            putExtra(EXTRA_DOMAIN, domain)
            putExtra(EXTRA_USERNAME_ID, usernameId)
            putExtra(EXTRA_PASSWORD_ID, passwordId)
        }
    }
}
