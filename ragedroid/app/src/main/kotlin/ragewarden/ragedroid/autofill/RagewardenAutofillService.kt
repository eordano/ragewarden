@file:Suppress("DEPRECATION")

package ragewarden.ragedroid.autofill

import android.app.PendingIntent
import android.os.Build
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.util.Log
import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveInfo
import android.service.autofill.SaveRequest
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import ragewarden.ragedroid.R
import ragewarden.ragedroid.data.LockState
import ragewarden.ragedroid.data.VaultBridge
import ragewarden.ragedroid.di.appEntryPoint
import ragewarden.ragedroid.model.VaultItem

class RagewardenAutofillService : AutofillService() {

    private val lockState: LockState by lazy { applicationContext.appEntryPoint().lockState() }

    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback,
    ) {
        val structure = request.fillContexts.lastOrNull()?.structure
        if (structure == null) {
            callback.onSuccess(null)
            return
        }
        val packageName = runCatching { structure.activityComponent?.packageName }.getOrNull()
        val walk = AssistStructureWalker.walk(structure, packageName)

        val username = walk.candidates.firstOrNull { it.role == FieldRole.Username }
        val password = walk.candidates.firstOrNull { it.role == FieldRole.Password }
        if (username == null && password == null) {
            callback.onSuccess(null)
            return
        }

        // Same class of defect as the IME: `VaultBridge`'s cache stays populated
        // while the vault is locked, so without this the picker enumerated the
        // matching item names into a third-party app's field and every dataset
        // led to a decrypt. Offer nothing at all instead -- the vault is not
        // participating in autofill while locked, and an `AutofillService` has
        // no way to host the unlock prompt.
        if (lockState.isLocked) {
            Log.i(TAG, "vault locked: offering no autofill datasets")
            callback.onSuccess(null)
            return
        }

        val backend = VaultBridge.ensureBackend(this)
        val matches = HostMatcher.matchVaultItems(
            items = backend.snapshot(),
            webDomain = walk.webDomain,
            packageName = walk.packageName,
        )

        if (matches.isEmpty()) {
            callback.onSuccess(null)
            return
        }

        val autofillIds = listOfNotNull(username?.autofillId, password?.autofillId).toTypedArray()
        val responseBuilder = FillResponse.Builder()

        matches.forEach { item ->
            responseBuilder.addDataset(buildColdDataset(item, walk.webDomain, walk.packageName, username, password))
        }

        if (autofillIds.isNotEmpty()) {
            responseBuilder.setSaveInfo(
                SaveInfo.Builder(
                    SaveInfo.SAVE_DATA_TYPE_USERNAME or SaveInfo.SAVE_DATA_TYPE_PASSWORD,
                    autofillIds,
                ).build(),
            )
        }

        callback.onSuccess(responseBuilder.build())
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        callback.onSuccess()
    }

    private fun buildColdDataset(
        item: VaultItem,
        webDomain: String?,
        packageName: String?,
        username: AutofillCandidate?,
        password: AutofillCandidate?,
    ): Dataset {
        val displayLabel = "Autofill ${item.name} into ${webDomain ?: packageName ?: "this app"}"
        val presentation = remoteViewLabel(displayLabel)

        val datasetBuilder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            Dataset.Builder()
        } else {
            @Suppress("DEPRECATION")
            Dataset.Builder(presentation)
        }

        val placeholder = AutofillValue.forText("")
        username?.let {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                datasetBuilder.setValue(it.autofillId, placeholder, presentation)
            } else {
                @Suppress("DEPRECATION")
                datasetBuilder.setValue(it.autofillId, placeholder)
            }
        }
        password?.let {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                datasetBuilder.setValue(it.autofillId, placeholder, presentation)
            } else {
                @Suppress("DEPRECATION")
                datasetBuilder.setValue(it.autofillId, placeholder)
            }
        }

        val authIntent = AutofillAuthActivity.intent(
            context = this,
            itemId = item.id,
            displayLabel = displayLabel,
            domain = webDomain ?: packageName ?: "",
            usernameId = username?.autofillId,
            passwordId = password?.autofillId,
        )
        val pending = PendingIntent.getActivity(
            this,
            (item.id.hashCode() xor displayLabel.hashCode()),
            authIntent,
            PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_MUTABLE,
        )
        datasetBuilder.setAuthentication(pending.intentSender)
        return datasetBuilder.build()
    }

    private fun remoteViewLabel(label: String): RemoteViews =
        RemoteViews(packageName, R.layout.ragedroid_autofill_chip).apply {
            setTextViewText(R.id.ragedroid_autofill_label, label)
        }

    private companion object {
        const val TAG = "RagewardenAutofill"
    }
}
