package ragewarden.ragedroid.autofill

import android.app.PendingIntent
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest
import ragewarden.ragedroid.data.LockState
import ragewarden.ragedroid.di.appEntryPoint

class RagewardenAutofillService : AutofillService() {

    private val lockState: LockState by lazy { applicationContext.appEntryPoint().lockState() }

    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback,
    ) {
        val structure = request.fillContexts.lastOrNull()?.structure
        val target = structure?.let(AutofillDatasets::target)
        if (target == null) {
            callback.onSuccess(null)
            return
        }
        val inline = request.inlineSuggestionsRequest
        if (lockState.isLocked) {
            callback.onSuccess(AutofillDatasets.lockedResponse(this, target, inline))
            return
        }
        callback.onSuccess(AutofillDatasets.matchingResponse(this, target, inline))
    }

    /**
     * Hands the submitted login to [AutofillSaveActivity], which unlocks if
     * needed and asks before writing. The password stays in this process
     * ([PendingSaves]); the intent carries a token.
     */
    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        val structure = request.fillContexts.lastOrNull()?.structure
        val candidate = structure?.let { s -> AutofillSave.candidate(s, ::appLabel) }
        if (candidate == null) {
            callback.onSuccess()
            return
        }
        val token = PendingSaves.put(candidate)
        val pending = PendingIntent.getActivity(
            this,
            token.hashCode(),
            AutofillSaveActivity.intent(this, token),
            PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        callback.onSuccess(pending.intentSender)
    }

    private fun appLabel(packageName: String): String? = runCatching {
        packageManager.getApplicationLabel(packageManager.getApplicationInfo(packageName, 0)).toString()
    }.getOrNull()
}
