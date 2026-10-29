package ragewarden.ragedroid.autofill

import ragewarden.ragedroid.ui.uiString
import android.app.PendingIntent
import android.app.assist.AssistStructure
import android.content.Context
import android.os.Build
import android.service.autofill.Dataset
import android.service.autofill.Field
import android.service.autofill.FillResponse
import android.service.autofill.InlinePresentation
import android.service.autofill.Presentations
import android.service.autofill.SaveInfo
import android.view.inputmethod.InlineSuggestionsRequest
import android.widget.inline.InlinePresentationSpec
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import ragewarden.ragedroid.R
import ragewarden.ragedroid.data.VaultBridge
import ragewarden.ragedroid.model.VaultItem

internal data class FillTarget(
    val webDomain: String?,
    val packageName: String?,
    val username: AutofillCandidate?,
    val password: AutofillCandidate?,
) {
    val ids: Array<AutofillId> get() = listOfNotNull(username?.autofillId, password?.autofillId).toTypedArray()
}

internal object AutofillDatasets {
    fun target(structure: AssistStructure): FillTarget? {
        val packageName = runCatching { structure.activityComponent?.packageName }.getOrNull()
        val walk = AssistStructureWalker.walk(structure, packageName)
        val username = walk.candidates.firstOrNull { it.role == FieldRole.Username }
        val password = walk.candidates.firstOrNull { it.role == FieldRole.Password }
        if (username == null && password == null) return null
        return FillTarget(walk.webDomain, walk.packageName, username, password)
    }

    fun matchingResponse(context: Context, target: FillTarget, inline: InlineSuggestionsRequest? = null): FillResponse? {
        val matches = HostMatcher.matchVaultItems(
            items = VaultBridge.ensureBackend(context).snapshot(),
            webDomain = target.webDomain,
            packageName = target.packageName,
        )
        if (matches.isEmpty()) {
            val save = saveInfo(target) ?: return null
            return FillResponse.Builder().setSaveInfo(save).build()
        }
        return response(context, matches, target, inline)
    }

    internal fun response(context: Context, matches: List<VaultItem>, target: FillTarget, inline: InlineSuggestionsRequest?): FillResponse {
        val builder = FillResponse.Builder()
        matches.forEachIndexed { i, item -> builder.addDataset(dataset(context, item, target, InlineSlots.spec(inline, i))) }
        saveInfo(target)?.let(builder::setSaveInfo)
        return builder.build()
    }

    /** Asks Android to offer a save when the form is submitted with a password; null without a password field. */
    internal fun saveInfo(target: FillTarget): SaveInfo? {
        val password = target.password?.autofillId ?: return null
        val builder = SaveInfo.Builder(SaveInfo.SAVE_DATA_TYPE_USERNAME or SaveInfo.SAVE_DATA_TYPE_PASSWORD, arrayOf(password))
        target.username?.autofillId?.let { builder.setOptionalIds(arrayOf(it)) }
        return builder.build()
    }

    fun lockedResponse(context: Context, target: FillTarget, inline: InlineSuggestionsRequest? = null): FillResponse {
        val pending = PendingIntent.getActivity(
            context,
            UNLOCK_REQUEST_CODE,
            AutofillUnlockActivity.intent(context),
            PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_MUTABLE,
        )
        val text = context.getString(R.string.autofill_unlock_to_fill)
        val label = chip(context, text)
        val inlinePresentation = InlineSlots.spec(inline, 0)?.let { InlineSlots.presentation(context, text, it) }
        val builder = FillResponse.Builder()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val presentations = Presentations.Builder().setMenuPresentation(label)
            inlinePresentation?.let(presentations::setInlinePresentation)
            builder.setAuthentication(target.ids, pending.intentSender, presentations.build())
        } else {
            @Suppress("DEPRECATION")
            builder.setAuthentication(target.ids, pending.intentSender, label, inlinePresentation)
        }
        saveInfo(target)?.let(builder::setSaveInfo)
        return builder.build()
    }

    private fun dataset(context: Context, item: VaultItem, target: FillTarget, inlineSpec: InlinePresentationSpec?): Dataset {
        val displayLabel = uiString(R.string.autofill_into_3, item.name, target.webDomain ?: target.packageName ?: uiString(R.string.this_app))
        val presentation = chip(context, displayLabel)
        val inlinePresentation = inlineSpec?.let { InlineSlots.presentation(context, item.name, it) }
        val placeholder = AutofillValue.forText("")
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val presentations = Presentations.Builder().setMenuPresentation(presentation)
            inlinePresentation?.let(presentations::setInlinePresentation)
            Dataset.Builder(presentations.build()).also { b ->
                target.ids.forEach { id -> b.setField(id, Field.Builder().setValue(placeholder).build()) }
            }
        } else {
            @Suppress("DEPRECATION")
            Dataset.Builder(presentation).also { b ->
                target.ids.forEach { id -> b.setValue(id, placeholder) }
                inlinePresentation?.let(b::setInlinePresentation)
            }
        }
        val authIntent = AutofillAuthActivity.intent(
            context = context,
            itemId = item.id,
            displayLabel = displayLabel,
            domain = target.webDomain ?: target.packageName ?: "",
            usernameId = target.username?.autofillId,
            passwordId = target.password?.autofillId,
        )
        val pending = PendingIntent.getActivity(
            context,
            item.id.hashCode() xor displayLabel.hashCode(),
            authIntent,
            PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_MUTABLE,
        )
        builder.setAuthentication(pending.intentSender)
        return builder.build()
    }

    fun chip(context: Context, label: String): RemoteViews =
        RemoteViews(context.packageName, R.layout.ragedroid_autofill_chip).apply {
            setTextViewText(R.id.ragedroid_autofill_label, label)
        }

    private const val UNLOCK_REQUEST_CODE = 0x52574c
}
