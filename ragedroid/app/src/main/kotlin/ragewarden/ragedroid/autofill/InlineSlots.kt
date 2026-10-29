package ragewarden.ragedroid.autofill

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.service.autofill.InlinePresentation
import android.view.inputmethod.InlineSuggestionsRequest
import android.widget.inline.InlinePresentationSpec
import androidx.autofill.inline.UiVersions
import androidx.autofill.inline.v1.InlineSuggestionUi
import ragewarden.ragedroid.MainActivity

/**
 * Keyboard-strip ("inline") suggestions, Android 11+. The keyboard sends one
 * presentation spec per slot it can show; a dataset past the last slot reuses
 * the last spec, and one past maxSuggestionCount gets no inline chip (it stays
 * in the dropdown).
 */
internal object InlineSlots {
    fun spec(request: InlineSuggestionsRequest?, index: Int): InlinePresentationSpec? {
        val specs = request?.inlinePresentationSpecs.orEmpty()
        if (specs.isEmpty() || index >= request!!.maxSuggestionCount) return null
        return specs[minOf(index, specs.lastIndex)]
    }

    fun presentation(context: Context, title: String, spec: InlinePresentationSpec): InlinePresentation? {
        if (!UiVersions.getVersions(spec.style).contains(UiVersions.INLINE_UI_VERSION_1)) return null
        val attribution = PendingIntent.getActivity(
            context,
            ATTRIBUTION_REQUEST_CODE,
            Intent(context, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val slice = InlineSuggestionUi.newContentBuilder(attribution)
            .setTitle(title)
            .setContentDescription(title)
            .build()
            .slice
        return InlinePresentation(slice, spec, false)
    }

    private const val ATTRIBUTION_REQUEST_CODE = 0x52574e
}
