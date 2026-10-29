package ragewarden.ragedroid.autofill

import android.content.Context
import android.service.autofill.Dataset
import android.service.autofill.FillResponse
import android.util.Size
import android.view.View
import android.view.inputmethod.InlineSuggestionsRequest
import android.widget.inline.InlinePresentationSpec
import androidx.autofill.inline.UiVersions
import androidx.autofill.inline.v1.InlineSuggestionUi
import androidx.test.core.app.ApplicationProvider
import kotlinx.collections.immutable.persistentListOf
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import ragewarden.ragedroid.model.VaultItem

/**
 * Each matching item becomes a dataset that authenticates before filling, and,
 * when the keyboard asked for inline suggestions, carries a keyboard-strip chip
 * for as many items as the keyboard has slots.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [31, 33, 34])
class AutofillDatasetsTest {
    private val context: Context get() = ApplicationProvider.getApplicationContext()

    private fun target() = FillTarget(
        webDomain = "github.com",
        packageName = null,
        username = AutofillCandidate(View(context).autofillId, FieldRole.Username, 1),
        password = AutofillCandidate(View(context).autofillId, FieldRole.Password, 1),
    )

    private fun item(n: Int) = VaultItem(
        id = "id-$n", name = "GitHub $n", username = "me", site = "github.com", folder = "All",
        rage = true, recipients = persistentListOf(), password = "", lastUsed = "", history = 0,
    )

    private fun inlineRequest(max: Int): InlineSuggestionsRequest {
        val style = UiVersions.newStylesBuilder().addStyle(InlineSuggestionUi.newStyleBuilder().build()).build()
        val spec = InlinePresentationSpec.Builder(Size(100, 40), Size(600, 80)).setStyle(style).build()
        return InlineSuggestionsRequest.Builder(listOf(spec)).setMaxSuggestionCount(max).build()
    }

    @Suppress("UNCHECKED_CAST")
    private fun datasets(r: FillResponse): List<Dataset> = field(r, "mDatasets").let { v ->
        (v as? List<Dataset>) ?: (v?.javaClass?.getMethod("getList")?.invoke(v) as List<Dataset>)
    }

    private fun field(o: Any, name: String): Any? {
        var c: Class<*>? = o.javaClass
        while (c != null) {
            runCatching { return c.getDeclaredField(name).apply { isAccessible = true }.get(o) }
            c = c.superclass
        }
        error("${o.javaClass.name} has no field $name")
    }

    private fun inlineOf(d: Dataset): Any? = field(d, "mInlinePresentation")

    private fun authenticates(d: Dataset): Boolean = field(d, "mAuthentication") != null

    @Test
    fun without_an_inline_request_every_dataset_authenticates_and_has_no_inline_chip() {
        val ds = datasets(AutofillDatasets.response(context, listOf(item(1), item(2)), target(), null))
        assertEquals(2, ds.size)
        ds.forEach {
            assertEquals(true, authenticates(it))
            assertNull(inlineOf(it))
        }
    }

    @Test
    fun an_inline_request_gets_a_chip_per_slot_and_no_more() {
        val ds = datasets(AutofillDatasets.response(context, listOf(item(1), item(2), item(3)), target(), inlineRequest(max = 2)))
        assertEquals(3, ds.size)
        assertNotNull(inlineOf(ds[0]))
        assertNotNull(inlineOf(ds[1]))
        assertNull(inlineOf(ds[2]))
        ds.forEach { assertEquals(true, authenticates(it)) }
    }

    @Test
    fun the_locked_response_offers_an_inline_unlock_chip() {
        val r = AutofillDatasets.lockedResponse(context, target(), inlineRequest(max = 1))
        assertNotNull(field(r, "mAuthentication"))
        assertNotNull(field(r, "mInlinePresentation"))
    }
}
